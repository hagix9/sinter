---
title: file_merge
description: 既存のテキストファイルのうち、宣言した一部分だけを管理し、それ以外は 1 バイトも変えない。
---

**目的:** テキストファイルのうち、宣言した一部分（完全に一致する 1 行、マーカーで囲んだブロック、`key = value` の設定 1 つ）だけを管理し、ファイルのそれ以外の部分は 1 バイトも変えずに残す。

[`file`](/ja/reference/resources/file/) と [`template`](/ja/reference/resources/template/) はファイル**全体**を管理します。宣言した内容に無いものは消えます。`file_merge` は、Sinter だけのものではないファイルのためのリソースです。たとえば `~/.ssh/authorized_keys`（他の鍵は残す）、`/etc/hosts`（他の行は残す）、設定 1 つだけが重要な単純な設定ファイルです。

## 書式

```yaml
- id: deploy-key
  type: file_merge
  with:
    path: /home/deploy/.ssh/authorized_keys
    merge: line
    line: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIsyntheticSYNTHETICsyntheticSYNTHETICsynthetic00 synthetic@example.invalid"
    owner: deploy
    group: deploy
    mode: "0600"
```

## パラメータ

すべての `merge` に共通:

| パラメータ | 必須 | 型 | デフォルト | 説明 |
|-----------|------|-----|-----------|------|
| `path` | はい | string（絶対パス） | — | 対象のファイル。`file.path` と同じ規則。DNF の設定は拒否します（[拒否するパス](#拒否するパス) を参照）。 |
| `merge` | はい | string | — | `line`、`block`、`key_value` のいずれか。 |
| `state` | いいえ | string | `present` | `present` か `absent`。ファイルではなく、管理する部分の状態。 |
| `create` | いいえ | boolean | `false` | ファイルが無いときに作ってよいか（`state: present` のときだけ意味がある）。 |
| `owner` | いいえ | string | — | 所有者名。指定しなければ既存のファイルの所有者のまま。 |
| `group` | いいえ | string | — | グループ名。指定しなければ既存のファイルのグループのまま。 |
| `mode` | いいえ | string | — | 引用符で囲んだ 4 桁の 8 進数（例 `"0600"`）。指定しなければ既存のファイルの mode のまま。 |

`merge: line`:

| パラメータ | 必須 | 型 | デフォルト | 説明 |
|-----------|------|-----|-----------|------|
| `line` | はい | string | — | ちょうど 1 行。改行（LF）、CR、NUL を含まず、空でも空白だけでもないこと。マーカー行の語句（`BEGIN SINTER MANAGED BLOCK` / `END SINTER MANAGED BLOCK`）を含まないこと。 |

`merge: block`:

| パラメータ | 必須 | 型 | デフォルト | 説明 |
|-----------|------|-----|-----------|------|
| `marker` | はい | string | — | ブロックの名前。`[A-Za-z0-9_.-]` の 1〜64 文字。 |
| `content` | `present` のとき | string | — | 2 つのマーカー行の間に置く行。複数行でも空でもよい。CR と NUL は不可。マーカー行の語句を含む行も不可。 |
| `comment_prefix` | いいえ | string | `#` | マーカー行の先頭。`#`、`;`、`//`、`--` のいずれか。 |

`merge: key_value`:

| パラメータ | 必須 | 型 | デフォルト | 説明 |
|-----------|------|-----|-----------|------|
| `key` | はい | string | — | `[A-Za-z0-9_.-]` の 1〜128 文字。大文字と小文字を区別して比べる。 |
| `value` | `present` のとき | string | — | 1 行。空でもよい。前後に空白やタブを付けない。数値や真偽値は引用符で囲む（`"100"`、`"true"`）。 |
| `separator` | いいえ | string | `=` | Sinter が key と value の間に書く文字列。`=`、` = `、`:`、`: `、空白 1 つのいずれか。 |

- `path`、`merge`、`marker`、`comment_prefix`、`key`、`separator` は静的な値です。変数（ループの中では `item`）は使えますが、fact、register、sensitive な値は使えません。
- `line`、`content`、`value` にはどの式も使えます。値が決まった時点でもう一度検査します。
- 別の `merge` のフィールド（たとえば `merge: line` に `key`）は検証のエラーです。

## 3 つの merge

### `line`: 完全に一致する 1 行

行の同一性は**行全体のバイト列**です（既存の各行から行末の改行だけを除いて比べます）。正規表現、前方一致、あいまいな一致はありません。

- `present`: `line` と等しい行が無ければ、ファイルの末尾に追加します。すでに 1 行以上あれば何も変えません。重複する行は決して追加しません。
- `absent`: `line` と完全に等しい行をすべて削除します。それ以外は何もしません。
- `line` はファイルの**すべての**行を見ます。`merge: block` が管理するブロックの中の行も含みます。`absent` はブロックの中の等しい行も削除し、`present` はその行を「すでにある」と数えます。1 つのファイルで、同じ文字列を `line` と `block` の中身の両方で管理しないでください。
- `BEGIN SINTER MANAGED BLOCK` または `END SINTER MANAGED BLOCK` の語句を含む `line` は検証のエラーです。ブロックを壊すか、ブロックに見せかける行になるためです。ブロックには `merge: block` を使ってください。

### `block`: 2 つのマーカー行の間

Sinter はブロックを次の形で書きます。

```text
# BEGIN SINTER MANAGED BLOCK <marker>
<content の行>
# END SINTER MANAGED BLOCK <marker>
```

- `present`: この marker のブロックが無ければ、末尾に追加します。内容が違うブロックがあれば、2 つのマーカー行の間の行だけを置き換えます。内容が同じなら何も変えません。
- `absent`: 2 つのマーカー行を含めてブロックを削除します。
- **別の** marker 名のブロックは管理対象外の内容であり、そのまま残します。
- `content` の最後の改行 1 つは最後の行の終わりです。空行が 1 つ増えるわけではありません。`content: ""` は、マーカーの間に行の無いブロックです。

### `key_value`: 設定 1 つ

次の行が `key` の行です。**行の先頭（1 桁目）**から key があり、その後に空白・タブ（あってもよい）と `=` または `:` が続く行。区切りが空白のときは、key の後に空白・タブが 1 つ以上続く行（または key で終わる行）。key はそこで終わっていなければなりません。`port` は `port_max = 1` には一致しません。コメント行（空白以外の最初の文字が `#` か `;`）は決して一致しません。

次の 2 種類の行は、編集せずに**拒否**します（「安全側に倒して拒否する場合」を参照）。行頭に空白・タブがあって key を設定する行と、宣言した key と大文字・小文字だけが違う key の行です。

- `present` で一致する行が無い: `key<separator>value` を末尾に追加します。
- `present` で一致する行がちょうど 1 つ: **値が違うときだけ**、その行全体を `key<separator>value` に置き換えます。現在の値は、区切りの後ろの文字列から前後の空白・タブを除いたものです。したがって `max_connections   =100` の値はすでに `100` であり、書き換えません。
- `absent`: 一致する 1 行を削除します。一致する行が無ければ何も変えません。
- 値はそのまま書きます。Sinter は引用符を付けず、エスケープもしません。
- 置き換える行は、ちょうど `key<separator>value` に書き直します。Sinter はコメントや引用符の書式を知りません。元の行の行内コメントや引用符は値の一部です。たとえば `a = "1" # note` の値は `"1" # note` であり、`value: "2"` を宣言すると `a=2` になります。引用符やコメントが必要なら `value` に書いてください。

## 期待される動作

- **管理する部分の外は 1 バイトも変えません。** コメント、空行、行の順序、ファイル末尾に改行が無いことも含みます。末尾に改行の無いファイルに何かを追加するときだけ、先にその改行を足します。
- **変えるものが無いときは、ファイルを一切書きません**（置き換えなし、inode も同じ）。宣言した `owner`、`group`、`mode` は、内容を書き直さずに適用します。
- 変更は `file` リソースと同じ方法で書きます。ファイルの隣でステージし、rename で原子的に公開し、その後に検証します。ファイルは編集の前に読みます。その読み取りから公開までの間にファイルが変わっていたら、公開を拒否し、他の書き手の内容を残します。確認は 2 つあります。ターゲットが報告するファイルの SHA-256 が、Sinter が読んだバイト列の SHA-256 と同じであること（内容の比較なので、サイズと時刻が変わらない変更も検出します）。そして rename の直前に、ファイルの同一性（inode、サイズ、所有者、mode、時刻）をもう一度確認します。その確認と rename の間のごく短い時間に入った書き込みは検出できません。Sinter はファイルをロックしません。
- ファイルの**名前は 1 つだけ**でなければなりません。ハードリンクが 2 つ以上ある通常ファイルは、plan、apply、audit のどれでも拒否します。置き換えると、もう一方の名前に古い内容が残るためです。
- パスは通常ファイルでなければなりません。シンボリックリンクは拒否し、決してたどりません。ディレクトリなど他の種類も拒否します。
- plan は変更を通常のファイル diff として表示します。`merge: line` の `state: absent` が等しい行を複数削除するとき、diff には削除する行だけを表示し、その間にある管理対象外の行は表示しません。plan と audit は読むだけです。
- リソースの `sensitive: true`、または sensitive な変数から来た値があると、plan、apply、audit の diff とすべての値を伏せます。sensitive なリソースが新しく作るファイルは、`mode` の指定が無ければ `0600` です。
- sensitive でないリソースでは、plan と audit は `key_value` の設定の古い値と新しい値を表示します。どちらかが秘密でありうるときは `sensitive: true` を指定してください。
- 変更は、他のリソースと同じように handler に通知されます。
- MCP では使えません。

### 拒否するパス

`file_merge` は DNF の設定を編集しません。`path` が `/etc/yum.conf` であるか、`/etc/yum.repos.d/`、`/etc/dnf/`（たとえば `dnf.conf`、`modules.d/`、`vars/`）、`/etc/yum/` の中にあると、レシピの読み込み時に検証のエラーになります。そこに 1 行足すだけで、パッケージの署名検査を無効にできてしまうためです（`gpgcheck=0`）。リポジトリは [`dnf_repository`](/ja/reference/resources/dnf_repository/)、モジュールストリームは [`dnf_module`](/ja/reference/resources/dnf_module/) で管理してください。どちらもパッケージの署名検査を保ちます。または [`file`](/ja/reference/resources/file/) でファイル全体を書いてください。

### ファイルが無いとき

| `state` | `create` | 結果 |
|---------|----------|------|
| `present` | `false`（デフォルト） | plan のエラー。`create: true` を指定するか、先にファイルを作ってください。何も作りません。 |
| `present` | `true` | 管理する部分だけを持つファイルを作ります。`owner`/`group`/`mode` を適用します。指定が無ければ、実行ユーザー（他のアカウントのホームディレクトリの中ではそのアカウント）の所有で mode `0644` です。 |
| `absent` | どちらでも | 何もしません。準拠・変更なしです。ファイルは作りません。 |

親ディレクトリは、`file` と同じく、すでに存在していなければなりません。同じ実行の中で前のリソースがそのファイルを作る場合、plan は失敗させずに、このリソースを unknown（apply まで保留）として報告します。

### 安全側に倒して拒否する場合

次の場合はどれも、plan は失敗し（終了コード 4）、apply はファイルを変えずに失敗し、audit は**エラー**（drift ではありません）として報告します。Sinter は修復も推測もしません。

- ファイルが正しい UTF-8 でない、NUL バイトを含む、CR を含む（CRLF のファイルは変換せずに拒否します）。
- ファイル、または編集後の結果が 256 KiB を超える。
- `block`: 同じ marker の BEGIN 行が 2 つある。BEGIN に対応する END が無い。END が BEGIN の前にある、または BEGIN が無い。ブロックの中に別のブロックのマーカー行がある。この marker のマーカー行が、宣言とは別の `comment_prefix` で書かれている。`BEGIN SINTER MANAGED BLOCK` / `END SINTER MANAGED BLOCK` の語句を含むのに、正しい形のマーカー行ではない行がある（たとえば行末に空白がある）。
- `key_value`: key が 2 行以上にある（「どれが有効かを Sinter は推測しません」）。ファイルにセクション見出し（`[...]` だけの行）がある。宣言とは別の種類の区切りで key を設定する行がある（たとえば `=` と宣言したファイルの中の `key value`）。key を設定する行が字下げされている（字下げは多くの場合、Sinter が理解しない構造を意味します。入れ子の YAML マッピングや、`sshd_config` の `Match` ブロックなど）。宣言した key と大文字・小文字だけが違う key を設定する行がある（ファイルを読む側が同じ設定として扱うかどうかを、Sinter は推測しません）。
- ファイルにハードリンクが 2 つ以上ある。

### 1 つのファイルに複数のリソース

- 管理する部分が違えば、複数の `file_merge` が同じ `path` を管理できます（違う行、違う marker、違う key）。
- 同じ path で、同じ行、同じ marker、同じ key を持つ 2 つの `file_merge` は検証のエラーです（レシピの読み込み時に決まらない `line`、たとえば register から来る行は比べません）。
- 同じ path で、違う `owner`、`group`、`mode` を宣言する 2 つの `file_merge` は検証のエラーです。同じ値を書くか、どちらか一方だけに書いてください。
- 同じ path に `file`、`template`、`link`、`directory`、`systemd_timer` リソースがあると検証のエラーです。パス全体の管理と一部分の管理は両立しません。同じファイルに `dnf_repository` がある場合も、宣言の順序に関係なく検証のエラーです（そのパスは、そもそも `file_merge` では拒否されます）。

### audit

- 管理する部分が宣言どおりで、宣言したメタデータも一致すれば準拠です。**管理対象外の内容は決して drift になりません。**
- drift には次元の名前が付きます: `line`、`block`、`value`、`owner`、`group`、`mode`。ファイル自体が無いのに部分が present であるべきときは `state`（`absent -> present`。`create` の値に関係ありません）。
- 上の「安全側に倒して拒否する場合」、読めないファイル、シンボリックリンクはエラーです。

## `authorized_keys`

```yaml
version: 1
resources:
  - id: deploy-key
    type: file_merge
    with:
      path: /home/deploy/.ssh/authorized_keys
      merge: line
      line: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIsyntheticSYNTHETICsyntheticSYNTHETICsynthetic00 synthetic@example.invalid"
      create: true
      owner: deploy
      group: deploy
      mode: "0600"
  - id: old-key-removed
    type: file_merge
    with:
      path: /home/deploy/.ssh/authorized_keys
      merge: line
      line: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIsyntheticSYNTHETICsyntheticSYNTHETICsynthetic01 old@example.invalid"
      state: absent
```

```toml
version = 1

[[resources]]
id = "deploy-key"
type = "file_merge"

[resources.with]
path = "/home/deploy/.ssh/authorized_keys"
merge = "line"
line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIsyntheticSYNTHETICsyntheticSYNTHETICsynthetic00 synthetic@example.invalid"
create = true
owner = "deploy"
group = "deploy"
mode = "0600"

[[resources]]
id = "old-key-removed"
type = "file_merge"

[resources.with]
path = "/home/deploy/.ssh/authorized_keys"
merge = "line"
line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIsyntheticSYNTHETICsyntheticSYNTHETICsynthetic01 old@example.invalid"
state = "absent"
```

- ファイルの中の他の鍵は、オプションもコメントも含めて、そのまま残ります。
- 同一性は行全体です。同じ鍵でも、コメントが違う行や、先頭に `from="192.0.2.10",no-pty` のようなオプションが付いた行は**別の行**です。`present` は宣言した行をその隣に追加し、`absent` はその行を削除しません。Sinter は既存の行のオプションを編集も削除もしません。
- `sshd` がファイルを受け付けるように、`owner` と `mode: "0600"` を宣言してください。`.ssh` ディレクトリ自体は `file_merge` では作りません。[`directory`](/ja/reference/resources/directory/) リソース（mode `"0700"`）を使ってください。
- 自分の接続が使っている鍵を削除すると、ログインできなくなることがあります。Sinter はこれを検出しません。
- 上の鍵は合成したもので、実在の鍵ではありません。

## `/etc/hosts` のブロック

```yaml
version: 1
resources:
  - id: app-hosts
    type: file_merge
    with:
      path: /etc/hosts
      merge: block
      marker: app-hosts
      content: |
        192.0.2.10 app1.example.invalid
        192.0.2.11 app2.example.invalid
```

```toml
version = 1

[[resources]]
id = "app-hosts"
type = "file_merge"

[resources.with]
path = "/etc/hosts"
merge = "block"
marker = "app-hosts"
content = """
192.0.2.10 app1.example.invalid
192.0.2.11 app2.example.invalid
"""
```

結果（ブロックより上の行は元からあり、変わりません）:

```text
127.0.0.1 localhost
# BEGIN SINTER MANAGED BLOCK app-hosts
192.0.2.10 app1.example.invalid
192.0.2.11 app2.example.invalid
# END SINTER MANAGED BLOCK app-hosts
```

## 設定ファイルの設定 1 つ

```yaml
version: 1
resources:
  - id: max-connections
    type: file_merge
    notify: [restart-app]
    with:
      path: /etc/app/app.conf
      merge: key_value
      key: max_connections
      value: "100"
      separator: " = "
handlers:
  - id: restart-app
    service: app.service
    action: restart
```

```toml
version = 1

[[resources]]
id = "max-connections"
type = "file_merge"
notify = ["restart-app"]

[resources.with]
path = "/etc/app/app.conf"
merge = "key_value"
key = "max_connections"
value = "100"
separator = " = "

[[handlers]]
id = "restart-app"
service = "app.service"
action = "restart"
```

`key_value` は、key が 1 回だけ現れ、行の順序に意味の無い**平らな**ファイルのためのものです。次のファイルには**安全ではありません**。

- セクション（`[section]`）のあるファイル: 拒否します。INI を理解した編集には対応していません。
- 行の順序に意味のあるファイル（新しい設定を単に末尾へ置いてはいけないファイル）。
- 同じ key が正当に複数回現れる形式や、最初に一致したものが有効になる形式。たとえば `Match` ブロックのある `sshd_config`（字下げされた key の行は拒否しますが、字下げ無しで書かれた `Match` ブロックは認識できません）。
- key の大文字・小文字を区別しない形式。大文字・小文字だけが違う key の行は拒否します。同じ設定としては扱いません。
- 他のファイルを `Include` するファイル: Sinter が見るのはこの 1 ファイルだけなので、実際に有効な値は別の場所から来ているかもしれません。

そのようなファイルでは、代わりに drop-in ファイル全体を [`file`](/ja/reference/resources/file/) か [`template`](/ja/reference/resources/template/) で管理してください。

## 制限

- 正規表現、パターン一致、前方一致はありません。「〜のように見える行を置き換える」こともできません。
- セクションには対応しません。YAML、JSON、TOML の文書を構造として merge することもできません。
- 改行が LF の UTF-8 テキストだけ。最大 256 KiB。
- 位置を選んで挿入することはできません。新しい部分はファイルの末尾に置きます。
- コメントや、コメントアウトされた設定は、変更もコメント解除もしません。
- 公開前の `validate` コマンドはありません（`file` とは違います）。
- 管理する最後の部分を削除しても、ファイルは削除しません。空のファイルが残ります。
- Sinter のスクリプト化されたテスト用ターゲットで検証しています。実ホストでの動作（実際の `authorized_keys` のステージと置き換え、`setpriv` による所有アカウントとしての実行、実際の ACL と拡張属性の応答）は `file` と同じコードを使いますが、`file_merge` 自体としては実ホストで測定していません。

## 対応 OS

`file` と同じ対象です。`file_merge` は `file` リソースのコマンドだけを使い、パッケージやサービスのバックエンドを必要としません。
