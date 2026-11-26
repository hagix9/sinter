---
title: dnf_repository
description: .repo ファイルの中の DNF リポジトリ 1 つについて、宣言したキーだけを管理する。パッケージの署名検査は弱めない。
---

:::caution[実機では未検証]
`dnf_repository` は、Sinter のスクリプト化された対象でだけテストしています。
この方法で編集したファイルを DNF がどう読むか、サポート対象の各ディストリビューションで
`/usr/bin/dnf` が何へのリンクかは、まだ実機で確かめていません。Sinter が確実に
読めないものは拒否し、推測しません。
:::

**目的:** DNF リポジトリを 1 つ宣言する。対象は `/etc/yum.repos.d/` にある `.repo`
ファイルの `[id]` セクションです。Sinter はそのセクションの、宣言したキーだけを管理し、
ファイルのそれ以外のセクション、キー、コメント、空行は 1 バイトも変えません。

## 書式

```yaml
- id: crb
  type: dnf_repository
  with:
    name: crb
    file: /etc/yum.repos.d/rocky.repo
    enabled: true
```

```toml
[[resources]]
id = "crb"
type = "dnf_repository"

[resources.with]
name = "crb"
file = "/etc/yum.repos.d/rocky.repo"
enabled = true
```

## パラメータ

| パラメータ | 必須 | 型 | デフォルト | 説明 |
|-----------|------|-----|-----------|------|
| `name` | はい | 静的な string | — | リポジトリ ID（セクション名）。`[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}`。`main` は拒否します（DNF 自身の設定セクションです）。 |
| `state` | いいえ | string | `present` | `present` か `absent`。 |
| `file` | いいえ | 静的な string | `/etc/yum.repos.d/<name>.repo` | セクションのあるファイル。`/etc/yum.repos.d/` の直下にあり、`.repo` で終わる単純なファイル名。 |
| `description` | いいえ | string | — | セクションの `name=` キー。1 行、1〜256 バイト。制御文字、Unicode の行区切り・段落区切り（U+0085、U+2028、U+2029）、双方向制御文字（U+202A〜U+202E、U+2066〜U+2069）は使えません。 |
| `baseurl` | いいえ | string またはリスト | — | `baseurl=`。 |
| `mirrorlist` | いいえ | string | — | `mirrorlist=`。 |
| `metalink` | いいえ | string | — | `metalink=`。 |
| `enabled` | いいえ | boolean | — | `enabled=1` か `enabled=0`。 |
| `gpgcheck` | いいえ | boolean | — | `true` だけを受け付けます（`gpgcheck=1`）。 |
| `repo_gpgcheck` | いいえ | boolean | — | `true` だけを受け付けます（`repo_gpgcheck=1`）。 |
| `gpgkey` | いいえ | string またはリスト | — | `gpgkey=`。 |

- `name` と `file` には変数を使えますが、fact と register は使えません。
- `state: present` では、`description` から `gpgkey` までのフィールドの少なくとも 1 つが必要です。`state: absent` では `name` と `file` だけを指定できます。
- 管理するのは宣言したキーだけです。宣言していないキーはそのまま残り、drift にもなりません。`baseurl`、`mirrorlist`、`metalink` は互いに代わりになるキーですが、1 つを宣言しても、ほかの 2 つをセクションから**削除しません**。
- ディストリビューションのファイルが定義するリポジトリ（たとえば `rocky.repo` の `crb`）を管理するには、`file` にそのファイルを指定します。セクションがファイルに無く、`baseurl`、`mirrorlist`、`metalink` のどれも宣言していない場合、リソースは失敗し、`file` を指定するよう伝えます。
- URL（`baseurl`、`mirrorlist`、`metalink`）: `https://`、`http://`、`file:///` のいずれか。空白を含まない印字可能な ASCII、2048 バイト以下、バックスラッシュなし。`$releasever`、`$basearch` などの `$var` は使えます。認証情報を含む URL（`user@host`、`user:password@host`）は拒否します。リポジトリ URL の中の認証情報には対応していません。
- `gpgkey`: `file:///` か `https://` だけです。`http://` の鍵 URL は拒否します。パッケージの検査に使う鍵を、認証されていない経路で受け取ってはならないためです。
- `baseurl` と `gpgkey` の要素にはカンマを含められません（DNF はリストの値をカンマで分割します）。リストは 32 個までです。
- sensitive な変数から作った値があると、リソースは sensitive になり、diff と audit の詳細は伏せられます。

## 署名検査を弱めない

- `gpgcheck: false` と `repo_gpgcheck: false` は検証のエラーです。Sinter は `gpgcheck=0` を書きません。署名検査をしないリポジトリは、内容を自分で書いた [`file`](/ja/reference/resources/file/) リソースのままにしてください。
- Sinter が新しく作るセクションには、`gpgcheck` を宣言していなくても必ず `gpgcheck=1` を書きます。`enabled` を宣言していなければ `enabled=1` を書きます。セクションを作るには `baseurl`、`mirrorlist`、`metalink` のいずれかが必要です。
- リポジトリを有効にする編集（セクションが `enabled=0`、`enabled` キーなし、または解釈できない値のときの `enabled: true`）と、`baseurl`、`mirrorlist`、`metalink` を書く編集は、編集後のセクションに明示的な `gpgcheck=1` が無ければ、plan の段階で拒否します。同じ変更で有効にするには `gpgcheck: true` を宣言してください。ファイルの中では `1`、`true`、`yes`（大文字小文字は問わない）を有効として扱います。
- すでに有効で `gpgcheck=0`（または `gpgcheck` キーなし）のリポジトリを、リソースが有効化も取得元の変更もしない場合、それは Sinter の決めることではありません。エラーにはせず、plan、apply、audit に「このリポジトリは署名検査が有効でない」という注記を付けます。
- Sinter が書くのは `gpgkey=` の設定だけです。鍵のダウンロード、取り込み（`rpm --import`）、信頼の設定はしません。鍵ファイルは `file` リソースで配置してください。設定した鍵は、そのリポジトリのパッケージを最初にインストールするときに DNF 自身が取り込みます。

## 期待される動作

- Sinter はリポジトリの**ファイル**を読みます。DNF には問い合わせません。そのため、次のものは観測しません: コマンドラインでの上書き（`--enablerepo`、`--disablerepo`、`--setopt`）、同じリポジトリ ID の別ファイルでの定義、DNF 5 の上書き用ディレクトリ。
- ファイルは、NUL バイトと CR 改行を含まない正しい UTF-8 で、256 KiB 以下の通常ファイルでなければなりません（シンボリックリンクは拒否し、たどりません）。名前は 1 つだけでなければなりません。ハードリンクが 2 つ以上あるファイルは、plan、apply、audit のどれでも拒否します。置き換えると、もう一方の名前に古い内容が残るためです。
- **他のファイルは見ません。** リポジトリを作るときも削除するときも、`/etc/yum.repos.d/` の別のファイルが同じ id を定義しているかどうかは確認しません。特に、`state: absent` で署名検査のある定義を削除した後は、別のファイルにある同じ id の定義（`gpgcheck=0` かもしれません）を DNF が使うようになります。id が複数の場所で定義されている可能性があるときは、`grep -l '^\[<id>\]' /etc/yum.repos.d/*.repo` で確認してください。
- 確実に読める必要があるのは、そのリポジトリのセクションだけです。次の場合は拒否します: その ID のセクションヘッダーがファイルに 2 つある。セクションの中に同じキーが 2 回ある。セクションの行が、空行、コメント（1 桁目が `#` か `;`）、`key=value`、キーの直後の字下げされた継続行のどれでもない。管理対象のキーと大文字小文字だけが違うキーがある。また、ファイルのどこであっても、`[` で始まるのに `[id]` の形でない行があれば拒否します。拒否の文には行番号だけを書き、ファイルの内容は書きません。
- すでにあるキーは、その場所のまま値を置き換えます。無いキーは、セクションの最後のキーの後に追加します。キーを書き換えるのは値が違うときだけです。真偽値は意味で、リストは要素の並びで比べるので、空白や改行の違いだけでは変更になりません。リストは 1 行に 1 要素で書きます。
- 新しいファイルの内容は、新しいセクションだけです（所有者 `root:root`、mode `0644`）。すでにあるファイルの所有者、グループ、mode は変えません。すでにあるファイルに新しいセクションを作るときは、末尾に追加します。
- `state: absent` はセクションを削除します。ヘッダーから最後のキーまでが対象です。ヘッダーの上のコメントと、最後のキーの後の空行・コメント行は残ります。セクションが 1 つも残らなくても、ファイル自体は削除しません。セクションやファイルが無ければ、何もしません。
- 変更は [`file`](/ja/reference/resources/file/) リソースと同じコードで行います（親パスの検査、ステージング、アトミックな置き換え、検証）。観測してから置き換えるまでの間にファイルが変わっていれば、上書きしません。ターゲットが報告するファイルの SHA-256 が、Sinter が読んだバイト列の SHA-256 と同じであることを確認し、rename の直前にファイルの同一性をもう一度確認します。その確認と rename の間のごく短い時間に入った書き込みは検出できません。
- **表示するのは宣言したキーだけです。** plan は、値が違う宣言済みのキーごとに、ファイルにある値と宣言した値を表示します（`enabled: 0` → `enabled: 1`）。セクションを作る・削除するときは `state` を表示し、新しいセクションでは宣言したキーも表示します。audit の詳細も宣言したキーだけです。このリソースが管理しない行（別のセクション、宣言していないキー、コメント）は表示しません。
- 宣言したキーがファイルで持っている値は**表示します**（たとえば `baseurl` を宣言していて値が違うときの、現在の `baseurl`）。その URL のパスやクエリ文字列にアクセストークンが含まれる場合は、リソースに `sensitive: true` を指定してください。
- ファイルのどこかのセクションに `password`、`username`、`proxy_password`、`proxy_username`、`sslclientkey` のキーや、認証情報を含む URL（`user@host`）があると、diff と audit の詳細を全体として伏せます。URL のパスやクエリ文字列の中のトークンは、認証情報としては認識しません。
- 変更の後、Sinter はリポジトリのメタデータを**更新しません**。そのリポジトリに依存する `package` リソースは、インストールのときに自分でメタデータを取得します。
- 同じ `name` の `dnf_repository` が 2 つある場合と、`dnf_repository` のファイルが `file`、`template`、`link`、`directory` リソースのパスでもある場合は、検証のエラーです。1 つのファイルに複数のリポジトリを宣言することはできます。
- [`file_merge`](/ja/reference/resources/file_merge/) では、リポジトリファイルやその他の DNF の設定（`/etc/yum.repos.d/`、`/etc/dnf/`、`/etc/yum/`、`/etc/yum.conf`）を編集できません。そのようなパスは、宣言の順序に関係なく検証のエラーです。部分編集を許すと、上の署名検査の規則を迂回できてしまうためです。
- リポジトリのファイルを変えるには root が必要です（root で接続するか `--sudo` を使う）。plan はそのことを伝えます。
- audit: セクションがあり、宣言したすべてのキーが宣言した値であれば（`state: absent` ではセクションが無ければ）適合です。drift では、違っているフィールドをそれぞれ示します（`enabled`、`gpgcheck`、`baseurl` など。セクションが無い・あってはならない場合は `state`。ファイルが無い場合も drift）。読めない、大きすぎる、シンボリックリンクである、あいまいなファイルや、拒否された親ディレクトリ、対応していないホストは、drift ではなくエラーです。
- MCP では使えません。

## 対応する環境

DNF 4 だけです: Rocky Linux、RHEL、AlmaLinux の 9 と 10。パッケージマネージャが DNF でない
ホスト（Ubuntu、Debian）と、DNF 5 のホスト（`/usr/bin/dnf` が `dnf5` へのリンク）では、
理由を示して拒否します。`/usr/bin/dnf` が DNF 4 のプログラムへのシンボリックリンクでない
ホストも拒否します。Sinter は推測しません。

## 例

ディストリビューションが定義するリポジトリを有効にする:

```yaml
version: 1
resources:
  - id: crb
    type: dnf_repository
    with:
      name: crb
      file: /etc/yum.repos.d/rocky.repo
      enabled: true
```

署名されたサードパーティのリポジトリを定義し、そこからインストールする。鍵ファイルは
`file` リソースです。配布する前に、鍵のフィンガープリントを確かめてください。

```yaml
version: 1
resources:
  - id: example-key
    type: file
    with:
      path: /etc/pki/rpm-gpg/RPM-GPG-KEY-example
      source: repo/RPM-GPG-KEY-example
      owner: root
      group: root
      mode: "0644"

  - id: example-repo
    type: dnf_repository
    depends_on: [example-key]
    with:
      name: example
      description: Example packages
      baseurl: https://repo.example.com/el$releasever/$basearch/
      gpgcheck: true
      gpgkey: file:///etc/pki/rpm-gpg/RPM-GPG-KEY-example

  - id: example-app
    type: package
    depends_on: [example-repo]
    with:
      name: example-app
      state: present
```

同じリポジトリを TOML で書く:

```toml
[[resources]]
id = "example-repo"
type = "dnf_repository"
depends_on = ["example-key"]

[resources.with]
name = "example"
description = "Example packages"
baseurl = "https://repo.example.com/el$releasever/$basearch/"
gpgcheck = true
gpgkey = "file:///etc/pki/rpm-gpg/RPM-GPG-KEY-example"
```

リポジトリを無効にする、別のリポジトリを削除する:

```yaml
version: 1
resources:
  - id: no-crb
    type: dnf_repository
    with:
      name: crb
      file: /etc/yum.repos.d/rocky.repo
      enabled: false

  - id: no-example
    type: dnf_repository
    with:
      name: example
      state: absent
```

```toml
[[resources]]
id = "no-crb"
type = "dnf_repository"

[resources.with]
name = "crb"
file = "/etc/yum.repos.d/rocky.repo"
enabled = false

[[resources]]
id = "no-example"
type = "dnf_repository"

[resources.with]
name = "example"
state = "absent"
```
