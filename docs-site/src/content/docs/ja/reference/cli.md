---
title: CLI リファレンス
description: sinter validate、plan、apply、audit、mcp、secrets — フラグと終了コード。
---

```text
sinter <COMMAND>

Commands:
  validate  Validate a recipe or bundle without connecting to a target
  plan      Preview changes against a target without mutating it
  apply     Apply a recipe to a target
  audit     Audit whether a target already satisfies a recipe. Read-only.
  mcp       Serve a read-only MCP (Model Context Protocol) endpoint on stdio
  secrets   Encrypt, decrypt and list secret files (standard age format).
```

`mcp`サブコマンドと`--targets-file`については[Core MCP](/ja/reference/mcp/)を、
`secrets`サブコマンドについては[sinter secrets](/ja/reference/secrets/)を
参照してください。

`sinter --version` はバージョンを表示します（例: `sinter 1.2.0`）。

## validate

```sh
sinter validate <RECIPE|BUNDLE> [--format text|json] [ターゲットオプション]
```

どのターゲットにも接続せずにレシピの構造と意味をチェックします。
成功時は終了コード 0 です。結果はレシピだけで決まります。
[ターゲットオプション](#ターゲットオプション)はすべてのフェーズで同じ
コマンドラインを使えるように受け付けますが、無視されます（ホストへの接続、
インベントリ・鍵・`known_hosts` の読み込み、`ssh` の実行は一切
行いません）。未知のオプションや綴り間違いは従来どおりエラーです。

## plan

```sh
sinter plan <RECIPE> [target options]
```

観測のみ — 接続して状態を観測し、非公式なプレビューを表示します。
変更は一切行わず、特に `systemctl daemon-reload` を実行することもありません。
apply が行う reload は `manager reloads` に一覧されます。

## apply

```sh
sinter apply <RECIPE> [target options]
```

状態を再観測し、変更を適用し、結果を検証し、通知されたハンドラを
実行します。変更が systemd マネージャの入力（ユニットファイル、drop-in、
alias リンク、`system.conf`）に触れた場合、またはユニットが
`NeedDaemonReload=yes` を報告した場合、apply はそれを必要とするサービスまたは
ハンドラの前、および成功した apply の最後に、システムマネージャに対して
`systemctl daemon-reload` を実行します。詳細は
[service](/ja/reference/resources/service/#マネージャの自動同期)を参照して
ください。

## audit

```sh
sinter audit <RECIPE> [target options] [--format text|json]
```

ターゲットがすでにレシピを満たしているかを検証します。audit は
完全に読み取り専用です：`plan` と同じ観測経路を使い、変更は一切
行わず、`command` リソースを実行せず、ハンドラも実行せず、`daemon-reload` も
実行しません。既存の観測に加えて実行する読み取り専用の `systemctl show` は、
ちょうど次の 2 つの形だけです:
`--property=LoadState,ActiveState,UnitFileState,NeedDaemonReload -- <unit>` と
`--property=UnitPath`。

レシピが唯一の desired-state の権威です — audit はレシピが記述する
状態を検査し、別途のポリシーベースラインには依存しません。
`/etc/ssh/sshd_config` を管理するレシピは `file`/`template`
リソースを通じて監査され、sshd の稼働状態は `service` リソースで
監査されます。SSH 固有の監査ロジックはありません。

audit は systemd マネージャの同期状態も、独立したドリフト次元
`manager_reload` として報告します（[audit の出力を読む](#audit-の出力を読む)を
参照）。

## secrets

```sh
sinter secrets encrypt [--passphrase | -r, --recipient <RECIPIENT>...] [-o, --output <OUT>] [-f, --force] <FILE | ->
sinter secrets decrypt [-i, --identity <PATH>] <FILE>
sinter secrets list    [--format text|json] [--recipe <FILE>...] [<PATH>...]
```

これらのフラグがインターフェースのすべてで、ほかの別名はありません。`secrets` は
下の[ターゲットオプション](#ターゲットオプション)を受け付けず、その `--identity` は
**age** の identity です（`decrypt` のみ）。動作、identity の探索、`list` の出力契約、
終了コードは [sinter secrets](/ja/reference/secrets/) に記載しています。

上記のコマンドとの関係が 2 点あります。

- `plan`、`apply`、`audit` の `--identity` は **SSH** 秘密鍵であり、シークレットには
  使われません。シークレットは `SINTER_IDENTITY`、既定の identity ファイル、
  リポジトリの `identity.age` を使います。
- `password_hash` を持つ `user` リソースには `--sudo` が必要です（`/etc/shadow` は
  root だけが読めるため）。

## ターゲットオプション

`validate`、`plan`、`apply`、`audit` が受け付けます（`validate` は無視します）。

| フラグ | デフォルト | 説明 |
|--------|-----------|------|
| `--host <HOST>` | localhost | SSH ホスト、または `~/.ssh/config` の `Host` 別名。省略でローカル実行。 |
| `--inventory <PATH>`（別名 `--hosts`） | — | ホストとグループの定義。各レシピは自身の `targets` が選んだホストでだけ実行されます。[複数ホスト](#複数ホスト)参照。`--host` とは併用不可。 |
| `--port <PORT>` | インベントリ、ssh_config の `Port`、なければ `22` | SSH ポート。 |
| `--user <USER>` | インベントリ、ssh_config の `User`、なければ `$USER` | SSH ユーザ。 |
| `--known-hosts <PATH>` | インベントリ、ssh_config の `UserKnownHostsFile`、なければ `~/.ssh/known_hosts` | ホスト鍵データベース（厳格）。 |
| `--identity <PATH>` | インベントリ、ssh_config の `IdentityFile`、なければ `~/.ssh/id_ed25519`、`id_ecdsa`、`id_rsa` | SSH 秘密鍵ファイル。複数回指定可能。引き継いだ一覧を置き換えます。[シークレット](/ja/reference/secrets/)には使われません。 |
| `--no-ssh-config` | off | OpenSSH クライアント設定を参照しない。 |
| `--sudo` | off | ターゲット側操作を `sudo -n` 経由で実行。`password_hash` を持つ `user` リソースでは必須。 |
| `--verbose` | off | 詳細な出力。 |
| `--format` | `text` | `text` または `json`。 |

### OpenSSH の設定

*Sinter v1.1.0 以降で利用できます。*

`ssh <host>` で接続できる環境なら、`sinter plan recipe.yaml --host <host>`
も同じ接続情報を使います。Sinter はインストール済みの OpenSSH クライアントに
設定を評価させ（`ssh -G <host>`。接続はしません）、`HostName`、`User`、`Port`、
`IdentityFile`、`IdentitiesOnly`、`IdentityAgent`、`HostKeyAlias`、最初の
`UserKnownHostsFile` を引き継ぎます。SSH 接続そのものは従来どおり Sinter
内蔵のトランスポートで行います。

- 優先順位（項目ごと）: CLI の明示オプション > インベントリのホストの値 >
  OpenSSH の設定 > 組み込みのデフォルト。
- ホスト鍵ポリシーは引き継ぎません。`StrictHostKeyChecking` や
  `UpdateHostKeys` などで [SSH アイデンティティのルール](#ssh-アイデンティティのルール)
  を緩めることはできません。
- `ProxyJump` / `ProxyCommand` は未対応です。これらを使うホストは直接接続
  せず、終了コード 3 で失敗します。
- 鍵: Ed25519、ECDSA、RSA（OpenSSH 形式・PEM 形式）の鍵ファイルが使えます。
  パスフレーズ付きの鍵は `ssh-agent` 経由でのみ使えます（先に `ssh-add`
  してください）。Sinter はパスフレーズを尋ねません。agent の鍵が先に試され、
  設定された鍵ファイルに一致するものが優先されます。`IdentitiesOnly yes`
  ではそれらだけを使います。
- `--no-ssh-config` でこれらをすべて無効にできます。`ssh` クライアントが
  ない環境では組み込みのデフォルトを使います。

## 複数ホスト

*Sinter v1.1.0 以降で利用できます。*

3 つの要素をそれぞれ明示します。

1. **インベントリ**: どのホストが存在するか（とそのグループ）
2. 各**レシピ**の `targets`: そのうちどのホストで実行してよいか
3. コマンドライン: その両方を指定

インベントリに書かれているだけのホストが実行対象になることはありません。

```yaml
# hosts.yaml
hosts:
  web01:
    address: 10.0.0.11     # 省略時はホスト名（~/.ssh/config の別名でも可）
    user: ubuntu           # 省略可: port, user, known_hosts, identity_files
  web02:
    address: 10.0.0.12
  db01:
    address: 10.0.0.21
    user: rocky
groups:
  web:
    hosts: [web01, web02]
  db:
    hosts: [db01]
```

```yaml
# nginx.yaml
version: 1
targets:
  groups: [web]            # hosts: [db01] を併記すると和集合
resources:
  - id: nginx
    type: package
    with:
      name: nginx
      state: present
```

```sh
sinter plan  nginx.yaml --inventory hosts.yaml
sinter apply nginx.yaml --hosts hosts.yaml
```

plan（および apply/audit）は最初にターゲット解決の結果を表示します。

```text
== target resolution ==
recipe nginx (nginx.yaml)
  db01   SKIP   no matching target
  web01  MATCH  group:web
  web02  MATCH  group:web
  selected 2, excluded 1
executions: 2 (1 recipe(s), 3 host(s))
```

フェイルクローズの規則（いずれも接続前に終了コード 2）:

- `--inventory` 使用時に `targets` のないレシピ
- インベントリにないホスト名・グループ名を指す `targets`
- 1 台も選ばない `targets`
- 同じアドレスとポートに解決される 2 つの選択ホスト
- 不正なインベントリ（未知のフィールド、未定義ホストや重複を含むグループ、
  ホストが空、構文エラー）
- `--host` と `--inventory` の併用

どのレシピにも選ばれないホストは、解決も接続もされません。`targets` は
インベントリ使用時だけ意味を持ちます。`--host`（または指定なし＝localhost）
は従来どおりの単一ターゲット動作で、`targets` を無視します。

ネストしたグループ、ホスト変数・グループ変数、パターン、暗黙の "all"
グループ、動的インベントリ、並列実行はありません。

### バンドル

バンドルは複数のレシピを 1 回の実行にまとめます。

```yaml
# web-stack.yaml
version: 1
name: web-stack            # 省略時はファイル名
recipes:                   # このファイルからの相対パス
  - common.yaml
  - nginx.yaml
  - app.yaml
```

```sh
sinter validate web-stack.yaml
sinter apply web-stack.yaml --inventory hosts.yaml
```

各レシピは**それぞれ自身の** `targets` で解決されます。`common` が
`groups: [linux]`、`nginx` が `groups: [web]` なら対象ホストは別々で、
「全レシピを全ホストへ」にはなりません。`targets` のないレシピが 1 つでも
あると、何も実行せずにバンドル全体がエラーになります。列挙したレシピは
すべて存在し検証に通る必要があり、同じレシピは 1 度だけ、バンドルの
入れ子は不可です。インベントリなしでは、各レシピを順に 1 つの `--host`
（または localhost）で実行します。

### 実行と失敗

- 実行単位は（レシピ, ホスト）の組です。レシピはバンドル順、各レシピ内の
  ホストは名前順で、1 つずつ実行します。
- `plan` と `audit` は読み取り専用で、すべての実行を試みます。
- `apply` はフェイルファストです。理由を問わず（2 検証、3 接続、4 plan、
  5 バックアップまたは apply の失敗、6 不確定）終了コードが 0 でない実行が
  出た時点で止まります。その実行は自身の結果またはエラーを保持し、以降の
  実行（同じレシピの後続ホスト、後続レシピのすべて）は `not_run`（理由に
  失敗した実行名）となり、接続もバックアップもリソース実行も行いません。
  それまでに完了した実行の結果はそのまま残り、ロールバックはしません。
- 終了コードは実行された実行のうち最も重いもの（6、5、4、3、2、7、0 の順。
  `not_run` は含めない）。一部が失敗して終了コード 0 になることはありません。
  要約行は `exit 0`、`non-zero`、`not run` の件数を示します。
- テキスト出力では各実行の通常のレポートの前に
  `== <レシピ> @ <ホスト> (<user>@<address>:<port>) ==` を、最後に
  `== executions ==` の要約を出力します。

## apply 前のバックアップ

*Sinter v1.1.0 以降で利用できます。*

レシピで、`apply` が何かを変更する前にターゲット上でコピーしておくパスを
宣言できます。

```yaml
version: 1
backup:
  paths:
    - /etc/ssh/sshd_config
    - /etc/nginx
resources:
  - id: nginx
    type: package
    with:
      name: nginx
      state: present
```

- `validate` は宣言だけを検査します。`plan` はパスを一覧表示するだけで
  （`BACKUP  <path> [planned]`）何もコピーしません。`audit` はバックアップを
  扱いません。
- `apply` は最初のリソースを実行する前に全パスをコピーします。保存先は
  `--sudo` 時 `/var/lib/sinter/backups/<run-id>/<元のパス>`、それ以外は
  ターゲットユーザの `~/.sinter/backups/<run-id>/<元のパス>` です。
  `<run-id>`（`<UTC 時刻>-<乱数>`）は 1 回の実行の全ホストで共通で
  （バンドルではレシピごとに `-<NN>-<レシピ名>` が付きます）、各ホストの
  バックアップはそのホスト上に置かれます。選択されたホストだけが対象です。
- ファイル、ディレクトリ（再帰）、シンボリックリンク（リンクのまま）を、
  モード・ACL・所有者・タイムスタンプを保ってコピーします。その他の拡張属性と
  SELinux ラベルはベストエフォートです。存在しないパスは `absent` として
  記録します。
- バックアップが 1 つでも失敗すると、リソースを 1 つも実行せずに apply を
  中止します（終了コード 5）。エラーには途中まで書かれた実行ディレクトリが
  示され、そのまま残ります。
- バックアップの内容は出力に現れません。Sinter はバックアップを復元・
  ローテーション・削除しません。バックアップはロールバックではありません。

## ターミナルの色

*Sinter v1.1.0 以降で利用できます。*

テキスト出力の状態語（`ok`/`CHANGED`/`PASS`/`success` は緑、
`POSSIBLE`/`DRIFT`/`blocked` は黄、`FAILED`/`ERROR`/`INDET` とエラー
メッセージは赤）は、出力先がターミナルのときだけ色付けされます。パイプ、
リダイレクト、CI ログでは色なしです。`NO_COLOR`（空でない値）と
`TERM=dumb` で色を無効にできます。`--format json` の出力に色コードが
含まれることはありません。

## 進捗表示

*v1.2.0 より後のリリースで利用できます。*

`plan`、`apply`、`audit` の実行中、Sinter は現在どこまで進んでいるかを表示できます。
進捗は **stderr** にだけ書かれます。stdout、レポート、JSON ドキュメント、終了コードには
一切影響せず、ベストエフォートです（進捗を書き込めない場合は、進捗なしで実行が続きます）。
`validate`、`secrets`、`mcp` は進捗を表示しません。

| 状況 | 進捗 |
|------|------|
| テキスト出力、stderr がターミナル、`TERM` が `dumb` ではない | **一時行**（自動） |
| テキスト出力、stderr がターミナルではない（パイプ、リダイレクト、CI ログ） | なし |
| テキスト出力、`TERM=dumb` | なし |
| `SINTER_PROGRESS=plain`、テキスト出力 | どの stderr でも**プレーン行** |
| `--format json` | 常になし |
| レシピが暗号化シークレットを参照している | 常になし |

優先順位（強い順）:

1. `--format json` と、シークレットを参照するレシピでは、ほかの設定にかかわらず進捗は
   出ません。
2. `SINTER_PROGRESS=plain` は、ターミナル上でも、`TERM=dumb` でも、プレーン行を選びます。
   ターミナルでは一時行に追加されるのではなく、一時行の代わりになります。
3. それ以外は、ターミナルでは一時行、ほかの出力先では何も出ません。

`SINTER_PROGRESS` を設定しない実行は、進捗が存在する前と同じ出力になります。ただし
対話的なターミナルでは、コマンドの実行中に一時行が表示され、終了時に消えます。

### SINTER_PROGRESS

プレーン行を有効にする方法は `SINTER_PROGRESS=plain` だけです。コマンドラインフラグも
設定項目もありません。効果があるのは値が正確に `plain` のときだけです。それ以外の値
（`Plain`、`PLAIN`、`1`、`auto`、`off`、空文字列、末尾に空白のある `plain `）は、警告なしに
無視され、変数が未設定の場合と同じになります。進捗を無効にする値はありません。一時行を
隠すには、その実行だけ `TERM=dumb` を設定するか、stderr をリダイレクトしてください。

### 一時行（ターミナル）

stderr 上の 1 行で、その場で上書きされ、実行が終わると消えます。そのため、あとに残る出力
（stdout のレポート、`sinter:` のエラー行）は、進捗がない場合とまったく同じです。

```text
resolve 0/3
connect
backup 1/2
apply 17/42 package:nginx 8s
handlers 0/1 handler:reload-nginx
```

- 先頭の語はステージです。`resolve`（ホストの OpenSSH クライアント設定を Sinter が問い合わせて
  いる間。localhost と `--no-ssh-config` では表示されません）、`connect`、`backup`、
  リソースの処理ではコマンド名そのもの（`plan`、`apply`、`audit`）、そして `handlers` です。
- `17/42` は、存在する項目のうち完了した項目の数です。割合ではなく件数で、残り時間の見積もりも
  ありません。総数が分からないステージ（`connect`）には件数が出ません。
- `package:nginx` は、処理中の項目のリソースタイプとレシピの `id` です。
- 時間（`8s`、`2m05s`、`1h02m`）は、数秒間何も変化しなかったときだけ表示されます。これは
  Sinter が最後に新しい項目またはステージへ進んでからの経過時間です。実行の**合計時間では
  なく**、項目が変わるたびに 0 から数え直されます。
- 失敗で終わったステージはそう表示されます（`apply 5/5 failed`、`indeterminate`）。件数だけで
  成功とみなすことはありません。
- 行はターミナルの幅に収まるよう切り詰められ、まず項目が短くされます。幅が分からない場合は
  60 桁と仮定します。

この行が示すのは Sinter がどれだけ待っているかだけで、ターゲットが生きていると主張する
ことはありません。

### プレーン行（`SINTER_PROGRESS=plain`）

プレーン進捗はログ向けです。CI ジョブ、リダイレクトされた stderr、自動化、その他、進捗を
あとから確認できる形で残したい場所で使います。一時行と違い、プレーン行は消えずに残ります。
行を消す操作、カーソル制御、色は一切使わず、stdout ではなく stderr に ASCII だけで書かれます。
どの行も `progress: ` で始まります（エラーを示す `sinter:` では始まりません）。

```text
progress: run: apply started
progress: connect: start
progress: connect: done (1s)
progress: apply: start 0/42
progress: apply: 5/42 (7s)
progress: apply: 5/42 on package:nginx, 30s since last progress
progress: apply: 5/42 on package:nginx, 1m30s since last progress
progress: apply: 9/42 (1m52s)
progress: apply: done 42/42 (3m41s)
progress: run: apply completed (3m43s)
```

- `run:` 行は 1 つの実行の開始と終了を示します。インベントリやバンドルの実行では、実行ごとに
  1 組が出力されます（ターゲット解決に処理がある場合はそのための 1 組も）。順序は実行される
  順です。進捗行にはホスト名もアドレスも含まれません。ホストを特定できる従来の出力
  （たとえば `sinter: [web @ web02] ...`）は、その実行の進捗行のあとに出力されます。
- `start`、`done`、`failed`、`indeterminate` はステージの状態を示します。成功しなかった
  ステージは `failed` または `indeterminate` で終わり（例: `progress: apply: failed 6/42 (12s)`）、
  `run:` 行も同じことを示します（`run: apply failed`）。Sinter の通常のエラーメッセージと
  レポートは変わらず、理由が書かれるのはそこだけです。
- `5/42 (7s)` は件数のマイルストーンで、完了した項目の数と、ステージ開始からの時間です。
  最後の `run:` 行では、実行開始からの時間です。
- 行数は、ステージの構成と Sinter が待った時間で決まり、レシピのリソース数には依存しません。
  ステージごとに、開始行、終了行、そして最大 10 個の件数マイルストーン（項目のおよそ 10 分の 1
  ごとに 1 行）が出ます。
- 項目の id はレポートと同じ形で表示されますが、印字可能な ASCII 以外の文字は `?` になり、
  64 文字を超える id は切り詰められて `...` で終わります。

#### ハートビート行

ステージが静かなとき、Sinter はまだ待っていることをログに残すためにハートビート行を書きます。
どの行も書かれないまま 30 秒たつと、最初のハートビートが書かれます。ハートビートのたびに
待ち時間は倍になり（60 秒、120 秒、240 秒）、最大 300 秒で頭打ちになります。したがって
ステージが動作中であれば、ハートビートは少なくとも 5 分ごとに出ます。開始行、マイルストーン行、
終了行が書かれると待ち時間は 30 秒に戻ります。マイルストーンに達しない新しい項目では
戻りません。

`30s since last progress` は、ステージが最後に開始した、または新しい項目へ進んだときからの
時間です。最後の行からの時間でも、実行の合計時間でもないため、マイルストーンの間でステージが
進んでいる最中でも、ハートビートが短い時間（たとえば `5s`）を報告することがあります。一時行と
同様に、経過時間を述べるだけで、ターゲットが生きている、または止まっているとは主張しません。

非常に長い停滞が続くと、コマンドが終了するかタイムアウトするまで、5 分ごとに 1 行ずつ
ハートビート行が増えます。これは意図的な仕様です。ログが 5 分を超えて無音になることはなく、
その代わり出力は待ち時間に応じて増えます（リソース数には応じません）。これらの間隔が個々の
CI システムのアイドル出力制限にどれだけ適合するかは、確認されていません。

#### 中断またはクラッシュした実行

Sinter が中断された（Ctrl-C、`SIGTERM`）か、内部エラーで停止した場合、プレーン行はそこで
終わります。最後の `run: ... completed` や `run: ... failed` 行がないことがあります。Sinter は
知り得ない結果をでっち上げません。最後の行がないログは、実行が正常に終了しなかったことを
意味し、成功や失敗を意味するものではありません。権威があるのは、従来どおり終了ステータスです。
これらのコマンドに Sinter はシグナルハンドラを設定しません。ターミナルでは、中断された実行が
最後の一時行を画面に残すことがあります。

### JSON とシークレットでは進捗なし

- **`--format json`** は、`SINTER_PROGRESS` の値や stderr がターミナルかどうかにかかわらず、
  どのストリームにも進捗を出しません。stdout は JSON ドキュメントだけで、stderr にはこれまで
  と同じもの（`sinter:` のエラー行）だけが出ます。[JSON 出力の契約](#json-出力の契約)を
  参照してください。
- **暗号化シークレットを参照するレシピ**（`content: { secret: <path> }` または
  `password_hash: { secret: <path> }`）は、`SINTER_PROGRESS=plain` を指定しても進捗を
  出しません。そのような実行ではパスフレーズのプロンプトやシークレット関連のメッセージが
  現れることがあるため、それらと決して混ざらないよう進捗を止めています。バンドルでは、
  シークレットを参照するレシピの実行と、その呼び出しのターゲット解決が対象になります。

### 進捗に含まれるものと含まれないもの

進捗は、ステージ、件数、項目のリソースタイプとレシピの `id`、コマンド名、固定の結果語だけから
作られます。ホスト名、アドレス、ユーザー名、鍵のパス、コマンドラインとその出力、ファイルの
内容、diff、シークレットの参照、エラーメッセージは決して含まれません。進捗にホストやレシピの
ラベルを表示することは、現在の動作には含まれていません。

進捗テキストは、ほかの stderr テキストと同じく参考情報です。解析しないでください。文言や
出力される行の集合は、マイナーリリースで変わることがあります。自動化には `--format json` と
[終了コード](#終了コード)を使ってください。

### 制限

- 一時行では、直前の再描画からおよそ 0.1 秒以内に起きた失敗は、行が失敗語を表示する前に実行が
  終わることがあります。`sinter:` のエラー行、レポート、終了コードには影響しません。
- 実行の終了時にターミナルが約 0.5 秒を超えて出力を受け付けなくなった場合、Sinter はそれ以上
  待ちません。実行、その出力、終了コードが遅れることはありません。この稀なケースでは、すでに
  始まっていた進捗の書き込みがあとから現れ、その間に出力された文字列の途中に混ざることが
  あります。進捗の書き込みは、Sinter のほかの stderr 出力とは同期されていません。
- 経過時間は秒単位で、1 秒未満のステージは `0s` と表示されます。

## plan / apply の出力を読む

`plan` は `== Sinter PLAN ==` で、`apply` は `== Sinter APPLY ==` で始まり、
続いて `target facts:` 行（ターゲットで検出されたホスト名、OS、ファミリ、
バージョン、アーキテクチャ）が出力されます。各リソースは 1 行のステータスと、
該当する場合は diff と理由を出力します:

```text
CHANGED  motd [template] known/normal
    + managed by sinter
    - (previous content)
```

| ステータス | 意味 |
|-----------|------|
| `ok` | リソースはすでに目的の状態に一致 — 変更は行われませんでした。 |
| `CHANGED` | リソースが変更されました（`plan` では変更される予定）。 |
| `POSSIBLE` | 変更が発生した可能性があるが確認できませんでした。 |
| `FAILED` | リソースが失敗 — 残りのリソースは blocked になります（fail-fast）。 |
| `INDET` | 変更の結果が不明（ディスパッチ後のタイムアウトなど）。自動リトライはされません。 |
| `skip` | リソースの `when` 条件が false と評価されました。 |
| `guard` | `creates`/`removes` ガードがすでに満た済み — コマンドは実行されませんでした。 |
| `blocked` | 前のリソースの失敗/indeterminate や依存関係未解決のため、実行されませんでした。 |
| `?` | 結果が不明（`plan` での `command` リソースなど。plan はコマンドを実行しません）。 |

`known/` の接頭辞は、リソースの現在状態が完全に観測された（`known`）か、
部分的に不明（`unknown`）かを示します。ハンドラは実行された場合に限り
末尾の `handlers:` に列挙され、キューに入ったが実行されなかったハンドラは
`pending handlers` に表示されます。

`daemon-reload` が計画された、実行された、または実行されなかった場合、出力には
`manager reloads (systemd daemon-reload):` セクションも含まれます。reload ごとに
1 エントリで、トリガー（`pending_input`、`observed_stale`、`package_discovery`）、
原因となったリソース、その reload が先行する消費側（service リソースまたは
ハンドラ）、結果が示されます。reload はマネージャの操作であり、restart では
ありません。`plan` では、まだ適用されていない systemd 入力に依存する
サービス（または現在 `NeedDaemonReload=yes` を報告しているサービス）は `?` と
なり、reason は「deferred/unknown until manager synchronization at apply…」で
始まります。これは「変更なし」でも失敗でもありません。

短い答え:

- **何か変更されましたか？** `CHANGED` の行を探してください。収束した実行では
  `ok`（と `skip`/`guard`）だけが表示されます。
- **plan は観測だけですか？** `plan` は同じステータスを出力しますが、変更は
  行いません。未適用の変更は plan 出力では `CHANGED` として表示されますが、
  ターゲットには手が加えられません。
- **スキップやブロックはありましたか？** `skip` は自分の `when` によるもの、
  `blocked` は前の問題によって妨げられたものです。
- **結果は不明ですか？** `?`、`POSSIBLE`、`INDET` — 再適用の前にターゲットを
  調べてください。

`--format json` は同じ情報を構造化して出力します。`plan` では、通知された
ハンドラは常に pending として報告されます。plan がハンドラを実行することは
ありません。マネージャの reload はトップレベルの `manager_reloads` 配列に
出力されます。

## audit の出力を読む

`audit` は `== Sinter AUDIT ==` で始まります。各リソースは決定的な
依存関係／実行順（依存先のリソースが先に報告される）で 1 行の
ステータスを出力し、該当する場合は drift の詳細や理由を出力します:

```text
DRIFT  motd [file]
    content: observed=[redacted] desired=[redacted]
```

コンテンツ関連の drift 詳細は保守的に redacted されます：audit は
コンテンツが「異なる」ことだけを報告し、内容やハッシュは出力しません。

| ステータス | 意味 |
|-----------|------|
| `PASS` | 観測された状態が目的の状態を満たしています。 |
| `DRIFT` | 観測により、目的の状態を満たしていないことが確定しました。 |
| `NOT_AUDITABLE` | audit が決して行わない操作を伴わないと検証できないリソース — `command` リソースは常に `NOT_AUDITABLE` で、実行されません。 |
| `NOT_APPLICABLE` | リソースの `when` 条件が false と評価されました。 |
| `ERROR` | 必要な観測を完了できませんでした。drift としては報告されません。 |

実行の末尾には `summary:` 行（total、compliant、drifted、
not_auditable、not_applicable、errors）と `status:` 行
（`no_drift`、`drift`、`indeterminate`）が出力されます。

終了コード `0` は「drift も観測エラーも検出されなかった」ことを
意味します — すべてのリソースが検証されたことを意味するわけでは
**ありません**。`NOT_AUDITABLE` は出力と summary に表示され続けるため、
未検証のリソースが暗黙に PASS になることはありません。

`--format json` では、audit は `{"mode", "status", "summary",
"resources"}` を出力します。リソースごとの `status` は `compliant`、
`drift`、`not_auditable`、`not_applicable`、`error` のいずれかです。
安定した構造の全体は [JSON 出力の契約](#json-出力の契約) を参照してください。

マネージャの同期は、独立したドリフト次元 `manager_reload` です（観測値
"daemon-reload pending (NeedDaemonReload=yes)"、期待値 "manager
synchronized"）。active/enabled の状態が一致していても `service` リソースに
表示され、また単一のユニットを指す管理対象のユニットファイルや drop-in にも
表示されます。content/mode/owner や state/enabled のドリフトとは独立しており、
audit は reload を行わないため、保留中の reload が修復済みと扱われることは
ありません。`NeedDaemonReload=no` は限定的な観測です（systemd は内容の
ハッシュではなく mtime とパスを比較します）。読み込まれている定義がディスク上の
バイト列と等しいことの証明にはなりません。単一のユニットに対応付けられない
管理対象の入力（テンプレート、型全体またはプレフィックスの drop-in、
`system.conf`）には、「manager consistency not verified…」という注記が付きます。
`NeedDaemonReload` や `UnitPath` を観測できない場合、そのリソースは `ERROR`
（集約結果は `indeterminate`）となり、`no_drift` になることはありません。
`link` リソースには audit でマネージャの観点はありません。

sensitive リソースは生の値を一切出力しません：drift の詳細は
`redacted` と表示され、シークレットは text、JSON、reason、stderr の
いずれにも現れません。

## 終了コード

| コード | 意味 |
|--------|------|
| 0 | 実行が完了（plan の差分があっても 0 で終了。audit は drift もエラーもなし） |
| 2 | バリデーション/スキーマエラー |
| 3 | ターゲット接続/capability/セキュリティエラー |
| 4 | plan を安全に完了できなかった |
| 5 | apply が失敗 |
| 6 | indeterminate — apply が indeterminate、または audit で 1 件以上の `ERROR` が記録された（エラーは drift より優先） |
| 7 | audit が drift を検出（観測エラーなし） |

## JSON 出力の契約

`--format json` は `validate`、`plan`、`apply`、`audit` で使えます。
v1.0.0 以降、この節に記載した内容は 1.x 系全体を通じて安定したインターフェースです。
`sinter mcp` は対象外で、[Core MCP](/ja/reference/mcp/) リファレンスに従います。

### 出力形式とエラー

- 出力は stdout 上の 1 つの JSON オブジェクトと、それに続く改行です。JSON
  モードでは、stdout にそれ以外は書き込みません。
- ドキュメントは、コマンドがレポートを生成した場合にだけ出力します。
  - `validate`: 成功時（終了コード 0）
  - `plan` / `apply`: 実行が完了した場合（終了コード 0、4、5、6）
  - `audit`: audit が完了した場合（終了コード 0、6、7）
- レポートを生成する前に失敗した場合、stdout は空になり、stderr に
  `sinter: …` の 1 行を書き込みます。例は、スキーマエラー（終了コード 2）や、
  接続・capability・セキュリティのエラー（終了コード 3）です。機械可読な
  エラー分類は [終了コード](#終了コード) で、stderr の文言は契約に含みません。

### validate

| フィールド | 型 | 値 |
|------------|----|----|
| `command` | string | `"validate"` |
| `status` | string | `"ok"` |
| `resources` | integer | recipe 内のリソース数 |
| `handlers` | integer | handler 数 |
| `vars` | integer | var 数 |

### plan と apply

| フィールド | 型 | 値 |
|------------|----|----|
| `mode` | string | `"plan"` または `"apply"` |
| `status` | string | `success`（終了コード 0）、`plan_error`（4）、`apply_failed`（5）、`indeterminate`（6） |
| `facts` | object | `hostname`、`os_name`、`os_family`、`os_version`、`arch` — ターゲット上で検出した値（string） |
| `resources` | array | リソースごとに 1 つのリソースオブジェクト（実行順） |
| `handlers` | array | 実行された handler のオブジェクト（`plan` では常に空） |
| `handlers_pending` | array of strings | 通知されたが実行されなかった handler の ID。`plan` では通知されたすべての handler がここに入る |
| `manager_reloads` | array | マネージャ reload オブジェクト（下記）。常に存在し、空配列 `[]` の場合もある。追加的なフィールド |

リソースオブジェクト（`plan` と `apply`）:

| フィールド | 型 | 値 |
|------------|----|----|
| `id` | string | recipe 内のリソース ID |
| `type` | string | リソース種別（例: `file`、`package`） |
| `loop_index` | integer または null | ループ展開されたリソースの反復インデックス。それ以外は `null` |
| `origin` | string | リソースの宣言元。フィールドは安定だが、文字列の内容は参考情報 |
| `execution` | string | `not_run`、`succeeded`、`failed`、`indeterminate` |
| `change` | string | `none`、`changed`、`possible` |
| `verification` | string | `not_applicable`、`not_performed`、`verified`、`failed`、`unknown` |
| `disposition` | string | `normal`、`skipped_by_condition`、`guard_satisfied`、`blocked_by_dependency`、`blocked_by_fail_fast` |
| `unknown` | boolean | 現在の状態を完全には観測できなかった場合に `true`（text 出力の `?`） |
| `sensitive` | boolean | sensitive リソースなら `true` |
| `reason` | string または null | 人が読むための説明。sensitive リソースでは `"<redacted>"` |
| `diff` | object または null | `null`、または `type` が `"redacted"`、`"summary"`（`current`、`desired` を含む）、`"text"`（`removed`、`added` を含む）のオブジェクト |
| `notes` | array of strings | 人が読むための注記。sensitive リソースでは各要素が `"<redacted>"` |

リソースは `id` と `loop_index` の組で識別します。

handler オブジェクトのフィールド:
- `id`（string）
- `service`（string）
- `action`（string）
- `state`（string: `NotRun`、`Succeeded`、`Failed`、`Indeterminate`。大文字・小文字も表記どおり）
- `reason`（string または null）

マネージャ reload オブジェクト（`plan` と `apply`）:

| フィールド | 型 | 値 |
|------------|----|----|
| `phase` | string | `resource`、`handler`、`final`、`planned`（`plan` は `planned` を報告） |
| `trigger` | string | `pending_input`、`observed_stale`、`package_discovery` |
| `causes` | array of strings | reload が必要になった原因のリソース ID |
| `consumer` | string または null | その reload が先行する service リソースまたは handler の ID。最後の reload では `null` |
| `execution` | string | `not_run`、`succeeded`、`failed`、`indeterminate` |
| `change` | string | `none`、`changed`、`possible` |
| `verification` | string | `not_applicable`、`not_performed`、`verified`、`failed`、`unknown` |
| `unknown` | boolean | 結果が不明な場合に `true`（`plan` では常に `true`） |
| `sensitive` | boolean | 原因または消費側が sensitive なら `true` |
| `reason` | string または null | 人が読むための説明。sensitive の場合は `"<redacted>"`。sensitive リソースについては、ユニット名、パス、stderr は出力されない |

`plan` のエントリは `phase` が `planned`、`execution` が `not_run`、
`unknown` が `true` です。上記の既存の値の集合は拡張されません。
`daemon-reload` が失敗した場合、実行全体は `apply_failed`、タイムアウトまたは
応答喪失の場合は `indeterminate` となり、終了コードは既存のものと同じです。

### audit

| フィールド | 型 | 値 |
|------------|----|----|
| `mode` | string | `"audit"` |
| `status` | string | `no_drift`（終了コード 0）、`drift`（7）、`indeterminate`（6） |
| `summary` | object | 整数の `total`、`compliant`、`drifted`、`not_auditable`、`not_applicable`、`errors` |
| `resources` | array | リソースごとに 1 つのオブジェクト（依存関係/実行順） |

リソースオブジェクト（`audit`）のフィールド:
- `id`（string）
- `type`（string）
- `loop_index`（integer または null）
- `origin`（string。内容は参考情報）
- `status`（string: `compliant`、`drift`、`not_auditable`、`not_applicable`、`error`）
- `sensitive`（boolean）
- `reason`（string または null）
- `details`（オブジェクトの配列。各オブジェクトは string の `dimension`、`observed`、`desired` を持つ。`dimension` は `manager_reload` になることがある。`observed` と `desired` は人が読むための値で、sensitive リソースでは `"[redacted]"`）

### backup（plan と apply）

*Sinter v1.1.0 以降で利用できます。*

レシピが `backup` を宣言しているときだけ出力されます。

| フィールド | 型 | 値 |
|-----------|----|----|
| `backup.run_id` | 文字列または null | 実行 ID（`apply`）。`plan` では `null`。 |
| `backup.directory` | 文字列または null | ターゲット上の実行ディレクトリ（`apply`）。`plan` では `null`。 |
| `backup.entries` | 配列 | 宣言順に 1 パス 1 オブジェクト: `path`（文字列）、`status`（`planned`、`backed_up`、`absent`）、`kind`（`file`、`directory`、`symlink`、または null）、`destination`（文字列または null）。 |

### インベントリとバンドル

*Sinter v1.1.0 以降で利用できます。*

`--inventory` 使用時、またはバンドルでは、`plan`・`apply`・`audit` は
すべての実行を試みた後に実行全体で 1 つのドキュメントを出力します。

| フィールド | 型 | 値 |
|-----------|----|----|
| `mode` | 文字列 | `"plan"`、`"apply"`、`"audit"` |
| `exit_code` | 整数 | 実行全体の終了コード。 |
| `bundle` | オブジェクトまたは null | バンドルの `name`、`path`。 |
| `inventory` | 文字列または null | インベントリのパス。 |
| `resolution` | 配列または null | インベントリ使用時、レシピごとに `recipe`、`path`、`hosts`（インベントリの全ホスト: `name`、`selected`（真偽値）、`reasons`（例 `"group:web"`））。 |
| `executions` | 配列 | （レシピ, ホスト）ごとに 1 オブジェクト、実行順。 |

実行オブジェクト: `recipe`（文字列）、`target`（`name` と `host`、`port`、
`user`。localhost では null）、`exit_code`（整数。未実行なら null）、
`status`（ドキュメントの `status`、または `error`、`not_run`）、`backup`
（下記）、そして `result`（単一ターゲット時に出力されるドキュメント）、
`error`（`kind`: `schema`、`connect`、`plan`、`apply`、`indeterminate`、
`message`）、`reason`（未実行の理由）のいずれか。

実行の `backup`: レシピが backup を宣言していない場合と `audit` では `null`。
それ以外は `status` — `planned`（plan）、`completed`（apply で全パスを
コピー）、`failed`（バックアップ段階で失敗。リソースは未実行）、
`not_started`（バックアップ前に失敗。例: 接続）、`not_run`（実行されず）—
と、`run_id`、`directory`（文字列または null）、`entries`（`path`、
`status`: `planned`・`backed_up`・`absent`・`failed`・`not_run`、`kind`、
`destination`）を持つオブジェクトです。その実行だけから作られるため
レシピ・ホスト・バックアップが混ざることはなく、ファイル内容は含みません。
完了した実行では `result.backup` と同じ内容を繰り返します。実行前に見つかった問題（インベントリ、
targets、解決、重複ホスト）ではドキュメントを出力せず、
[出力形式とエラー](#出力形式とエラー)のとおり終了します。

バンドルに対する `validate` は、ドキュメントに `bundle`（文字列）と
`recipes`（レシピごとの `recipe`、`path`、`resources`、`handlers`、`vars`、
`targets`）を追加し、`resources`・`handlers`・`vars` は合計値になります。

### 互換性のルール

- **1.x で安定なもの:**
  - 上に記載したすべてのフィールドの名前・型・null 可否
  - 記載した値とその意味
  - status と終了コードの対応
  - 出力形式とエラーのルール
  - リソースの識別方法と並び順
- **追加的な変更**は 1.x のマイナーリリースで行うことがあります。
  - 任意のオブジェクトへの新しいフィールドの追加（例: `manager_reloads`）や、
    audit の `dimension` の新しい値（例: `manager_reload`）
  - 新しいコマンドの JSON 出力

  利用側は、知らないフィールドを無視してください。
- **破壊的変更**は、新しいメジャーバージョンでのみ行います。
  - 記載したフィールドの削除や名前変更
  - 記載したフィールドの型や null 可否の変更
  - 記載した値の削除や意味の変更
  - 記載した値の集合への値の追加（`status`、`execution`、`change`、
    `verification`、`disposition`、audit の `status`、handler の `state`、
    `diff.type` の各集合は閉じているため、利用側は網羅的に判定できます）
  - status に対応する終了コードの変更
- **保証しないもの:**
  - オブジェクトのキーの順序、空白、インデント
  - 記載していないフィールド
  - 人が読むためのテキストの文言（`reason`、`notes`、diff の本文、audit
    `details` の値、`origin`、`facts` の値の書式）
  - stderr のメッセージ、text 出力
- **マスキングは契約の一部です。** sensitive な値は JSON 出力に決して現れず、
  上記の目印に置き換えられます。

## SSH アイデンティティのルール

- 選択された `known_hosts` ファイルが権威です。未知または変更された
  ホスト鍵は失敗します。自動登録や安全でないフォールバックは
  ありません。
- ポート 22 はポートなしの `host` エントリを使います。それ以外の
  ポートには `[host]:port` が必要です。
- ハッシュ化された（`|1|…`）`known_hosts` エントリに対応し、同じ厳密な
  アイデンティティで照合します。
- `@revoked` 行に載っている鍵は拒否します。
- ホストについて known_hosts に記録済みの鍵種別のホスト鍵アルゴリズムを
  優先して交渉するため、Ed25519 鍵だけ（または RSA 鍵だけ）で登録された
  ホストも受け入れます。
- OpenSSH の `HostKeyAlias` がある場合は、ホスト名の代わりにその別名を
  アイデンティティに使います。
