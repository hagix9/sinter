---
title: CLI リファレンス
description: sinter validate、plan、apply、audit、mcp — フラグと終了コード。
---

```text
sinter <COMMAND>

Commands:
  validate  Validate a recipe or bundle without connecting to a target
  plan      Preview changes against a target without mutating it
  apply     Apply a recipe to a target
  audit     Audit whether a target already satisfies a recipe. Read-only.
  mcp       Serve a read-only MCP (Model Context Protocol) endpoint on stdio
```

`mcp`サブコマンドと`--targets-file`については[Core MCP](/ja/reference/mcp/)を参照してください。

`sinter --version` はバージョンを表示します（例: `sinter 1.1.1`）。

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
変更は一切行いません。

## apply

```sh
sinter apply <RECIPE> [target options]
```

状態を再観測し、変更を適用し、結果を検証し、通知されたハンドラを
実行します。

## audit

```sh
sinter audit <RECIPE> [target options] [--format text|json]
```

ターゲットがすでにレシピを満たしているかを検証します。audit は
完全に読み取り専用です：`plan` と同じ観測経路を使い、変更は一切
行わず、`command` リソースを実行せず、ハンドラも実行しません。

レシピが唯一の desired-state の権威です — audit はレシピが記述する
状態を検査し、別途のポリシーベースラインには依存しません。
`/etc/ssh/sshd_config` を管理するレシピは `file`/`template`
リソースを通じて監査され、sshd の稼働状態は `service` リソースで
監査されます。SSH 固有の監査ロジックはありません。

## ターゲットオプション

`validate`、`plan`、`apply`、`audit` が受け付けます（`validate` は無視します）。

| フラグ | デフォルト | 説明 |
|--------|-----------|------|
| `--host <HOST>` | localhost | SSH ホスト、または `~/.ssh/config` の `Host` 別名。省略でローカル実行。 |
| `--inventory <PATH>`（別名 `--hosts`） | — | ホストとグループの定義。各レシピは自身の `targets` が選んだホストでだけ実行されます。[複数ホスト](#複数ホスト)参照。`--host` とは併用不可。 |
| `--port <PORT>` | インベントリ、ssh_config の `Port`、なければ `22` | SSH ポート。 |
| `--user <USER>` | インベントリ、ssh_config の `User`、なければ `$USER` | SSH ユーザ。 |
| `--known-hosts <PATH>` | インベントリ、ssh_config の `UserKnownHostsFile`、なければ `~/.ssh/known_hosts` | ホスト鍵データベース（厳格）。 |
| `--identity <PATH>` | インベントリ、ssh_config の `IdentityFile`、なければ `~/.ssh/id_ed25519`、`id_ecdsa`、`id_rsa` | 秘密鍵ファイル。複数回指定可能。引き継いだ一覧を置き換えます。 |
| `--no-ssh-config` | off | OpenSSH クライアント設定を参照しない。 |
| `--sudo` | off | ターゲット側操作を `sudo -n` 経由で実行。 |
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
ありません。

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
- `details`（オブジェクトの配列。各オブジェクトは string の `dimension`、`observed`、`desired` を持つ。`observed` と `desired` は人が読むための値で、sensitive リソースでは `"[redacted]"`）

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
  - 任意のオブジェクトへの新しいフィールドの追加
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
