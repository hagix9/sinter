---
title: CLI リファレンス
description: sinter validate、plan、apply、audit、mcp — フラグと終了コード。
---

```text
sinter <COMMAND>

Commands:
  validate  Validate a recipe without connecting to a target
  plan      Preview changes against a target without mutating it
  apply     Apply a recipe to a target
  audit     Audit whether a target already satisfies a recipe. Read-only.
  mcp       Serve a read-only MCP (Model Context Protocol) endpoint on stdio
```

`mcp`サブコマンドと`--targets-file`については[Core MCP](/ja/reference/mcp/)を参照してください。

`sinter --version` はバージョンを表示します（例: `sinter 0.5.1`）。

## validate

```sh
sinter validate <RECIPE> [--format text|json]
```

どのターゲットにも接続せずにレシピの構造と意味をチェックします。
成功時は終了コード 0 です。

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

## ターゲットオプション（plan / apply / audit）

| フラグ | デフォルト | 説明 |
|--------|-----------|------|
| `--host <HOST>` | localhost | SSH ホスト。省略でローカル実行。 |
| `--port <PORT>` | `22` | SSH ポート。 |
| `--user <USER>` | `$USER` | SSH ユーザ。 |
| `--known-hosts <PATH>` | `~/.ssh/known_hosts` | ホスト鍵データベース（厳格）。 |
| `--identity <PATH>` | — | 秘密鍵ファイル。複数回指定可能。 |
| `--sudo` | off | ターゲット側操作を `sudo -n` 経由で実行。 |
| `--verbose` | off | 詳細な出力。 |
| `--format` | `text` | `text` または `json`。 |

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
- ハッシュ化された `known_hosts` エントリはサポートされません。
