---
title: CLI リファレンス
description: sinter validate、plan、apply — フラグと終了コード。
---

```text
sinter <COMMAND>

Commands:
  validate  Validate a recipe without connecting to a target
  plan      Preview changes against a target without mutating it
  apply     Apply a recipe to a target
```

`sinter --version` はバージョンを表示します（例: `sinter 0.2.1`）。

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

## ターゲットオプション（plan / apply）

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

## 終了コード

| コード | 意味 |
|--------|------|
| 0 | 実行が完了（plan の差分があっても 0 で終了） |
| 2 | バリデーション/スキーマエラー |
| 3 | ターゲット接続/capability/セキュリティエラー |
| 4 | plan を安全に完了できなかった |
| 5 | apply が失敗 |
| 6 | apply が indeterminate になった |

## SSH アイデンティティのルール

- 選択された `known_hosts` ファイルが権威です。未知または変更された
  ホスト鍵は失敗します。自動登録や安全でないフォールバックは
  ありません。
- ポート 22 はポートなしの `host` エントリを使います。それ以外の
  ポートには `[host]:port` が必要です。
- ハッシュ化された `known_hosts` エントリはサポートされません。
