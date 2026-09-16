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

`sinter --version` はバージョンを表示します（例: `sinter 0.2.0`）。

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
