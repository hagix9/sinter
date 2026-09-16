---
title: command
description: 正確な argv と固定された環境でターゲット上のプログラムを実行する。
---

**目的:** ターゲット上でプログラムを実行する。本質的には冪等では
ないため、`creates`/`removes` ガードや `changed_when` で変更報告を
制御する。

## 書式

```yaml
- id: update_index
  type: command
  with:
    program: /usr/bin/touch
    args: ["/var/lib/myapp/indexed"]
    creates: /var/lib/myapp/indexed
```

## パラメータ

| パラメータ | 必須 | 型 | デフォルト | 説明 |
|-----------|------|-----|-----------|------|
| `program` | はい | string（絶対パス） | — | 実行ファイルのパス。 |
| `args` | いいえ | list of strings | `[]` | 正確な argv — シェル評価なし、NUL は拒否。 |
| `cwd` | いいえ | string（絶対パス） | — | 作業ディレクトリ。 |
| `env` | いいえ | map of strings | `{}` | 追加の環境変数。`PATH`、`LANG`、`LC_ALL`、`HOME` は予約済み。 |
| `timeout_seconds` | いいえ | integer 1..86400 | `300` | 実行タイムアウト。 |
| `success_codes` | いいえ | list of integers 0..255 | `[0]` | 成功とみなす終了コード。 |
| `creates` | いいえ | string（絶対パス） | — | ガード: このパスが存在する場合スキップ。`removes` とは排他。 |
| `removes` | いいえ | string（絶対パス） | — | ガード: このパスが存在**しない**場合スキップ。 |
| `changed_when` | いいえ | string（式） | — | 正常実行後に `result.<field>` から変更かどうかを決定する。 |
| `register` | いいえ | string（識別子） | — | 構造化された結果を `registers.<name>` に格納する。 |

## 期待される動作

- プログラムは与えられた argv で直接実行されます — シェルを介さない
  ため、クォートや展開の意外な挙動はありません。
- 環境: 固定のベースライン（`PATH`、`LANG`、`LC_ALL`、`HOME`）に
  `env` マップを加えたもの。コントローラ、SSH セッション、sudo、
  ログインシェルの環境変数は継承されません。
- `success_codes` に含まれる終了コード → 成功。それ以外 → 失敗。
  コマンドが開始しなかったと証明できない限り、変更は保守的に
  `possible` と分類されます。
- `register` は `result` のフィールド（`exit_code`、stdout/stderr
  など）を捕捉し、後続の `when`/`changed_when` 式で利用できます。

## ガード

- `creates`: パスが存在する場合コマンドは実行されません。結果は
  成功 / 変更なし / `guard_satisfied` で、`register` には未実行の
  結果が格納されます。
- `removes`: パスが存在しない場合、同じスキップ意味論が適用されます。
- これは依存先をブロックする `when: false` とは異なります。

## 失敗時の動作

- ディスパッチ後のタイムアウト、応答の喪失、シグナルの不確実性 →
  **indeterminate**。自動リトライはされません。
- 成功でない終了コード → リソース失敗。残りのリソースは blocked
  （fail-fast）。

## プラットフォームに関する補足

すべての対応ターゲットに適用されます。`program` はターゲット上の
絶対パスである必要があります。

## 関連

[冪等性](/sinter/ja/concepts/idempotency/) ·
[レシピ — 式](/sinter/ja/concepts/recipes/)
