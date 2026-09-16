---
title: directory
description: ディレクトリを目的のメタデータで存在させる。
---

**目的:** ディレクトリが目的の所有者・グループ・モードで存在する
（または存在しない）ことを保証する。

## 書式

```yaml
- id: appdir
  type: directory
  with:
    path: /opt/myapp
    mode: "0755"
    owner: root
    group: root
```

## パラメータ

| パラメータ | 必須 | 型 | デフォルト | 説明 |
|-----------|------|-----|-----------|------|
| `path` | はい | string（絶対パス） | — | 管理対象ディレクトリのパス。 |
| `state` | いいえ | string | `present` | `present` または `absent`。 |
| `owner` | いいえ | string | — | 所有者名。 |
| `group` | いいえ | string | — | グループ名。 |
| `mode` | いいえ | string | — | 引用符付きの 4 桁 8 進数。例: `"0755"`。 |

## 期待される動作

- `present`: そのディレクトリだけを作成します — 親はあらかじめ存在
  している必要があります（再帰的な作成はしません）。
- `absent`: ディレクトリを削除します。空でないディレクトリや
  ディレクトリ以外のオブジェクトは拒否されます。
- `owner`/`group`/`mode` が省略された場合、メタデータは保持されます。

## 冪等性

完全に冪等です。

## 失敗時の動作

- 親ディレクトリが存在しない → 失敗（暗黙の再帰なし）。
- パス中の予期しないシンボリックリンク → 変更前に拒否。

## プラットフォームに関する補足

すべての対応ターゲットに適用されます。

## 関連

[file](/sinter/ja/reference/resources/file/) ·
[link](/sinter/ja/reference/resources/link/)
