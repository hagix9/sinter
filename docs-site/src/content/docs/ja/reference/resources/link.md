---
title: link
description: シンボリックリンクを管理する。
---

**目的:** `path` のシンボリックリンクが `target` を指していること、
または存在しないことを保証する。

## 書式

```yaml
- id: vimrc
  type: link
  with:
    path: /etc/vim/vimrc.local
    target: /opt/myapp/vimrc.local
```

## パラメータ

| パラメータ | 必須 | 型 | デフォルト | 説明 |
|-----------|------|-----|-----------|------|
| `path` | はい | string（絶対パス） | — | シンボリックリンクのパス。 |
| `target` | `present` のとき | string | — | リンク先。`state` が `present` の場合に必須。 |
| `state` | いいえ | string | `present` | `present` または `absent`。 |

## 期待される動作

- `present`: 存在しなければシンボリックリンクを作成し、リンク先が
  異なる既存のシンボリックリンクは張り替えます。
- `absent`: シンボリックリンクを削除します。シンボリックリンク以外の
  オブジェクトをリンクとして削除することは拒否されます。

## 冪等性

完全に冪等です — すでに `target` を指しているシンボリックリンクは
そのままです。

## 失敗時の動作

- `path` が既存のシンボリックリンク以外（ファイル、ディレクトリ）→
  失敗。Sinter が暗黙に置き換えることはありません。
- *親*パス中の予期しないシンボリックリンクは変更前に拒否されます。

## プラットフォームに関する補足

すべての対応ターゲットに適用されます。

## 関連

[file](/sinter/ja/reference/resources/file/) ·
[directory](/sinter/ja/reference/resources/directory/)
