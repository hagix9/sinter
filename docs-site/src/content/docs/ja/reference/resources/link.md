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
- シンボリックリンクが systemd マネージャの入力（ユニットファイル、drop-in、
  alias/mask/`.wants`/`.requires` リンク、`system.conf`）を実際に変更すると、
  それを必要とする次のサービスまたはハンドラの前、および成功した apply の
  最後に、Sinter が `systemctl daemon-reload` を自動的に実行します。
  [service](/ja/reference/resources/service/#マネージャの自動同期)を参照して
  ください。

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

[file](/ja/reference/resources/file/) ·
[directory](/ja/reference/resources/directory/)
