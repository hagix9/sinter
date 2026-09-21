---
title: service
description: systemd サービスの起動状態と有効化を管理する。
---

**目的:** systemd ユニットが `running`/`stopped` および/または
`enabled`/`disabled` であることを保証する。

## 書式

```yaml
- id: sshd
  type: service
  with:
    name: sshd
    state: running
    enabled: true
```

## パラメータ

| パラメータ | 必須 | 型 | デフォルト | 説明 |
|-----------|------|-----|-----------|------|
| `name` | はい | string | — | systemd ユニット名。 |
| `state` | いいえ | string | — | `running` または `stopped`。 |
| `enabled` | いいえ | boolean | — | `true`/`false`。 |

`state` と `enabled` の少なくとも一方が必須です。

## 期待される動作

- `state: running` は必要に応じてユニットを起動します。`stopped` は
  停止します。
- `enabled: true`/`false` は起動時有効化を設定します。
- Ubuntu と RHEL 系を問わず、あらゆる systemd ターゲットで動作します。
- Sinter は暗黙の `daemon-reload` を実行しません。ユニットファイルの
  変更は別途扱う必要があります。

## 冪等性

完全に冪等です — すでに目的の状態にあるユニットは再起動も再有効化も
されません。

## 失敗時の動作

- ユニットが見つからない → 失敗（`plan` では、まだ適用されていない
  パッケージに依存するサービスが deferred/unknown を報告することが
  あります）。
- `masked` ユニットに `running` を要求 → 失敗。`static` ユニットに
  `enabled` → 失敗。
- 観測の失敗は失敗/indeterminate として報告され、変更として報告
  されることはありません。

## プラットフォームに関する補足

ターゲットに systemd が必要です（すべての対応プラットフォーム）。

## 関連

[package](/sinter/ja/reference/resources/package/) ·
[handlers](/sinter/ja/concepts/recipes/)
