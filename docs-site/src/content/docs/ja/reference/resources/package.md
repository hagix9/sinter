---
title: package
description: ターゲットのパッケージバックエンドでパッケージをインストール・削除する。
---

**目的:** ターゲットのネイティブなパッケージバックエンド — Ubuntu
では `apt`、RHEL 系ターゲットでは `dnf` — を使って、パッケージが
インストール済み（`present`）または削除済み（`absent`）であることを
保証する。

## 書式

```yaml
- id: tree
  type: package
  with:
    name: tree
    state: present
```

## パラメータ

| パラメータ | 必須 | 型 | デフォルト | 説明 |
|-----------|------|-----|-----------|------|
| `name` | はい | string | — | パッケージ名（検証される）。 |
| `state` | はい | string | — | `present` または `absent`。必須。 |

## 期待される動作

- バックエンドはターゲットの `/etc/os-release` の識別情報から自動的に
  選択されます — レシピはプラットフォーム中立のままです。
- Ubuntu での `present` → `apt`。Rocky/RHEL ファミリ → `dnf`。
- v0.2.0 ではバージョン固定はありません。
- dnf ターゲットでは、インストールはプライベートキャッシュ
  スナップショット経由で行われます —
  [実行モデル](/sinter/ja/concepts/execution-model/)と
  [Rocky ガイド](/sinter/ja/guides/rocky-linux/)を参照してください。
- 壊れたパッケージ状態（設定途中など）は自動修復ではなく失敗と
  なります。

## 冪等性

完全に冪等です — すでにインストール済みの `present`、すでに削除済みの
`absent` は変更もパッケージトランザクションも発生させません。

## 失敗時の動作

- 非対応プラットフォーム / バックエンドの欠落 → capability エラー。
- 解決できないパッケージ、リポジトリエラー、曖昧な観測 → 失敗または
  indeterminate。偽の変更報告にはなりません。
- 変更前の観測失敗が変更として報告されることはありません。

## プラットフォームに関する補足

| プラットフォーム | バックエンド |
|------------------|--------------|
| Ubuntu 24.04 LTS amd64 | apt |
| Rocky Linux 9 x86_64 | dnf |

## 関連

[service](/sinter/ja/reference/resources/service/) ·
[実行モデル](/sinter/ja/concepts/execution-model/)
