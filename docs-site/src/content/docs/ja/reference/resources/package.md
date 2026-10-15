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

操作ごとに環境変数を明示できます。環境変数はこのパッケージ操作（権限
昇格した `apt` / `dnf` の実行を含む）にだけ渡され、ホスト全体の永続的な
設定にはなりません。

```yaml
- id: install-tools
  type: package
  with:
    name: curl
    state: present
    env:
      HTTP_PROXY: "http://proxy.example.com:3128"
      HTTPS_PROXY: "http://proxy.example.com:3128"
      NO_PROXY: "localhost,127.0.0.1,.example.internal"
```

## パラメータ

| パラメータ | 必須 | 型 | デフォルト | 説明 |
|-----------|------|-----|-----------|------|
| `name` | はい | string | — | パッケージ名（検証される）。 |
| `state` | はい | string | — | `present` または `absent`。必須。 |
| `env` | いいえ | string の map | 空 | このパッケージ操作に渡す環境変数。 |

## 期待される動作

- バックエンドはターゲットの `/etc/os-release` の識別情報から自動的に
  選択されます — レシピはプラットフォーム中立のままです。
- Ubuntu での `present` → `apt`。RHEL 系ターゲット（Rocky Linux、RHEL、
  AlmaLinux、Oracle Linux）→ `dnf`。
- v1.4.0 ではバージョン固定はありません。
- dnf ターゲットでは、インストールはプライベートキャッシュ
  スナップショット経由で行われます —
  [実行モデル](/ja/concepts/execution-model/)と
  [Rocky ガイド](/ja/guides/rocky-linux/)を参照してください。
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

## メタデータスナップショット（dnf）

RHEL 系ターゲットでは、インストールはターゲットの dnf メタデータのプライベートな
スナップショットに対して cache-only で実行されます。スナップショットは有効な
すべてのリポジトリのメタデータキャッシュが完全である必要があります。有効な
リポジトリのメタデータが未キャッシュの場合（新しいイメージや、直前に追加した
リポジトリなど）、Sinter は `dnf makecache` と同じくターゲット自身の dnf
メタデータキャッシュを一度だけ更新し、スナップショットを再作成して検証し直します。
手動での準備は不要です。取得するのは未キャッシュのメタデータだけ
（`metadata_expire=-1`）なので、キャッシュ済みのホストでは余分な通信は発生しません。
またこの手順で取得するのはリポジトリのメタデータのみで、パッケージのペイロードは
ダウンロードしません。メタデータを確立できない場合は、パッケージを変更する前に
fail-closed になります。スナップショットは live cache にダウンロード済みの
パッケージをトランザクションのペイロードと誤認しなくなり、live cache を削除・
コピーすることもありません。
パッケージ同一性の問い合わせ（`rpm -qp`）は信頼されていない署名の警告を無視します。
署名が信頼されるかどうかは引き続き dnf とペイロードのダイジェストで決まります。

## プラットフォームに関する補足

| プラットフォーム | バックエンド |
|------------------|--------------|
| Ubuntu 24.04 / 26.04 LTS | apt |
| Rocky Linux 9 / 10 | dnf |
| RHEL 9 / 10 | dnf |
| AlmaLinux 9 / 10 | dnf |
| Oracle Linux | dnf（互換性見込み — 受入検証は未実施） |

## 関連

[service](/ja/reference/resources/service/) ·
[実行モデル](/ja/concepts/execution-model/)
