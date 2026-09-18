---
title: Ubuntu
description: Ubuntu 24.04 / 26.04 LTS amd64 管理対象ガイド — apt バックエンド。
---

Ubuntu 24.04 LTS amd64 は Sinter 最初のリファレンスターゲットであり、
Ubuntu 26.04 LTS amd64 も同じ `apt` バックエンドでサポートされます。
両方とも v0.2.1 で完全にサポートされています。

## 要件

| 要件 | 補足 |
|------|------|
| Ubuntu 24.04 または 26.04 LTS | amd64 |
| OpenSSH サーバ | 厳格な `known_hosts` 検証。自動登録なし |
| systemd | `service` リソースとハンドラに必要 |
| `/bin/sh` | ターゲット側シェル |
| `attr` パッケージ | `/usr/bin/getfattr`。ターゲットで確認し、不在なら `sudo apt install attr` を実行 |
| `sudo -n` | `--sudo` 使用時はパスワードなし sudo |

## パッケージ管理

Ubuntu では `type: package` は **apt** を使います。パッケージ名は有効な
Debian パッケージ名である必要があります。`state` は `present` または
`absent` です。

```yaml
resources:
  - id: nginx
    type: package
    with:
      name: nginx
      state: present
```

## プラットフォーム検出

Sinter はターゲットの `/etc/os-release` を読み、`ID=ubuntu` など
Debian 系システムに対して `apt` バックエンドを選択します。レシピ側で
バックエンドを切り替える仕組みはありません。レシピはプラットフォーム
中立のままです。

## 実行例

```sh
sinter plan --host web01 --sudo recipe.yaml
sinter apply --host web01 --sudo recipe.yaml
```

`known_hosts` にホスト鍵がない場合（またはデフォルト以外のポートで
`[host]:port` エントリがない場合）、接続はフェイルクローズします。

## テストに関する補足

リポジトリの SSH 統合テストスイートは、`SINTER_TEST_SSH_*` 環境変数を
使って使い捨ての Ubuntu ホストを対象にします。
[コントリビューション](/sinter/ja/contributing/)を参照してください。
