---
title: Ubuntu
description: Ubuntu 24.04 / 26.04 LTS amd64 管理対象ガイド — apt バックエンド。
---

Ubuntu 24.04 LTS amd64 は Sinter 最初のリファレンスターゲットであり、
Ubuntu 26.04 LTS amd64 も同じ `apt` バックエンドでサポートされます。
リポジトリでは両version lineを対象とします。26.04の新しい資格確認は
Unreleasedに属し、公開済みv0.2.1の対応範囲を変更しません。

## 統一 Linux x86_64 配布

今後のリリースでは、対応する Ubuntu 24.04 / 26.04、Rocky Linux 9 / 10
の x86_64 向けに `sinter-v<VERSION>-linux-x86_64.tar.gz` を1つ配布します。
実行ファイルは共通ですが、実行時の検出により Ubuntu は APT、Rocky は
DNF を使います。任意の Linux や他のアーキテクチャへの対応を意味しません。

凍結候補は Ubuntu 24.04.5 LTS、Ubuntu 26.04.1 LTS、Rocky Linux 9.8、
Rocky Linux 10.2（すべて x86_64）の4実ホストで受入検証済みです。
他の各point releaseや将来のリリースを個別に検証したという意味ではありません。
公開済み v0.2.1 は従来のディストリビューション別アセットのままです。
現在のダウンロードは[インストール](https://hagix9.github.io/sinter/ja/getting-started/installation/)
を参照してください。統一候補はまだ公開アセットではありません。


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
