---
title: インストール
description: リリース tarball から Sinter をインストールするか、ソースからビルドする。
---

Sinter は**コントローラ**（`sinter` を実行するマシン）上で動作します。
管理対象ホストに必要なのは SSH アクセスだけです。コントローラは macOS、
Ubuntu 24.04 LTS、またはバイナリがビルドできる任意の環境で構いません。

## リリース tarball から（推奨）

リリースアセットは
[GitHub Releases](https://github.com/hagix9/sinter/releases) ページで
公開されています。各アーカイブには `sinter` バイナリ、2 つの README、
ライセンスファイルが含まれます。

```sh
# 例: Ubuntu 24.04 amd64 コントローラ
curl -LO https://github.com/hagix9/sinter/releases/download/v0.2.0/sinter-v0.2.0-ubuntu24.04-amd64.tar.gz
curl -LO https://github.com/hagix9/sinter/releases/download/v0.2.0/SHA256SUMS

sha256sum -c SHA256SUMS    # 期待される出力: ... OK

tar -xzf sinter-v0.2.0-ubuntu24.04-amd64.tar.gz
./sinter-v0.2.0-ubuntu24.04-amd64/sinter --version   # sinter 0.2.0
```

Rocky Linux 9 x86_64 コントローラの場合は、代わりに
`sinter-v0.2.0-rocky9-x86_64.tar.gz` を使ってください。

:::note
リリースアーカイブ名は、そのバイナリを生成したツールチェーンの
プラットフォームを示します。同じバイナリは他のターゲットに対する
コントローラとしても動作します。プラットフォーム表記はビルド・検証
された環境を表すものであり、管理できるターゲットを表すものでは
ありません。
:::

## ソースからビルド

Rust ツールチェーン（rustup またはディストリビューションのパッケージ）
が必要です:

```sh
git clone https://github.com/hagix9/sinter.git
cd sinter
cargo build --locked --release
./target/release/sinter --version
```

## 管理対象ホストの要件

ターゲットに Sinter をインストールする必要はありません。必要なもの:

- `known_hosts` に登録済みの鍵で到達できる OpenSSH サーバ
- systemd
- `/bin/sh`
- `--sudo` を使う場合はパスワードなしの `sudo -n`

Sinter は未知または変更された SSH ホスト鍵を拒否します。デフォルト
以外の SSH ポートを使う場合は、`known_hosts` に `[host]:port` 形式の
明示的なエントリが必要です。

:::caution[将来の改善点]
現在、`curl | sh` 形式のインストーラはありません。ダウンロードと
チェックサム検証が、サポートされるインストール方法です。
:::
