---
title: インストール
description: リリース tarball から Sinter をインストールするか、ソースからビルドする。
---

Sinter は**コントローラ**（`sinter` を実行するマシン）上で動作します。
管理対象ホストに必要なのは SSH アクセスだけです。現在のリリースは、
サポートされる 2 つの管理対象プラットフォーム（Ubuntu 24.04 LTS amd64 と
Rocky Linux 9 x86_64）向けのバイナリを公開しています。macOS など他の OS の
コントローラは、ソースからビルドできます。

## リリース tarball から（Linux では推奨）

現在のリリースは **v0.2.1** です。リリースアセットは
[GitHub Releases](https://github.com/hagix9/sinter/releases) ページで
公開されています。各アーカイブには `sinter` バイナリ、2 つの README、
ライセンスファイルが含まれます。

```sh
# 例: Ubuntu 24.04 amd64 コントローラ
curl -LO https://github.com/hagix9/sinter/releases/download/v0.2.1/sinter-v0.2.1-ubuntu24.04-amd64.tar.gz
curl -LO https://github.com/hagix9/sinter/releases/download/v0.2.1/SHA256SUMS

sha256sum -c SHA256SUMS    # 期待される出力: ... OK

tar -xzf sinter-v0.2.1-ubuntu24.04-amd64.tar.gz
sudo install -m 0755 sinter-v0.2.1-ubuntu24.04-amd64/sinter /usr/local/bin/sinter
sinter --version   # sinter 0.2.1
```

Rocky Linux 9 x86_64 コントローラの場合は、代わりに
`sinter-v0.2.1-rocky9-x86_64.tar.gz` を使ってください。バイナリを `PATH`
の通った場所（上の例では `/usr/local/bin`）に置くと、どのディレクトリからも
`sinter` を実行できます。レシピの隣に置いて `./sinter` として実行しても
かまいません。

:::note
新しいリリースはこれらのダウンロードを置き換えます。v0.2.1 以外の
バージョンをインストールするには、そのリリースのファイル名を Releases
ページから取り、URL 内のタグを読み替えてください。ダウンロード、
チェックサム検証、展開、確認の手順は同じです。
:::

:::note
リリースアーカイブ名は、そのバイナリを生成したツールチェーンの
プラットフォームを示します。同じバイナリは他の Linux ターゲットに対する
コントローラとしても動作します。プラットフォーム表記はビルド・検証
された環境を表すものであり、管理できるターゲットを表すものでは
ありません。Linux 向けリリースバイナリは macOS 上では動作しません。
:::

## macOS（または他の環境）のコントローラ

macOS 向けのリリースアーティファクトはありません。代わりにソースから
ビルドしてください（下記参照）。管理対象ホストは、コントローラがどこで
動いていても、サポートされる Linux ターゲットです。

## ソースからビルド

Rust ツールチェーン（rustup またはディストリビューションのパッケージ）
が必要です:

```sh
git clone https://github.com/hagix9/sinter.git
cd sinter
cargo build --locked --release
./target/release/sinter --version
```

`target/release/sinter` を `PATH` の通った場所にコピーすると、インストール
済みのバイナリと同じように使えます。

## 管理対象ホストの要件

ターゲットに Sinter をインストールする必要はありません。必要なもの:

- ホスト鍵が `known_hosts` に登録済みの OpenSSH サーバ
- systemd
- `/bin/sh`
- `--sudo` を使う場合はパスワードなしの `sudo -n`
- 公開鍵をあらかじめ authorized_keys に登録済みのユーザーアカウント
  （SSH エージェントまたは鍵ファイルで到達できること）

## SSH 認証情報

Sinter は SSH を転送と認証の両方に使います。関わる識別情報は 2 つあり、
それぞれ別々に検証されます:

- **ホストの識別情報（ターゲットのホスト鍵）。** Sinter はサーバーを
  `known_hosts` ファイル（デフォルト `~/.ssh/known_hosts`、または
  `--known-hosts`）と照合します。未知または変更されたホスト鍵は
  フェイルクローズし、自動登録は行われません。
- **ユーザー認証（あなたの秘密鍵）。** Sinter は次の順で試します:
  実行中の ssh-agent、各 `--identity` ファイル、デフォルトの
  `~/.ssh/id_ed25519` と `~/.ssh/id_rsa`。対応する公開鍵が、ターゲット
  ユーザーとしてターゲット上であらかじめ許可されている必要があります。
  Sinter が鍵をプロビジョニングすることはありません。

Sinter は未知または変更された SSH ホスト鍵を拒否します。デフォルト
以外の SSH ポートを使う場合は、`known_hosts` に `[host]:port` 形式の
明示的なエントリが必要です。

:::caution[将来の改善点]
現在、`curl | sh` 形式のインストーラはありません。ダウンロードと
チェックサム検証が、サポートされるインストール方法です。
:::
