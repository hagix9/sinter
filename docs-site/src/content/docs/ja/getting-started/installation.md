---
title: インストール
description: リリース tarball から Sinter をインストールするか、ソースからビルドする。
---

Sinter は**コントローラ**上で動作します。管理対象ホストには下記の要件が
必要ですが、Sinter のインストールは不要です。公開済み v0.2.1 の Linux
アーティファクトはディストリビューション別です。Rocky Linux 9 を基準に
ビルドする統一 Linux x86_64 アーティファクトは、4実ホストで同一
バイナリの受入検証を終えた将来リリースの標準であり、v0.2.1 の
公開アセットではありません。macOS のコントローラはソースからビルドできます。

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

## リリース tarball から（Linux では推奨）

現在のリリースは **v0.2.1** です。リリースアセットは
[GitHub Releases](https://github.com/hagix9/sinter/releases) ページで
公開されています。各アーカイブには `sinter` バイナリ、2 つの README、
ライセンスファイルが含まれます。

```sh
# コントローラに合わせて Ubuntu 24.04 または Rocky Linux 9 を選択します。
ASSET=sinter-v0.2.1-ubuntu24.04-amd64.tar.gz
# ASSET=sinter-v0.2.1-rocky9-x86_64.tar.gz
curl -fLO "https://github.com/hagix9/sinter/releases/download/v0.2.1/$ASSET"
curl -fLO https://github.com/hagix9/sinter/releases/download/v0.2.1/SHA256SUMS

grep -F "  $ASSET" SHA256SUMS | sha256sum -c -
tar -xzf "$ASSET"
sudo install -m 0755 "${ASSET%.tar.gz}/sinter" /usr/local/bin/sinter
sinter --version   # sinter 0.2.1
```

バイナリを `PATH` の通った場所（上の例では `/usr/local/bin`）に置くと、
どのディレクトリからも `sinter` を実行できます。レシピの隣に置いて
`./sinter` として実行してもかまいません。

:::note
新しいリリースはこれらのダウンロードを置き換えます。v0.2.1 以外の
バージョンをインストールするには、そのリリースのファイル名を Releases
ページから取り、URL 内のタグを読み替えてください。ダウンロード、
チェックサム検証、展開、確認の手順は同じです。
:::

:::note
v0.2.1 の名称はビルド環境を示します。公開済みアセットの名前を変更したり、
v0.2.1 の URL に将来の統一名称を使用したりしないでください。Linux の
バイナリは macOS では動作しません。
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
- `attr` パッケージ（`/usr/bin/getfattr`）— Sinter はパスを書き込む前に
  拡張属性と POSIX ACL を確認し、安全だと証明できないパスは拒否します。
  各ターゲットで `test -x /usr/bin/getfattr` を確認してください。
  不在なら Ubuntu は `sudo apt install attr`、Rocky は
  `sudo dnf install attr` でインストールしてください
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
