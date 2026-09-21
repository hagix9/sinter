---
title: インストール
description: リリース tarball から Sinter をインストールするか、ソースからビルドする。
---

## インストール

Sinter **v0.4.1** は、対応するすべての Linux x86_64 プラットフォーム
ライン — Ubuntu 24.04 / 26.04 LTS、Rocky Linux 9 / 10、RHEL 9 / 10、
AlmaLinux 9 / 10 — を1つの `sinter-v0.4.1-linux-x86_64.tar.gz`
アーティファクトで配布します。

```sh
curl -fsSL https://hagix9.github.io/sinter/install.sh | sh
$HOME/.local/bin/sinter --version
```

インストーラは公式GitHubの最新安定版を選び、展開前にSHA256SUMSを検証し、
sudoを使わず `$HOME/.local/bin` に配置します。必要なら自分でPATHへ追加して
ください。シェル設定は変更しません。実行前の内容確認と手動ダウンロードは
[インストール](https://hagix9.github.io/sinter/ja/getting-started/installation/)を参照してください。

### 実行前に内容を確認

```sh
curl -fsSLo install.sh https://hagix9.github.io/sinter/install.sh
less install.sh
sh install.sh
```

### バージョンと配置先

```sh
SINTER_VERSION=v0.4.1 sh install.sh
SINTER_INSTALL_DIR="$HOME/bin" sh install.sh
```

インストーラは Linux x86_64/amd64 専用です。curl、GNU tar、sha256sumを
含むcoreutilsが必要です。未対応OS・アーキテクチャは拒否し、ARMアセットは
ありません。配置先は絶対パスの信頼できるディレクトリに限定します。
既存のユーザー所有の通常ファイルは原子的に置換できますが、symlinkや
非通常オブジェクトは拒否します。ネットワーク・checksum・構造検証の失敗では
既存実行ファイルを保持します。sudo、PATH、シェル設定の自動変更はありません。
checksumは破損・配布整合性を確認し、GitHub侵害への完全な防御ではありません。

### リリースから手動インストール

```sh
ASSET=sinter-v0.4.1-linux-x86_64.tar.gz
curl -fLO "https://github.com/hagix9/sinter/releases/download/v0.4.1/$ASSET"
curl -fLO https://github.com/hagix9/sinter/releases/download/v0.4.1/SHA256SUMS
grep -F "  $ASSET" SHA256SUMS | sha256sum -c -
tar -xzf "$ASSET"
sudo install -m 0755 "${ASSET%.tar.gz}/sinter" /usr/local/bin/sinter
/usr/local/bin/sinter --version
```

環境変数はインストールにだけ適用し、永続的なホスト設定にはしません。
過去のv0.2.1アセットは従来のディストリビューション別名称を維持します。

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
  不在なら Ubuntu は `sudo apt install attr`、RHEL系（Rocky、RHEL、
  AlmaLinux）は `sudo dnf install attr` でインストールしてください
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
