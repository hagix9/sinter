---
title: 対応プラットフォーム
description: プラットフォーム、アーキテクチャ、パッケージバックエンドのサポートマトリクス。
---

## 管理対象

| プラットフォーム | アーキテクチャ | パッケージバックエンド | ステータス |
|------------------|----------------|------------------------|-----------|
| Ubuntu 24.04 LTS | amd64 | apt | サポート、受入検証済み |
| Ubuntu 26.04 LTS | amd64 | apt | サポート、受入検証済み |
| Rocky Linux 9 | x86_64 | dnf | サポート、受入検証済み |
| Rocky Linux 10 | x86_64 | dnf | サポート、受入検証済み |
| RHEL 9 | x86_64 | dnf | サポート、受入検証済み |
| RHEL 10 | x86_64 | dnf | サポート、受入検証済み |
| AlmaLinux 9 | x86_64 | dnf | サポート、受入検証済み |
| AlmaLinux 10 | x86_64 | dnf | サポート、受入検証済み |
| Oracle Linux | x86_64 | dnf | 互換性見込み — 受入検証は未実施 |

Oracle LinuxはRHEL系platformとして認識され、SinterのDNF backendを
使用します。対応するRHEL系実装と互換性があると見込まれますが、現在
Sinterの実ホスト受入マトリクスには含まれていません。

RHEL系ターゲットでは、標準的に構成されたDNFリポジトリが機能している
必要があります。リポジトリの転送と認証はネイティブのdnf/librepo
スタックに委任されます — プロバイダがエンタイトルメントを供給する
クラウドイメージを含む — ため、Sinter固有のリポジトリ設定は不要です。

## 統一 Linux x86_64 配布

Sinter v1.1.0では、対応するすべてのx86_64向けバージョンラインに
`sinter-v<VERSION>-linux-x86_64.tar.gz` を1つ配布します。
実行ファイルは共通ですが、実行時の検出により Ubuntu は APT、RHEL系は
DNF を使います。任意の Linux や他のアーキテクチャへの対応を意味しません。

v1.0.0 以降の各リリースは、公開前にリリース成果物そのものを8つの対応
ターゲットで受入検証し、受入manifest、raw log、チェックサムをリリース
アセットとして公開します（[受入証跡](https://github.com/hagix9/sinter/blob/main/release/ACCEPTANCE_EVIDENCE.md)参照）。

現行リリースの Sinter v1.1.0 は、Linux x86_64 検証ゲートを通過した後、
リリース成果物そのもの（`sinter-v1.1.0-linux-x86_64.tar.gz`）を8台の
実x86_64 Linuxホストで受入検証しました。検証したpoint releaseは
Ubuntu 24.04.5 LTS、Ubuntu 26.04.1 LTS、Rocky Linux 9.8、Rocky Linux 10.2、
RHEL 9.8、RHEL 10.2、AlmaLinux 9.8、AlmaLinux 10.2（すべてx86_64）です。
各ホストでtarballと展開した実行ファイルがバイト単位で同一（SHA-256）で
あることを確認し、同一の論理受入シナリオと成果物同一性・MCPのチェックを
実行しました。**結果: 408チェックが通過、失敗0。**
（[v1.1.0 の受入証跡](https://github.com/hagix9/sinter/releases/tag/v1.1.0)参照）Sinter v1.0.0 も同じ8台での受入検証
（408/408）を、v0.5.1 と v0.4.1 もそれぞれ以前の8台での受入検証（344/344）を通過しており、その記録は履歴として
保持します。他の各point releaseや将来のリリースを
個別に検証したという意味ではありません。
過去の v0.2.1 は従来のディストリビューション別アセットのままです。
現在のダウンロードは[インストール](https://sinter.fulltrust.co.jp/ja/getting-started/installation/)
を参照してください。

すべての管理対象に必要なもの:

- systemd
- OpenSSH サーバ（厳格な `known_hosts` 検証）
- `/bin/sh`
- `attr` パッケージ（`/usr/bin/getfattr`）— 詳細は下記
- 権限昇格が必要な場合はパスワードなしの `sudo -n`

### `attr` パッケージはターゲットの要件です

Sinter はパスを書き込む（または信頼すべき親ディレクトリを確認する）
前に、そのパスの拡張属性と POSIX ACL を列挙し、安全だと証明できない
セキュリティメタデータを持つパスは上書きせずに拒否します。この列挙は
`/usr/bin/getfattr`（`attr` パッケージが提供）を使用します。

各ターゲットで `test -x /usr/bin/getfattr` を確認してください。
このツールが不在のターゲットでは、`file`・`template`・`directory`・`link` の
各リソースはすべてフェイルクローズし、不足しているプログラムとその
インストール方法を示すエラーを返します:

```text
cannot inspect access metadata of parent path /; refusing unsafe path;
the target has no /usr/bin/getfattr, so access metadata cannot be inspected
(install the 'attr' package: apt install attr on Debian/Ubuntu,
dnf install attr on RHEL family)
```

ターゲルトごとに 1 回インストールしてください。この拒否は仕様であり、
バイパスされることはありません:

```sh
sudo apt install attr          # Debian / Ubuntu
sudo dnf install attr          # RHEL 系（Rocky など）
```

イメージの既定値を仮定せず、必要なツールが不在の場合だけ `attr` を
インストールしてください。

## コントローラ

コントローラ（`sinter` を実行する側）は macOS、Ubuntu 24.04 LTS、
Ubuntu 26.04 LTS、Rocky Linux 9、Rocky Linux 10、RHEL 9、RHEL 10、
AlmaLinux 9、AlmaLinux 10、その他バイナリがビルドできる x86_64 Linux
環境でサポートされます。Sinter のリリースバイナリは単一の Linux x86_64
アーティファクトです。公開済み v0.2.1 は
ディストリビューション別アセットを維持します
（[インストール](/ja/getting-started/installation/)を参照）。

## 明示的に非対応のもの

- その他のディストリビューション / リリース（バックエンドを推測する
  代わりに capability エラーでフェイルクローズ）。
- aarch64 のアーティファクトは検証されていません — ビルドが存在しても
  サポートを意味しません。

## スコープ

Sinter のスコープには動的インベントリ、ロール、プラグイン、
オーケストレーション、組み込みスクリプトは含まれません。リリース履歴は
[CHANGELOG](https://github.com/hagix9/sinter/blob/main/CHANGELOG.md)を
参照してください。
