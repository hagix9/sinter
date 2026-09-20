---
title: 対応プラットフォーム
description: プラットフォーム、アーキテクチャ、パッケージバックエンドのサポートマトリクス。
---

## 管理対象

| プラットフォーム | アーキテクチャ | パッケージバックエンド | ステータス |
|------------------|----------------|------------------------|-----------|
| Ubuntu 24.04 LTS | amd64 | apt | サポート |
| Ubuntu 26.04 LTS | amd64 | apt | サポート |
| Rocky Linux 9 | x86_64 | dnf | サポート |
| Rocky Linux 10 | x86_64 | dnf | サポート |

## 統一 Linux x86_64 配布

公開済み v0.4.0 では、対応する Ubuntu 24.04 / 26.04、Rocky Linux 9 / 10
の x86_64 向けに `sinter-v<VERSION>-linux-x86_64.tar.gz` を1つ配布します。
実行ファイルは共通ですが、実行時の検出により Ubuntu は APT、Rocky は
DNF を使います。任意の Linux や他のアーキテクチャへの対応を意味しません。

公開済み v0.4.0 の実行ファイルは Ubuntu 24.04.5 LTS、Ubuntu 26.04.1 LTS、Rocky Linux 9.8、
Rocky Linux 10.2（すべて x86_64）の4実ホストで受入検証済みです。
他の各point releaseや将来のリリースを個別に検証したという意味ではありません。
過去の v0.2.1 は従来のディストリビューション別アセットのままです。
現在のダウンロードは[インストール](https://hagix9.github.io/sinter/ja/getting-started/installation/)
を参照してください。統一 v0.4.0 アーティファクトは公開済みです。

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
Ubuntu 26.04 LTS、Rocky Linux 9、Rocky Linux 10、その他バイナリがビルド
できる x86_64 Linux 環境でサポートされます。v0.4.0 のリリースバイナリは
単一の Linux x86_64 アーティファクトです。公開済み v0.2.1 は
ディストリビューション別アセットを維持します
（[インストール](/sinter/ja/getting-started/installation/)を参照）。

## 明示的に非対応のもの

- その他のディストリビューション / リリース（バックエンドを推測する
  代わりに capability エラーでフェイルクローズ）。
- ハッシュ化された `known_hosts` エントリ。
- aarch64 のアーティファクトは検証されていません — ビルドが存在しても
  サポートを意味しません。

## スコープ

Sinter のスコープにはインベントリ、ロール、プラグイン、
オーケストレーション、組み込みスクリプトは含まれません。リリース履歴は
[CHANGELOG](https://github.com/hagix9/sinter/blob/main/CHANGELOG.md)を
参照してください。
