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

**受入基準環境:**

- Ubuntu 24.04.4 amd64（回帰・同一バイナリ確認の参照VM環境）
  および Ubuntu 26.04.1 LTS amd64（fresh hostの最終受入: command・file・
  package・service・guard・拒否/秘匿・冪等性と独立状態確認。
  旧ホストのtemplate証跡は履歴）。
- Rocky Linux 9.8 x86_64（DNF 4.14.0）— v0.2.0 のターゲット受入環境であり、
  Linux x86_64 アーティファクトのビルド基準環境。
- Rocky Linux 10.2 x86_64（DNF 4.20.0・rpm 4.19）— 5 種類のリソースすべてと
  purge の冪等性に関する実ホスト受入。

上記は検証済みpoint releaseの基準環境であり、他の各point releaseや
将来のリリースを個別に受入検証したという意味ではありません。
Ubuntu 26.04の最終資格確認はfresh GCP host `ubuntu02-b2` で、同じ
Rocky 9基準candidateを用い、独立状態確認と19件の記録済みチェック成功を
確認しました。旧ホストのincidentは履歴であり最終証跡ではありません。
Ubuntu 24.04.4とRocky 9.8の同一バイナリ回帰確認はx86_64 VMで実施しました。

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
できる x86_64 Linux 環境でサポートされます。リリースバイナリは
単一の Linux x86_64 アーティファクトとして公開されます
（[インストール](/sinter/ja/getting-started/installation/)を参照）。

## 明示的に非対応のもの

- その他のディストリビューション / リリース（バックエンドを推測する
  代わりに capability エラーでフェイルクローズ）。
- ハッシュ化された `known_hosts` エントリ。
- aarch64 のアーティファクトは検証されていません — ビルドが存在しても
  サポートを意味しません。

## スコープ

v0.2.1 のスコープにはインベントリ、ロール、プラグイン、
オーケストレーション、組み込みスクリプトは含まれません。リリース履歴は
[CHANGELOG](https://github.com/hagix9/sinter/blob/main/CHANGELOG.md)を
参照してください。
