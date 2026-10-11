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

Sinter v1.3.0では、対応するすべてのx86_64向けバージョンラインに
`sinter-v<VERSION>-linux-x86_64.tar.gz` を1つ配布します。
実行ファイルは共通ですが、実行時の検出により Ubuntu は APT、RHEL系は
DNF を使います。任意の Linux や他のアーキテクチャへの対応を意味しません。

v1.0.0 以降の各リリースは、公開前にリリース成果物そのものを8つの対応
ターゲットで受入検証し、受入manifest、raw log、チェックサムをリリース
アセットとして公開します（[受入証跡](https://github.com/hagix9/sinter/blob/main/release/ACCEPTANCE_EVIDENCE.md)参照）。

現行リリースの Sinter v1.3.0 は、Linux x86_64 検証ゲートを通過した後、
リリース成果物そのもの（`sinter-v1.3.0-linux-x86_64.tar.gz`）を8台の
実x86_64 Linuxホストで受入検証しました。検証したpoint releaseは
Ubuntu 24.04.5 LTS、Ubuntu 26.04.1 LTS、Rocky Linux 9.8、Rocky Linux 10.2、
RHEL 9.8、RHEL 10.2、AlmaLinux 9.8、AlmaLinux 10.2（すべてx86_64）です。
各ホストでtarballと展開した実行ファイルがバイト単位で同一（SHA-256）で
あることを確認し、従来の受入シナリオと成果物同一性・MCPのチェック、実ホストでの
`group` → `user` → `directory` → `file` のライフサイクル、および v1.3.0 の機能
（進捗表示、`plan` と `apply` の一致、テンプレートタグのエラー、rpm の `~`/`^` バージョン）
の実ホスト検証を実行しました。
**結果: 3,980チェックが通過、失敗0。**
（[v1.3.0 の受入証跡](https://github.com/hagix9/sinter/releases/tag/v1.3.0)参照）
Sinter v1.2.0 も以前の同じ8台での受入検証（1240チェック、失敗0。[v1.2.0 の受入証跡](https://github.com/hagix9/sinter/releases/tag/v1.2.0)）を通過しています。
Sinter v1.1.3、v1.1.2、v1.1.1、v1.1.0、v1.0.0 も以前の同じ8台での受入検証
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

## 未リリースのシークレット機能の実機受入検証

暗号化シークレット機能（`sinter secrets`、`file.content: { secret: … }`、
`user.password_hash`）は v1.2.0 に含まれますが、リリース前の
**2026-10-04** に、ソースコミット
`bce63a5fe8a6ab8e8756f7e117b6c707ea124b91` からのリリース前ビルドで、
リリース受入と同じ 8 ターゲット上で実機受入検証を行いました。

| ターゲット | OS | sudo | 結果 |
|---|---|---|---|
| Ubuntu 24.04 LTS | 24.04.5 | sudo 1.9.15p5 | 合格 |
| Ubuntu 26.04 LTS | 26.04.1 | **sudo-rs 0.2.13** | 合格 |
| Rocky Linux 9 | 9.8 | sudo 1.9.17p2 | 合格 |
| Rocky Linux 10 | 10.2 | sudo 1.9.17p2 | 合格 |
| RHEL 9 | 9.8 | sudo 1.9.17p2 | 合格 |
| RHEL 10 | 10.2 | sudo 1.9.17p2 | 合格 |
| AlmaLinux 9 | 9.8 | sudo 1.9.17p2 | 合格 |
| AlmaLinux 10 | 10.2 | sudo 1.9.17p2 | 合格 |

すべて x86_64 です。**8 ターゲット中 8 ターゲットで合格**しました。

この検証で用いたバイナリは 1 つだけで、Rocky Linux 9.8 x86_64 上で追加
フラグなしの `cargo build --locked --release` によりビルドされ、SHA-256 は
`fe1a200e896b287c98543b6450298bc469ab3aff6bb427dbe77be91eb8b4488b`、必要とする
GLIBC の最大バージョンは `GLIBC_2.34` です。使用前に 8 ターゲットすべてで
バイナリが同一であることを確認しました。**これは公開済みのリリース
アーティファクトではありません**: `sinter-v1.2.0-linux-x86_64.tar.gz` ではありません。
上でリンクした v1.2.0 の受入証跡はリリースアーティファクトを対象としており、ここで述べた
シークレットの受入検証は再実行しておらず、`user.password_hash` もリリースアーティファクトでは
再実行していません。

受入検証した内容:

- **ファイルシークレット** — バイト単位の公開（NUL・CRLF を含むランダム
  バイナリ、末尾改行なし）、宣言した owner/group/mode、`validate` / `plan` /
  `apply` / `audit`、冪等性、外部からの変更の drift と復元、identity が無い /
  誤っている場合のフェイルクローズ。
- **`password_hash`** — 変更 1 回につき実際の `sudo -n /usr/sbin/chpasswd -e`
  が 1 回、ハッシュは標準入力のみ、保存されたフィールドとの照合および
  ターゲット上での `crypt` による機能確認、`sudo` 配下の
  `getent -s files shadow`、`/etc/shadow` の mode・owner 不変、`--sudo` なしの
  失敗、最終変更日の記録。
- **`$y$` の挙動** — Ubuntu 24.04、Ubuntu 26.04、Rocky Linux 10、RHEL 10、
  AlmaLinux 10 では受理・保存。Rocky Linux 9、RHEL 9、AlmaLinux 9 では
  **拒否**されます。拒否メッセージは
  `yescrypt ($y$) hashes are not supported on this platform (RHEL-family 9); use a $6$ hash`
  であり、`chpasswd` は呼ばれず、保存されたフィールドは変化しません。
- **ロック済みアカウントの保護** — *異なる*ハッシュでロックされたアカウントは
  コマンドが 1 つも実行されない段階で拒否され（`chpasswd` 0 回、保存
  フィールド不変、ロックは維持、`audit` は `DRIFT` を報告）、同じハッシュでは
  何も起こりません。
- **sudo-rs** — Ubuntu 26.04 のネイティブ sudo は sudo-rs 0.2.13 です
  （`/usr/bin/sudo` → `/usr/lib/cargo/bin/sudo`）。ハッシュとファイルペイ
  ロードを標準入力で渡す動作は、ローカルパイプと pty なしの SSH チャネルの
  両方で成功しました。どのターゲットにも何もインストール・置換していません。
- **SSH** — ホスト鍵を厳格に検証しつつ、各ターゲット自身の sshd に対して
  Sinter を SSH 経由で実行。16 MiB のシークレットは Ubuntu 26.04 で
  **4.2 秒**、Rocky Linux 9 で **4.4 秒**（Sinter の最大 RSS はそれぞれ
  93,580 kB、92,692 kB）で、300 秒の標準入力期限に十分余裕があります。残り
  6 ターゲットでも、同じホスト鍵検証付き SSH スモークを小さいペイロードで
  実行しました。
- **漏洩なし** — 8 ターゲットすべてで、Sinter の出力、sudo ログ、システムの
  認証ログ、証跡ファイル、ファイル名、プロセス一覧にシークレットは 1 件も
  検出されませんでした。
- **後片付け** — すべてのターゲットが基準状態（アカウントデータベース、
  subuid/subgid、パッケージ、有効ユニット、`authorized_keys`）と、元の
  `TERMINATED` の電源状態に戻りました。

この記録の限界（省略せず明記します）:

- SSH はターゲット自身の sshd への loopback 経由です。Sinter の SSH トランス
  ポート、ターゲットの sshd、ホスト鍵検証、リモート実行経路は立証しますが、
  外部ネットワーク経路の性能は測定していません。
- プロセス引数のサンプリングはベストエフォートです。より強い証拠は sudo
  ログと、Sinter が標準入力のみで秘密情報を渡す設計です。
- シークレットとして配置した鍵は Ed25519 のみで、他の鍵形式は検証して
  いません。
- FIPS モード、exFAT・ネットワークボリューム、NSS のみで提供されるアカウント、
  パスワードのマーカー `*` / 空 / `!*`、`user` / `group` の作成・削除の各
  次元は検証していません。これらはスクリプト化されたテストのみでカバーされて
  います。

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
