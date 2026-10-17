---
title: Rocky Linux
description: Rocky Linux 9 / 10 x86_64 管理対象ガイド — dnf バックエンド。
---

Rocky Linux 9 x86_64 は v0.2.0 から、Rocky Linux 10 x86_64 は v0.4.0 から
サポートされています。両version lineは v1.5.1 で受入検証済みであり、
どちらも **dnf** パッケージバックエンドを使います。

**受入基準環境:** Rocky Linux 9.8 x86_64（DNF 4.14.0）— 実際の SSH と
`sudo -n` 越しに、パッケージのインストール/削除/冪等性、file、
service、command リソースについて検証済み — および Rocky Linux 10.2
x86_64（DNF 4.20.0・rpm 4.19）。同じ 5 種類のリソースに加え、
purge の収束/冪等性について検証済みです。Rocky 9/10 は対応するversion lineであり、9.8 と 10.2 が検証済みの
基準環境です。他の各マイナーリリースを個別に検証した意味ではありません。

## 統一 Linux x86_64 配布

Sinter v1.5.1では、対応するすべてのx86_64向けバージョンラインに
`sinter-v<VERSION>-linux-x86_64.tar.gz` を1つ配布します。
実行ファイルは共通ですが、実行時の検出により Ubuntu は APT、RHEL系は
DNF を使います。任意の Linux や他のアーキテクチャへの対応を意味しません。

Sinter v1.5.1 のリリース成果物は Ubuntu 24.04、Ubuntu 26.04、
Rocky Linux 9.8、Rocky Linux 10.2、RHEL 9.8、RHEL 10.2、
AlmaLinux 9.8、AlmaLinux 10.2（すべてx86_64、264チェック通過・失敗0）の
8実ホストで受入検証済みです。
他の各point releaseや将来のリリースを個別に検証したという意味ではありません。
過去の v0.2.1 は従来のディストリビューション別アセットのままです。
現在のダウンロードは[インストール](https://sinter.fulltrust.co.jp/ja/getting-started/installation/)
を参照してください。


## 要件

| 要件 | 補足 |
|------|------|
| Rocky Linux 9 または 10 | x86_64 |
| OpenSSH サーバ | 厳格な `known_hosts` 検証 |
| systemd | `service` リソースに必要 |
| `/bin/sh` | ターゲット側シェル |
| `attr` パッケージ | `/usr/bin/getfattr`。ターゲットで確認し、不在なら dnf で `attr` をインストール |
| `sudo -n` | `--sudo` 使用時はパスワードなし sudo |
| dnf | パッケージバックエンド |

## パッケージ管理

`type: package` のレシピはプラットフォーム中立です。同じレシピが
Rocky 上では dnf で実行されます:

```yaml
version: 1

resources:
  - id: nano
    type: package
    with:
      name: nano
      state: present
```

## dnf インストールの仕組み

dnf のインストールでは、変更を行う `dnf` プロセスがメタデータのために
ネットワークに触れることはありません:

1. DNF メタデータキャッシュのプライベートスナップショットが
   `/var/tmp/sinter-dnf.*` 配下にモード 0700 で作成される。
2. トランザクション解決とメタデータ検証がスナップショットに対して
   **キャッシュのみ**で実行される。
3. 解決済みの RPM ペイロードがネイティブの `dnf`/librepo 転送経由で
   スナップショットへダウンロードされる — リポジトリ認証は
   dnf/librepo が担う — そして各ペイロードの RPM identity が
   凍結されたトランザクション集合に対して検証される。
4. 最終的な変更が `dnf -C --setopt=cachedir=<snapshot>` で実行される
   — キャッシュのみ。
5. スナップショットは失敗時を含めて処理後に削除される。

ペイロードの完全性またはidentityを証明できない場合、変更の前に
フェイルクローズします。

## Rocky Linux / RHEL 8 を SSH の接続先にする（v1.5.1）

Sinter 自体は EL8 では動きません（Linux 版は glibc 2.34 が必要です）。しかし、
対応する controller（EL9 / EL10、Ubuntu。macOS はソースからのビルドのみ）から SSH で EL8 のホストを
**管理**できます。v1.5.1 の検証で Rocky Linux 8.10（dnf 4.7.0）で実測しました
（リリースの受入としての主張ではまだありません）。

- **前提:** `attr` パッケージ（`getfattr`）。最小構成やクラウドのイメージには
  入っていないことが多く、その場合 `file` / `directory` / `template` は、その旨を
  示して fail-closed になります。先に導入してください（`attr` を `package`
  リソースで入れられます）。
- **Python:** 実際のパッケージ名で宣言してください。`python36`（module stream
  `python36:3.6`、自動で有効になります）、`python3.11`、`python3.12`、
  `python3.11-pip`、`python39`、`python38`。EL8 の `python3` と `python311` は
  パッケージ名ではなく provides なので、Sinter は導入の前に拒否し、実際の
  パッケージ名を案内します。[`examples/recipes/python-el8.yaml`](https://github.com/hagix9/sinter/blob/main/examples/recipes/python-el8.yaml) を参照してください。
- **module stream:** module の既定の stream を有効にしながらの導入は動作します
  （取引に `Enabling module streams:` が出る場合）。既定以外の stream を使うときは
  先に有効にしてください。[`examples/recipes/postgresql-os.yaml`](https://github.com/hagix9/sinter/blob/main/examples/recipes/postgresql-os.yaml) を参照してください。

## PostgreSQL、EPEL / CRB、その他のリポジトリ

- **OS の PostgreSQL:** 既定は EL8 が 10、EL9 が 13 で、どちらも upstream の
  サポートが終了しています。EL10 は 16 です。OS の **16** か、PGDG の **17** を
  使ってください。新しいサーバーに既定の 10 や 13 を選ばないでください。
  [`examples/recipes/postgresql-os.yaml`](https://github.com/hagix9/sinter/blob/main/examples/recipes/postgresql-os.yaml) は 3 つとも 16 を導入し（EL8 / EL9 は
  module stream `postgresql:16`）、検証付きの `postgresql.conf`、`pg_hba.conf`、
  [`postgresql_role`](/ja/reference/resources/postgresql_role/) を設定します。

  | メジャー版 | EL8（module stream） | EL9 | EL10 | upstream のサポート終了 |
  |-----------|----------------------|-----|------|------------------------|
  | 10 | `postgresql:10`（既定） | — | — | 2022-11（終了） |
  | 12 | `postgresql:12` | — | — | 2024-11（終了） |
  | 13 | `postgresql:13` | 既定（モジュールではない） | — | 2025-11（終了） |
  | 15 | `postgresql:15` | `postgresql:15` | — | 2027-11 |
  | 16 | `postgresql:16` | `postgresql:16` | 既定 | 2028-11 |
  | 17 | PGDG | PGDG | PGDG | 2029-11 |

  EL8 の stream は、Rocky Linux 8.10 で `dnf module list postgresql` が示すもの
  です（9.6 も表示されます）。v1.5.1 の検証で検証したのは、EL8 / EL9 の
  `postgresql:16`、EL10 の 16、3 つすべての PGDG 17 の導入で、ほかの行は検証して
  いません。日付は PostgreSQL プロジェクトのものです。ディストリビューションが
  module stream を保守する期間は、そのディストリビューションの application
  stream のライフサイクルで決まります。
- **PGDG の PostgreSQL 17:** [`examples/recipes/postgresql-pgdg17.yaml`](https://github.com/hagix9/sinter/blob/main/examples/recipes/postgresql-pgdg17.yaml) は、指紋を
  照合して固定した鍵と、`gpgcheck` / `repo_gpgcheck` を有効にした PGDG の
  リポジトリをファイルとして宣言します。PGDG の repo RPM を URL から導入する
  方法は推奨しません。dnf は既定ではローカル / URL の RPM の署名を検証しません
  （`localpkg_gpgcheck=0`）。
- **EPEL と CRB / PowerTools:** [`examples/recipes/epel-crb.yaml`](https://github.com/hagix9/sinter/blob/main/examples/recipes/epel-crb.yaml)。dnf は初回の
  利用時に、リポジトリの `gpgkey` のファイルから鍵を取り込みます。信頼の起点は
  その鍵のファイルなので、サードパーティのリポジトリでは鍵を固定して（ファイル
  として管理して）ください。
- **任意の署名付きリポジトリ:** [`examples/recipes/signed-repo.yaml`](https://github.com/hagix9/sinter/blob/main/examples/recipes/signed-repo.yaml)（鍵のファイル
  + リポジトリのファイル + パッケージ）。署名の無いパッケージや別の鍵で署名
  されたパッケージは拒否されます（`GPG check FAILED`）。

**リポジトリの管理方法（推奨）。** サードパーティのリポジトリは、固定した鍵と
`.repo` のファイルとして、`gpgcheck` を有効にして宣言してください。どちらのファイルも
ほかの管理ファイルと同じく plan、apply、**audit** の対象になり、2 回目の apply は
変更なしになります。リポジトリ専用のリソースはありません。OS に含まれていて無効に
なっているリポジトリ（CRB、PowerTools）には管理できる専用のファイルが無いので、
読み取りだけの確認を先に行い、無効だったときだけ有効化のコマンドを実行します
（`epel-crb.yaml`）。パッケージは audit されますが、コマンドが変えたリポジトリの
有効状態そのものは `sinter audit` の対象外です（command リソースは audit しません）。

## プラットフォーム検出

`/etc/os-release` の `ID=rocky`（RHEL ファミリ）が dnf バックエンドを
選択します。未知または非対応のプラットフォームは capability エラー
です。Sinter がバックエンドを推測することはありません。

## 制限事項

- 検証済みは x86_64 のみ。aarch64 のサポートは想定しないでください。
- Rocky 9.8 が受入基準環境です。他の 9.x マイナーリリースは同じ
  インターフェースを共有しますが、個別には検証されていません。
- ハッシュ化された `known_hosts` エントリはサポートされません
  （すべてのターゲットで同じ）。
