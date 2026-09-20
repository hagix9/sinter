---
title: Rocky Linux
description: Rocky Linux 9 / 10 x86_64 管理対象ガイド — dnf バックエンド。
---

Rocky Linux 9 x86_64 は v0.2.0 からサポートされています。Rocky Linux 10
x86_64 の資格確認は公開済み v0.4.0 に含まれます。どちらも **dnf** パッケージバックエンドを使います。

**受入基準環境:** Rocky Linux 9.8 x86_64（DNF 4.14.0）— 実際の SSH と
`sudo -n` 越しに、パッケージのインストール/削除/冪等性、file、
service、command リソースについて検証済み — および Rocky Linux 10.2
x86_64（DNF 4.20.0・rpm 4.19）。同じ 5 種類のリソースに加え、
purge の収束/冪等性について検証済みです。Rocky 9/10 は対応するversion lineであり、9.8 と 10.2 が検証済みの
基準環境です。他の各マイナーリリースを個別に検証した意味ではありません。

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
3. 必要な RPM ペイロードが URL 検証の後にスナップショットへ
   プリフェッチされる。
4. 最終的な変更が `dnf -C --setopt=cachedir=<snapshot>` で実行される
   — キャッシュのみ。
5. スナップショットは失敗時を含めて処理後に削除される。

いずれかのステップで完全性を証明できない場合、変更の前に
フェイルクローズします。

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
