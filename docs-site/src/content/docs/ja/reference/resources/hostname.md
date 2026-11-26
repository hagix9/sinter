---
title: hostname
description: ホストの静的ホスト名を hostnamectl で設定する。
---

**目的:** ホストの静的ホスト名（`hostnamectl`）を宣言する。`/etc/hostname` に保存される名前である。

## 書式

```yaml
- id: name
  type: hostname
  with:
    name: web01.example.invalid
```

```toml
[[resources]]
id = "name"
type = "hostname"

[resources.with]
name = "web01.example.invalid"
```

## パラメータ

| パラメータ | 必須 | 型 | デフォルト | 説明 |
|-----------|------|-----|-----------|------|
| `name` | はい | string | — | ホスト名。`a-z`、`0-9`、`-` からなるラベル（各 1〜63 バイト、先頭と末尾に `-` は不可）を 1 つのドットで区切る。全体で 1〜64 バイト。小文字のみ。 |

- `name` には変数を使える。ファクト、register、機密値は使えない。レシピの読み込み時に解決して検査する。
- 大文字を含む名前は検証エラーになり、小文字で書くよう求める。Sinter が大文字を小文字に直すことはない。
- 1 つのレシピに `hostname` は 1 つだけ。2 つ目は検証エラーになる。

## 動作

- **観測。** Sinter は `/usr/bin/hostnamectl --static` と `/usr/bin/hostnamectl --transient` を実行する（読み取りのみ）。終了コードが 0 で、標準出力が 1 行以下の場合だけ受け入れる。静的ホスト名の答えが空なら「未設定」とみなす。それ以外の終了コード、2 行目、出力の切り捨て、シグナル、タイムアウトはエラーになる。Sinter は名前を推測しない。
- **plan** は静的ホスト名を `name` と比べる。異なる場合は現在の名前と宣言した名前を表示し、ほかには何も実行しない。
- **apply** は root で `/usr/bin/hostnamectl set-hostname <name>` をシェルを使わずに実行する。終了コードが 0 以外なら失敗である。終了コード 0 だけでは成功としない。静的ホスト名をもう一度観測し、`name` と等しくなければリソースは失敗になる。ツールが強制終了された、タイムアウトした、接続が切れた場合は、名前が変わったかどうか分からないと報告する。成功とは報告しない。
- 2 回目の apply は何も変更せず、`set-hostname` も実行しない。
- **一時的な（transient）ホスト名は報告するだけで、管理しない。** transient ホスト名は稼働中のカーネルが使っている名前である。変更の後（または変更が不要だったとき、あるいは audit）にこれが `name` と異なる場合、結果に注記を付ける。DHCP などの別の仕組みが稼働中の名前を設定している、という内容である。これはドリフトでも失敗でもない。
- **audit** は静的ホスト名を `name` と比べ、違いを `static` のドリフトとして報告する。観測の失敗と、`hostnamectl` がないホストはエラーになる。

## Sinter がしないこと

- `/etc/hosts` は編集しない。ホスト自身の名前のエントリが必要なら、[`file_merge`](/ja/reference/resources/file_merge/) で宣言する。
- 何も再起動しない。起動時にホスト名を読むプログラムは、再起動するまで以前の名前を使い続ける。名前を変更する plan と apply の結果には、必ずこの注記が付く。
- pretty 名、transient 名だけの設定、そのほかの `hostnamectl` のプロパティは設定しない。
- 同じ実行の中の `facts.hostname` は、Sinter が接続したときに観測した名前のままである。新しい名前は次の実行から見える。

変更があれば、ほかのリソースと同じようにハンドラへ通知する。そのため、レシピで `service` ハンドラを使ってサービスを再起動できる。

Sinter が使う SSH 接続はホスト名に依存しない。そのため、このリソースには接続リスクの扱いがない。

## 権限

ホスト名の変更には root が必要である。root で接続するか `--sudo` を使う。接続が root でない場合、plan はそのことを注記する。変更するものがない実行に root は要らない。

## 対応していないもの

- `/usr/bin/hostnamectl` がないホスト: plan と apply は「hostname is not supported on this host (hostnamectl was not found)」で失敗し、audit はエラーを報告する。
- 大文字、アンダースコア、末尾のドット、64 バイトを超える名前。
- `systemd-hostnamed` が使えないコンテナなどの環境: そこでは `hostnamectl` が失敗し、Sinter はそれを観測エラーとして報告する。

## 対応 OS

Ubuntu 24.04 と 26.04、Rocky Linux、RHEL、AlmaLinux の 9 と 10。

このリソースは Sinter のスクリプト化したテスト用ターゲットでのみ試験している。**実ホストでは検証していない**。対象は、`hostnamectl --static`、`--transient`、`set-hostname` の出力と終了コード、および transient ホスト名がどうなるかである。
