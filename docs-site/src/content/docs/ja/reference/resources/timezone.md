---
title: timezone
description: ホストのシステムタイムゾーンを timedatectl で設定する。
---

**目的:** ホストのシステムタイムゾーンを宣言する。シンボリックリンク `/etc/localtime` が `/usr/share/zoneinfo` の下で指すゾーンである。

## 書式

```yaml
- id: zone
  type: timezone
  with:
    name: Asia/Tokyo
```

```toml
[[resources]]
id = "zone"
type = "timezone"

[resources.with]
name = "Asia/Tokyo"
```

## パラメータ

| パラメータ | 必須 | 型 | デフォルト | 説明 |
|-----------|------|-----|-----------|------|
| `name` | はい | string | — | `Asia/Tokyo`、`UTC`、`America/Argentina/Buenos_Aires` のような IANA ゾーン名。`A-Z`、`a-z`、`0-9`、`_`、`+`、`-` からなる 1〜3 個の要素を `/` で区切る。`-` で始まる要素は不可。64 バイト以下。 |

- `name` には変数を使える。ファクト、register、機密値は使えない。レシピの読み込み時に解決して検査する。
- 先頭の `/`、`.`、`..` は拒否する。`posix/` と `right/` の下のゾーン、および `posixrules` と `localtime` という名前も拒否する。ゾーンそのものを宣言する。
- 1 つのレシピに `timezone` は 1 つだけ。2 つ目は検証エラーになる。
- `/etc/localtime` はこのリソースが所有する。同じレシピでこのパスに `file`、`template`、`link`、`file_merge` を宣言すると検証エラーになる。

## 動作

- **観測（読み取りのみ）。** Sinter は `/etc/localtime` をたどらずに調べる。これはシンボリックリンクで、リンク先が `/usr/share/zoneinfo/<ゾーン>` か `../usr/share/zoneinfo/<ゾーン>` でなければならない。通常ファイル（コピーしたゾーンファイル）、`/etc/localtime` がないこと、それ以外のリンク先はエラーになる。Sinter はコピーされたファイルからゾーンを推測しない。
- **plan** はゾーンを `name` と比べる。異なる場合は、`/usr/share/zoneinfo/<name>` が通常ファイルとして存在すること、`/usr/bin/timedatectl` が存在することを確かめ、現在のゾーンと宣言したゾーンを表示する。インストールされていないゾーンはゾーン名を示すエラーになる。ただし、実行の前のリソース（たとえば `tzdata` パッケージ）がそれを提供しうる場合は、apply で改めて確認する。
- **apply** は root で `/usr/bin/timedatectl set-timezone <name>` をシェルを使わずに実行する。終了コードが 0 以外なら失敗である。終了コード 0 だけでは成功としない。`/etc/localtime` をもう一度観測し、`name` を指していなければリソースは失敗になる。ツールが強制終了された、タイムアウトした、接続が切れた場合は、ゾーンが変わったかどうか分からないと報告する。成功とは報告しない。
- 2 回目の apply は何も変更せず、`timedatectl` も実行しない。すでに宣言したゾーンにあるホストでは `timedatectl` そのものが要らない。
- **audit** はゾーンを `name` と比べ、違いを `timezone` のドリフトとして報告する。コピーされたゾーンファイル、リンクがないこと、観測の失敗はすべてエラーであり、ドリフトにはしない。

## Sinter がしないこと

- 時計、NTP 同期（`set-ntp`）、RTC のモード（`set-local-rtc`）、そのほかの `timedatectl` の設定は変えない。
- 何も再起動しない。すでに動いているプログラムは、再起動するまで起動時のタイムゾーンを使い続ける。ゾーンを変更する plan と apply の結果には、必ずこの注記が付く。
- `/etc/localtime` を自分で書くことはしない。タイムゾーンデータのインストールも、`/etc/timezone`（Debian、Ubuntu）の直接編集もしない。

変更があれば、ほかのリソースと同じようにハンドラへ通知する。

## 権限

ゾーンの変更には root が必要である。root で接続するか `--sudo` を使う。接続が root でない場合、plan はそのことを注記する。変更するものがない実行に root は要らない。

## 機密リソース

`sensitive: true` の場合、ゾーンは差分、注記、理由、audit の詳細に表示しない。ただし読み取り専用コマンドの記録には、Sinter が確認するゾーンファイル（`/usr/share/zoneinfo/<name>`）の名前が残る。機密の `file` のパスが残るのと同じである。

## 対応していないもの

- 通常ファイル（コピーしたゾーンファイル）としての `/etc/localtime`、または `/usr/share/zoneinfo` を指さないリンク。
- `/usr/bin/timedatectl` がないホスト（コンテナなど `systemd-timedated` がないシステム）。変更が必要な場合、plan と apply は「timezone is not supported on this host (/usr/bin/timedatectl was not found)」で失敗する。audit はリンクを読むだけである。
- システムによって `/usr/share/zoneinfo` の下でシンボリックリンクになっているゾーン名。ゾーンファイルは通常ファイルでなければならない。

## 対応 OS

Ubuntu 24.04 と 26.04、Rocky Linux、RHEL、AlmaLinux の 9 と 10。

このリソースは Sinter のスクリプト化したターゲットでのみテストしている。Rocky Linux 10.2 を読み取り専用で調べたところ、`/etc/localtime` は `/usr/share/zoneinfo/Asia/Tokyo` へのシンボリックリンクだった。**実ホストでは検証していないもの:** 各 OS で `timedatectl set-timezone` が書く内容、出力、終了コード。Ubuntu、EL 9、RHEL、AlmaLinux でのリンクの形。各 OS ですべてのゾーンファイルが通常ファイルかどうか。コンテナ内での動作。
