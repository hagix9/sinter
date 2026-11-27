---
title: locale
description: ホストのシステム既定ロケール（LANG と LC_*）を localectl で設定する。
---

**目的:** ホストのシステム既定ロケールを宣言する。`LANG` と、必要に応じて個々の `LC_*` カテゴリであり、OS がロケールファイルに保存している値である。

## 書式

```yaml
- id: default-locale
  type: locale
  with:
    lang: en_US.UTF-8
    lc:
      LC_TIME: en_GB.UTF-8
```

```toml
[[resources]]
id = "default-locale"
type = "locale"

[resources.with]
lang = "en_US.UTF-8"

[resources.with.lc]
LC_TIME = "en_GB.UTF-8"
```

## パラメータ

| パラメータ | 必須 | 型 | デフォルト | 説明 |
|-----------|------|-----|-----------|------|
| `lang` | いいえ | string | — | `LANG` の値。 |
| `lc` | いいえ | map | — | `LC_*` カテゴリとその値。キーは `LC_CTYPE`、`LC_NUMERIC`、`LC_TIME`、`LC_COLLATE`、`LC_MONETARY`、`LC_MESSAGES`、`LC_PAPER`、`LC_NAME`、`LC_ADDRESS`、`LC_TELEPHONE`、`LC_MEASUREMENT`、`LC_IDENTIFICATION`。 |

- 設定は少なくとも 1 つ必要である。
- 値は `C`、`POSIX`（`C.UTF-8` のようにコードセット付きも可）、または `en_US.UTF-8`、`ja_JP.UTF-8`、`sr_RS@latin` のような `ll[_CC][.codeset][@modifier]`。英字、数字、`_ . @ -` からなり、64 バイト以下。
- `lang` には変数を使える。ファクト、register、機密値は使えない。レシピの読み込み時に解決して検査する。`lc` の値はリテラルの文字列である。
- `LC_ALL` と `LANGUAGE` は拒否する。`LC_ALL` はほかのすべての設定を上書きするもので、システムの既定値には向かない。`LANGUAGE` は言語のリストであり、ロケールではない。
- 1 つのレシピに `locale` は 1 つだけ。2 つ目は検証エラーになる。
- `/etc/locale.conf` と `/etc/default/locale` はこのリソースが所有する（OS にかかわらず両方）。同じレシピでどちらかのパスに `file`、`template`、`file_merge` を宣言すると検証エラーになる。

## 動作

- **既定値の置き場所。** Rocky Linux、RHEL、AlmaLinux では `/etc/locale.conf`。Ubuntu では `/etc/default/locale`。Sinter が OS ファミリーを認識できないホストでは、リソースを拒否する（「locale is not supported on this host」）。
- **Ubuntu のリンク。** Ubuntu 24.04 以降では `/etc/default/locale` が `../locale.conf` へのリンクで、値は `/etc/locale.conf` にある。Sinter がたどるのはこのリンクだけである。条件は、root が所有し、リンクの文字列が `../locale.conf` か `/etc/locale.conf` で、リンク先の `/etc/locale.conf` が通常ファイル（または存在しない）であること。ほかのリンク、別アカウントが所有するリンク、`/etc/locale.conf` 自体がリンクである構成は拒否する。読み取り後にリンクをもう一度確認する。`localectl` がリンクを置き換えたり消したりした場合、apply は変更を報告したうえで失敗する。Sinter はリンクを元に戻さない。
- **観測（読み取りのみ）。** Sinter はこのファイルを、上のリンク以外のシンボリックリンクをたどらずに読み、`KEY=value` か `KEY="value"` の行、空行、`#` のコメントだけを受け入れる。同じキーが 2 回ある、単一引用符、`export`、`$`、バッククォート、復帰文字、そのほかの書き方はエラーになる。シェルがそれをどう解釈するかを Sinter は推測しない。ファイルがない場合は、どのキーも設定されていないとみなす。
- **管理するのは宣言したキーだけである。** ファイル内のほかのキーは比較せず、変更にも含めない。
- **利用可能か（plan、読み取りのみ）。** 変更が必要な場合、`C` と `POSIX` 以外の宣言値はすべて `/usr/bin/locale -a` に載っていなければならない。コードセットは大文字小文字と `-` を区別せずに比べるので、`en_US.UTF-8` は `en_US.utf8` と一致する。載っていないロケールはエラーになる（「locale … is not installed on this host; install or generate it first (a language-pack / glibc-langpack package, or locale-gen) — Sinter does not do that」）。実行の前のリソース（たとえば言語パックのパッケージ）がそれを提供しうる場合、plan は apply で改めて確認すると表示する。
- **apply** は root で `/usr/bin/localectl set-locale KEY=value ...` をシェルを使わずに実行する。宣言したキーはすべて渡す（すでに設定済みのキーも渡すので、ツールが設定全体を置き換えても残る）。終了コードが 0 以外なら失敗である。終了コード 0 だけでは成功としない。ファイルをもう一度読み、宣言したキーがすべて宣言した値になっていなければリソースは失敗になる。宣言していないキーを `localectl` が変えたり消したりした場合は、結果の注記で知らせる。ツールが強制終了された、タイムアウトした、接続が切れた場合は、既定値が変わったかどうか分からないと報告する。成功とは報告しない。
- 2 回目の apply は何も変更せず、`locale -a` も `localectl` も実行しない。
- **audit** は、宣言したキーのうち値が異なるものを、キー名の次元（`LANG`、`LC_TIME` など）のドリフトとして報告する。Sinter が読めない、または理解できないファイルと、認識できない OS ファミリーはエラーであり、ドリフトにはしない。

## Sinter がしないこと

- 言語パックはインストールしない。`locale-gen` も `localedef` も実行しない。
- ロケールファイルを自分で書くことはしない。書くのは `localectl` である。
- 何も再起動せず、動いているセッションも変えない。既定値は、これからのログインと、この後に起動するサービスに適用される。既存のセッションと動いているサービスは元のロケールのままである。既定値を変更する plan と apply の結果には、必ずこの注記が付く。
- コンソールのキーマップと X11 のレイアウト（`localectl set-keymap`、`set-x11-keymap`）は設定しない。

## 権限

既定値の変更には root が必要である。root で接続するか `--sudo` を使う。接続が root でない場合、plan はそのことを注記する。変更するものがない実行に root は要らない。

## 対応していないもの

- OS ファミリーが Red Hat 系でも Debian 系でもないホスト。
- `/usr/bin/localectl` がないホスト（`systemd-localed` がないコンテナなど）。変更が必要な場合、plan と apply は「locale is not supported on this host (/usr/bin/localectl was not found)」で失敗する。
- `KEY=value` / `KEY="value"` を超えるシェル構文を含むロケールファイル。

## 対応 OS

Ubuntu 24.04 と 26.04、Rocky Linux、RHEL、AlmaLinux の 9 と 10。

このリソースは Sinter のスクリプト化したターゲットでのみテストしている。Rocky Linux 10.2 を読み取り専用で調べたところ、`/etc/locale.conf` は `LANG=en_US.UTF-8` で、`/etc/default/locale` はなく、`locale -a` は `C`、`C.utf8`、`en_US`、`en_US.utf8` などを返した。**実ホストでは検証していないもの:** 各 OS で `localectl set-locale` がファイルをどう書き換えるか、渡していないキーとコメントを残すかどうか。Ubuntu の `localectl` が `/etc/locale.conf` に書き、リンクを残すこと（v1.16.0 RC 2 の受入で Ubuntu 24.04 のリンク構成を確認し、RC 2 はこれを拒否した）。`localectl` の終了コードとメッセージ。Ubuntu、EL 9、RHEL、AlmaLinux での `locale -a`。
