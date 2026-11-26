---
title: kernel_module
description: カーネルモジュールを今と起動時に読み込む、またはブラックリストに入れる。Sinter 自身のファイルと modprobe を使う。
---

**目的:** カーネルモジュール 1 つを宣言する。今も起動のたびにも読み込む、起動時に Sinter が読み込むのをやめる、またはエイリアスによる自動読み込みから外す（ブラックリスト）のいずれかである。

## 書式

```yaml
- id: br-netfilter
  type: kernel_module
  with:
    name: br_netfilter

- id: no-pcspkr
  type: kernel_module
  with:
    name: pcspkr
    state: blacklisted
```

```toml
[[resources]]
id = "br-netfilter"
type = "kernel_module"

[resources.with]
name = "br_netfilter"

[[resources]]
id = "no-pcspkr"
type = "kernel_module"

[resources.with]
name = "pcspkr"
state = "blacklisted"
```

## パラメータ

| パラメータ | 必須 | 型 | デフォルト | 説明 |
|-----------|------|-----|-----------|------|
| `name` | はい | string | — | モジュール名。`A-Z`、`a-z`、`0-9`、`_`、`-` からなる 1〜64 バイト。`-` と `_` は同じモジュールを指す。Sinter は `_` の形を使う。 |
| `state` | いいえ | string | `present` | `present`、`absent`、`blacklisted` のいずれか（変数ではなくリテラル）。 |
| `runtime` | いいえ | boolean | `true` | `present` のとき、今モジュールを読み込む。 |
| `persist` | いいえ | boolean | `true` | `present` のとき、起動のたびに読み込む（`/etc/modules-load.d` の Sinter のファイル）。 |

- `name` には変数を使える。ファクト、register、機密値は使えない。レシピの読み込み時に解決して検査する。
- `present` では `runtime` と `persist` の少なくとも一方が true でなければならない。`absent` と `blacklisted` では `runtime` と `persist` を拒否する。
- 1 つのモジュールに `kernel_module` は 1 つだけ（`br-netfilter` と `br_netfilter` は同じ）。2 つ目は検証エラーになる。
- そのモジュールの Sinter の 2 つのファイルはこのリソースが所有する。同じレシピでどちらかのパスに `file`、`template`、`file_merge` を宣言すると検証エラーになる。

## Sinter が所有するファイル

| ファイル | 内容 | 使う状態 |
|---------|------|---------|
| `/etc/modules-load.d/sinter-<name>.conf` | `# Managed by Sinter (kernel_module). Local changes are replaced.` と `<name>` | `persist` 付きの `present` |
| `/etc/modprobe.d/sinter-blacklist-<name>.conf` | 同じコメント行と `blacklist <name>` | `blacklisted` |

どちらも `root:root`、モード `0644` で、`file` リソースを通して丸ごと書く（アトミックな置き換え、親ディレクトリの検査、シンボリックリンクの拒否、差分）。これらのディレクトリのほかのファイルは一切編集しない。

## 動作

- **present**
  - 読み込まれているかどうかは `/sys/module/<name>` で判断する（そこにディレクトリがあれば読み込み済み。そこに現れる組み込みモジュールも読み込み済みとみなす）。`/sys/module` そのものが存在しなければならない。
  - 読み込みが必要な場合だけ、`/usr/sbin/modprobe -n -v -- <name>`（modprobe のドライラン）が終了コード 0 でなければならない。終了コード 1 は「module … is not available for the running kernel」というエラーになり、ファイルは何も書かない。それ以外の答えは観測エラーである。実行の前のリソース（たとえばパッケージ）がそのモジュールを提供しうる場合、plan は apply で改めて確認すると表示する。
  - apply はまず Sinter のファイルを書き（ブラックリストのファイルを消し、起動時のファイルを書く）、次に root で `/usr/sbin/modprobe -- <name>` を実行して、`/sys/module/<name>` をもう一度観測する。終了コードが 0 以外、またはモジュールが現れない場合は失敗である。すでにファイルを変更していた場合、失敗はその変更も報告する。シグナル、タイムアウト、接続の切断は「読み込まれたかどうか分からない」と報告し、成功とはしない。
  - 読み込み済みのモジュールには、ドライランも `modprobe` も要らない。
- **absent**: Sinter の起動時のファイルを消す。モジュールは**アンロードしない**。再起動するまで読み込まれたままである。
- **blacklisted**: Sinter のブラックリストのファイルを書き、起動時のファイルを消す。モジュールは**アンロードしない**。再起動の後も、明示的に、またはほかのモジュールの依存として読み込まれうる。`blacklist` が止めるのはエイリアスによる自動読み込みだけである。
- **audit** は、起動時のファイルの違いを `persistent`、ブラックリストのファイルの違いを `blacklist`、読み込まれていないモジュール（`present` かつ `runtime` のとき）を `loaded` として報告する。観測の失敗はすべてエラーであり、ドリフトにはしない。audit は `modprobe` を実行しない。

## Sinter がしないこと

- モジュールをアンロードしない（どの状態でも `modprobe -r` は実行しない）。使用中のモジュールのアンロードと依存関係の扱いには、別の設計が必要である。
- `/etc/modules-load.d`、`/usr/lib/modules-load.d`、`/etc/modprobe.d` のほかのファイルは評価しない。ほかの場所の `blacklist` や `install` の行によって、起動時の動作が変わりうる。再起動後の状態は検証しない。
- モジュールのパラメータは設定せず、カーネルコマンドライン（`modprobe.blacklist=`、`module.param=`）にも触れない。それは今後の `kernel_args` タイプの範囲である。
- モジュールのパッケージはインストールせず、initramfs も作り直さない。

## 権限

ファイルの書き込みとモジュールの読み込みには root が必要である。root で接続するか `--sudo` を使う。接続が root でない場合、plan はそのことを注記する。

## 機密リソース

モジュール名は機密として扱わない。`sysctl` の名前やファイルのパスと同じく、注記とコマンドの記録に現れる。ファイルの差分は `file` リソースの伏せ字の規則に従う。

## 対応していないもの

- `/sys/module` がないホスト（sysfs がない）と、読み込みが必要なのに `/usr/sbin/modprobe` がないホスト（「kernel_module is not supported on this host」）。
- `/sys/module` に現れない組み込みモジュール（パラメータのないもの）。`modprobe` は成功するがモジュールが観測できないので、リソースは失敗する。こうしたモジュールには `persist` だけ（`runtime: false`）を使う。

## 対応 OS

Ubuntu 24.04 と 26.04、Rocky Linux、RHEL、AlmaLinux の 9 と 10。

このリソースは Sinter のスクリプト化したターゲットでのみテストしている。Rocky Linux 10.2 を読み取り専用で調べたところ、`/etc/modules-load.d` は空で、`/sys/module/loop` はあり、未知のモジュールの `/sys/module/<名前>` はなかった。`modprobe -n -v` は、利用できるモジュールでは終了コード 0 と `insmod …` の行を返し、未知のモジュールでは終了コード 1 と `FATAL: Module … not found` を返した。**実ホストでは検証していないもの:** `modprobe -n` がどの OS でも何も変えないこと。読み込みそのものとその終了コード。各 OS とカーネルで組み込みモジュールが `/sys/module` にどう現れるか。起動時に systemd-modules-load と modprobe が Sinter のファイルを読むこと。Ubuntu、EL 9、RHEL、AlmaLinux のすべて。
