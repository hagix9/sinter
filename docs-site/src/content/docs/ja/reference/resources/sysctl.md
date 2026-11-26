---
title: sysctl
description: カーネルパラメータ 1 つを、現在の値と専用ファイルによる永続設定として設定する。
---

**目的:** カーネルパラメータ（`sysctl`）を 1 つ宣言する。稼働中のカーネルが今使っている値と、起動時に読み込まれる永続設定の両方を扱う。

## 書式

```yaml
- id: swappiness
  type: sysctl
  with:
    name: vm.swappiness
    value: 10
```

```toml
[[resources]]
id = "swappiness"
type = "sysctl"

[resources.with]
name = "vm.swappiness"
value = 10
```

複数の値を持つパラメータは 1 つの文字列で書く。

```yaml
- id: tcp-rmem
  type: sysctl
  with:
    name: net.ipv4.tcp_rmem
    value: "4096 131072 6291456"
```

```toml
[[resources]]
id = "tcp-rmem"
type = "sysctl"

[resources.with]
name = "net.ipv4.tcp_rmem"
value = "4096 131072 6291456"
```

## パラメータ

| パラメータ | 必須 | 型 | デフォルト | 説明 |
|-----------|------|-----|-----------|------|
| `name` | はい | string | — | ドット区切りのパラメータ名。`[a-z0-9_]+(\.[A-Za-z0-9_-]+)+`、128 バイトまで。`/` と `*` は使えない。 |
| `value` | `present` のとき | string または integer | — | 印字可能な ASCII の 1 行。1024 バイトまで。空は不可。`{{` を含められない。 |
| `state` | いいえ | string | `present` | `present` または `absent`。そのまま書く。 |
| `runtime` | いいえ | boolean | `true` | 現在の値を管理する。`true` か `false` をそのまま書く。 |
| `persist` | いいえ | boolean | `true` | 永続設定のファイルを管理する。`true` か `false` をそのまま書く。 |

- `name` には変数を使える。ファクト、register、機密値は使えない。レシピの読み込み時に解決して検査する。
- `value` は、前後の空白を除き、連続する空白とタブを 1 つの空白にまとめてから比較する。そのため `4096 131072 6291456` は、カーネルが表示するタブ区切りの形と等しい。ファイルと変更コマンドにもこの形を使う。
- `state`、`runtime`、`persist` に変数は使えない。
- `runtime` と `persist` の少なくとも一方は `true` でなければならない。
- `state: absent` のとき、`value`、`runtime`、`persist` は指定できない。
- 1 つのレシピで、1 つのパラメータに対する `sysctl` は 1 つだけ。同じ `name` の 2 つ目は検証エラーになる。

## 永続設定

Sinter はパラメータごとにファイルを 1 つ、丸ごと所有する。

```
/etc/sysctl.d/90-sinter-<name>.conf
```

内容は次のとおりで、これ以外は書かない。

```
# Managed by Sinter (sysctl). Local changes are replaced.
<name> = <value>
```

所有者は `root:root`、モードは `0644`。このファイルは [`file`](/ja/reference/resources/file/) リソースと同じ方法で書く。つまり、親ディレクトリを同じように検査し、アトミックに置き換え、plan では差分を表示する。同じレシピで同じパスを `file`、`template`、`file_merge` が扱うと検証エラーになる。

Sinter は `/etc/sysctl.conf` もほかのファイルも編集しない。`/etc/sysctl.d` の中で後に並ぶファイルや `/etc/sysctl.conf` が、起動時に別の値を設定することがある。Sinter はその順序を評価しない。再起動後の値は、このリソースでは**検証していない**。

## 動作

- **現在の値の観測。** Sinter は `/usr/sbin/sysctl -n -- <name>` を実行する（読み取りのみ）。終了コードが 0 で、標準出力がちょうど 1 行、標準エラーが空の場合だけ受け入れる。0 以外の終了コードは「unknown kernel parameter」として報告し、リソースを止める。「存在しない」とも「差分」とも扱わない。出力の切り捨て、2 行目、シグナル、タイムアウトはエラーになる。
- **plan** はファイルの差分を表示し、現在の値は注記で示す（`"60" -> "10"`）。観測以外は何も実行しない。
- **apply** は次の順で動く。
  1. 現在の値を観測する（未知のパラメータは、何かを書く前に拒否する）。
  2. `persist` が `true` で内容が異なれば、ファイルを書く。
  3. `runtime` が `true` で現在の値が異なれば、root で `/usr/sbin/sysctl -w -- <name>=<value>` をシェルを使わずに実行し、もう一度観測する。

  変更が成功するのは、`sysctl -w` が 0 で終了し、**かつ**その後に観測した値が `value` と等しい場合だけである。それ以外は失敗になる。ファイルをすでに書いていた場合、失敗の結果にもその変更が報告される。ファイルを書けなかった場合、現在の値には触れない。`sysctl -w` が強制終了された、タイムアウトした、接続が切れた場合は、現在の値が変わったかどうか分からないと報告する。成功とは報告しない。
- 2 回目の apply は何も変更しない。ファイルを書き直さず、`sysctl -w` も実行しない。
- `runtime: false` のとき、Sinter は `sysctl` を一切実行しない。ファイルだけを管理し、パラメータが稼働中のカーネルにあるかどうかも確認しない。設定は次の起動時、または `sysctl --system` を実行したときに有効になる。
- `persist: false` のとき、現在の値だけを管理する。以前に Sinter が書いたファイルはそのまま残る。削除するには `state: absent` を使う。
- **`state: absent`** は Sinter のファイルだけを削除する。現在の値は**元に戻さない**。戻すべき「以前の値」が存在しないためである。現在の値は、再起動するか別の変更があるまでそのまま残る。`sysctl` は実行しない。
- **audit** は、ファイルの違いを `persistent`（`file` の audit が報告する内容、所有者、グループ、モード、有無）として、現在の値の違いを `runtime` として報告する。どちらも、リソースが管理している場合だけ調べる。未知のパラメータと観測の失敗はエラーであり、ドリフトではない。

変更があれば、ほかのリソースと同じようにハンドラへ通知する。Sinter は何も再起動しない。

## 権限

カーネルパラメータの変更と `/etc/sysctl.d` への書き込みには root が必要である。root で接続するか `--sudo` を使う。接続が root でない場合、plan はそのことを注記する。変更するものがない実行に root は要らない。

## 制限と対応していないもの

- `/usr/sbin/sysctl` がないホスト: `runtime: true` の場合、plan と apply は「sysctl cannot manage the running value on this host (/usr/sbin/sysctl was not found)」で失敗し、audit はエラーを報告する。
- `/`（別の区切り文字）や `*`（パターン）を含む名前、ドットを含むインターフェース名は宣言できない。
- 値はカーネルが表示する形で書く必要がある。書き込んだ値をカーネルが丸める、範囲内に収める、またはパラメータが読み取り専用の場合、リソースは `sysctl -w` の後で失敗し、以後の実行も同じように失敗する。
- 2 行以上を表示するパラメータは管理できない。
- 空の値は宣言できない。
- カーネルモジュールを読み込んだ後にだけ現れるパラメータは、モジュールが読み込まれていない間は「unknown kernel parameter」になる。ファイルだけを管理するには `runtime: false` を使う。
- Sinter は起動時にどのファイルが優先されるかを評価しない。`sysctl --system` も実行しない。
- リソースに `sensitive: true` を付けると、plan、apply、audit の出力に値を出さない。パラメータ名とファイルのパスは表示される。

## 対応 OS

Ubuntu 24.04 と 26.04、Rocky Linux、RHEL、AlmaLinux の 9 と 10。

このリソースは Sinter のスクリプト化したテスト用ターゲットでのみ試験している。**実ホストでは検証していない**。対象は、`sysctl -n` と `sysctl -w` の出力と終了コード、書き込んだ値をカーネルがどう保持するか、起動時に何が読み込まれるかである。
