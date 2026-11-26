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

Sinter は `/etc/sysctl.conf` もほかのファイルも編集しない。`sysctl --system` も実行しない。つまり、ほかの設定を適用し直すことはない。

## 起動時にどのファイルが優先されるか

起動時、`systemd-sysctl` は `/usr/lib/sysctl.d`、`/usr/local/lib/sysctl.d`、`/run/sysctl.d`、`/etc/sysctl.d` にある `*.conf` をファイル名の順に並べ、その順に適用する。2 つのファイルが同じキーを設定すると、**最後に**適用されたファイルが優先される。1 つのファイルの中では、最後の行が優先される。たとえば Rocky Linux 10.2 では `/etc/sysctl.d/99-sysctl.conf` が `/etc/sysctl.conf` へのリンクで、`90-sinter-<name>.conf` より後に並ぶ。そのため `/etc/sysctl.conf` の値が Sinter の値より優先される。

永続ファイルを管理するとき、Sinter はこの順序を `/usr/bin/systemd-analyze cat-config sysctl.d`（ファイルを表示するだけのコマンド）で読む。

- **plan と apply** は、Sinter のファイルより後に適用されるファイルが同じキーを設定していれば、注記を付ける。例: 「/etc/sysctl.d/99-sysctl.conf also sets vm.swappiness and is applied after Sinter's file: at boot its value wins, so after a reboot the value will be "30", not the declared "10"」。順序の後ろにあり、キーに一致するパターン設定（`net.ipv4.conf.*.rp_filter` など）も名前を示す。これは注記であり、失敗にはしない。そのファイルを管理しているのはあなたかもしれないからである。
- **audit** は、これらのファイルが与える値が宣言した値と異なれば、次元 `boot` を報告する（observed: `30 (from /etc/sysctl.d/99-sysctl.conf)`）。再起動するとホストは宣言した値にならないので、このリソースは準拠とはならない。後のファイルが同じ値を設定している場合は、注記付きで準拠になる。Sinter のファイルより前に適用されるファイルは関係しない。
- `state: absent` では、Sinter のファイルを消した後も起動時にそのキーを設定するファイルを注記で示す。
- `systemd-analyze` がない、失敗した、Sinter が読めない出力を返した場合は、ほかのファイルを**調べていない**。リソースはこれまでどおり動き、そのことを注記で示す（audit では `boot: not examined`）。それを理由にドリフトやエラーにはしない。後のファイルにキーを含む読めない行がある場合や、後のパターン設定が別の値を与える場合も同じである。
- その出力では、各ファイルが `# <path>` という行で始まる。ファイルの中のコメントが、この行とまったく同じ形になることがある。systemd-sysctl は各ファイル名を 1 回だけ、ファイル名の順に適用するので、これらの行が同じファイルを 2 回示す、その順に並んでいない、または名前が `.conf` で終わらないファイルを示す場合、Sinter は出力を読めないものとして扱う（**調べていない**）。順序をたまたま保っている同じ形のコメントは、各ファイルを読まない限り本物の見出し行と区別できない。sysctl.d のパス 1 つだけから成るコメントは避けること。

宣言した値を起動時に優先させるには、そのファイルからほかの設定を消すか、`sysctl` リソースではなくそのファイルで値を宣言する。Sinter がほかのファイルを編集することはない。

**TuneD。** TuneD のプロファイルが選択されている場合（`/etc/tuned/active_profile` が空でない場合）、plan、apply、audit は注記を付ける。TuneD は起動時のファイルの後でカーネルパラメータを設定することがある（`reapply_sysctl` オプションによる）。Sinter はプロファイルの内容を読まない。各パラメータは 1 か所で宣言すること。

実際に再起動した後の値は、このリソースでは**検証していない**。次元 `boot` は設定ファイルが示す値である。

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
- **audit** は、ファイルの違いを `persistent`（`file` の audit が報告する内容、所有者、グループ、モード、有無）として、現在の値の違いを `runtime` として、起動時の値の違いを `boot`（上記）として報告する。いずれも、リソースが管理している場合だけ調べる。未知のパラメータと観測の失敗はエラーであり、ドリフトではない。

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
- Sinter は `sysctl --system` を実行せず、自分の値を優先させるためにほかのファイルを編集しない。起動時にパターン設定と明示的な設定のどちらが優先されるかは判定しない。TuneD のプロファイルの内容も評価しない。
- plan が読むのはホストに今あるファイルであり、同じ plan の前のリソースが作るファイルは含まない。
- リソースに `sensitive: true` を付けると、plan、apply、audit の出力に値を出さない。パラメータ名とファイルのパスは表示される。

## 対応 OS

Ubuntu 24.04 と 26.04、Rocky Linux、RHEL、AlmaLinux の 9 と 10。

このリソースは Sinter のスクリプト化したテスト用ターゲットでのみ試験している。**実ホストでは検証していない**。対象は、`sysctl -n` と `sysctl -w` の出力と終了コード、書き込んだ値をカーネルがどう保持するか、起動時に何が読み込まれるかである。`systemd-analyze cat-config sysctl.d` の出力は Rocky Linux 10.2 でだけ測定した。EL 9 と Ubuntu での形式、`/etc/sysctl.conf` がすべての OS で起動時の順序に含まれるかどうかは検証していない。再起動後の値は、再起動テストでしか確かめられない。
