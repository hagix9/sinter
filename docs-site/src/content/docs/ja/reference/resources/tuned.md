---
title: tuned
description: ホストの TuneD プロファイルを tuned-adm で選択する。
---

**目的:** ホストでどの TuneD プロファイルを選択するか（`tuned-adm profile`）、またはプロファイルを選択しないこと（`tuned-adm off`）を宣言する。

## 書式

```yaml
- id: profile
  type: tuned
  with:
    profile: throughput-performance
```

```toml
[[resources]]
id = "profile"
type = "tuned"

[resources.with]
profile = "throughput-performance"
```

## パラメータ

| パラメータ | 必須 | 型 | デフォルト | 説明 |
|-----------|------|-----|-----------|------|
| `profile` | 3 つのうち 1 つ | string | — | 選択するプロファイル。`[A-Za-z0-9][A-Za-z0-9_.-]{0,63}`。 |
| `recommended` | 3 つのうち 1 つ | boolean（リテラル） | `false` | `true`: `tuned-adm recommend` がこのホストに勧めるプロファイルを選択する。 |
| `state` | 3 つのうち 1 つ | `active` または `off`（リテラル） | `active` | `off`: プロファイルを選択しない。 |
| `verify` | いいえ | boolean（リテラル） | `false` | `true`: 選択したプロファイルが適用されていることも `tuned-adm verify` で確認する（apply では変更の後、および audit）。 |

- `profile`、`recommended: true`、`state: off` のうち、**ちょうど 1 つ**を書く。どれも書かない場合と、2 つ以上書いた場合は検証エラーになる。
- `profile` には変数を使える。ファクト、register、機密値は使えない。レシピの読み込み時に解決して検査する。`recommended`、`state`、`verify` はリテラルで書く。
- `state: off` と `verify: true` の組み合わせは検証エラーになる。確認する対象がないためである。
- 1 つのレシピに `tuned` は 1 つだけ。2 つ目は検証エラーになる。

## 「選択」と「適用」は別のもの

TuneD は選択したプロファイルの名前を `/etc/tuned/active_profile` に保存する。このファイルが示すのは、どのプロファイルが**選択**されているかである。プロファイルの設定が**適用**されるのは、`tuned.service` が動いている間だけである。Sinter はこの 2 つを分けて報告する。

- plan、apply、audit が宣言と比べるのは「選択」である。
- プロファイルが選択されていても `tuned.service` が active でない場合、変更なしの結果に注記を付ける。audit は `service` の差分として報告する。
- 設定が実際に有効かどうかは、`verify: true` で求めたときだけ確認する。

## 例

TuneD がこのホストに勧めるプロファイルを選択する。

```yaml
- id: profile
  type: tuned
  with:
    recommended: true
```

```toml
[[resources]]
id = "profile"
type = "tuned"

[resources.with]
recommended = true
```

チューニングを無効にする（プロファイルを選択しない）。

```yaml
- id: profile
  type: tuned
  with:
    state: off
```

```toml
[[resources]]
id = "profile"
type = "tuned"

[resources.with]
state = "off"
```

プロファイルを選択し、適用されていることを確認する。

```yaml
- id: profile
  type: tuned
  with:
    profile: throughput-performance
    verify: true
```

```toml
[[resources]]
id = "profile"
type = "tuned"

[resources.with]
profile = "throughput-performance"
verify = true
```

### 全体の順序: パッケージ、サービス、独自プロファイル、選択

Sinter は TuneD をインストールしない。起動もしない。この 2 つと、必要なら独自プロファイルを、`tuned` リソースより前に宣言する。

```yaml
version: 1
resources:
  - id: tuned-package
    type: package
    with:
      name: tuned
      state: present

  - id: tuned-service
    type: service
    depends_on: [tuned-package]
    with:
      name: tuned.service
      state: running
      enabled: true

  - id: site-db-dir
    type: directory
    depends_on: [tuned-package]
    with:
      path: /etc/tuned/profiles/site-db
      parents: true

  - id: site-db-conf
    type: file
    depends_on: [site-db-dir]
    with:
      path: /etc/tuned/profiles/site-db/tuned.conf
      content: |
        [main]
        include=throughput-performance

  - id: profile
    type: tuned
    depends_on: [tuned-service, site-db-conf]
    with:
      profile: site-db
```

```toml
version = 1

[[resources]]
id = "tuned-package"
type = "package"

[resources.with]
name = "tuned"
state = "present"

[[resources]]
id = "tuned-service"
type = "service"
depends_on = ["tuned-package"]

[resources.with]
name = "tuned.service"
state = "running"
enabled = true

[[resources]]
id = "site-db-dir"
type = "directory"
depends_on = ["tuned-package"]

[resources.with]
path = "/etc/tuned/profiles/site-db"
parents = true

[[resources]]
id = "site-db-conf"
type = "file"
depends_on = ["site-db-dir"]

[resources.with]
path = "/etc/tuned/profiles/site-db/tuned.conf"
content = "[main]\ninclude=throughput-performance\n"

[[resources]]
id = "profile"
type = "tuned"
depends_on = ["tuned-service", "site-db-conf"]

[resources.with]
profile = "site-db"
```

- 古い TuneD は、独自プロファイルを `/etc/tuned/profiles/<name>/` ではなく `/etc/tuned/<name>/` に置く。Sinter は両方を探す。ファイルは、使っている TuneD が読む場所に書く。
- TuneD がまだインストールされていないホストでも、このレシピの plan は失敗しない。前のパッケージがツールを入れる可能性があるため、`tuned` リソースは「apply まで不明」と表示される。
- **バンドル:** レシピをまたぐ場合も同じ順序にする。パッケージをインストールしてサービスを起動するレシピを、`tuned` リソースを持つレシピより前に置く。後ろのレシピの plan は、同じように判断を apply に延ばす。

## 動作

- **観測（読み取りのみ）。**
  - `/usr/sbin/tuned-adm` が実行可能なら、TuneD はインストールされているとみなす。
  - 選択されているプロファイルは `/etc/tuned/active_profile` から読む。ファイルがない、または空の場合は「プロファイルは選択されていない」とみなす。プロファイル名 1 つだけの 1 行なら、そのプロファイルである。それ以外はエラーになる。Sinter は推測しない。シンボリックリンクはたどらない。
  - `tuned.service` は、`service` リソースがユニットを観測するのと同じ方法で観測する。
  - `recommended: true` の場合、`/usr/sbin/tuned-adm recommend` を実行する。終了コードが 0 で、プロファイル名 1 つだけの 1 行の場合だけ受け入れる。
- **plan** は選択を宣言と比べる。異なる場合は、プロファイルが存在することと `tuned.service` が active であることを確認し、現在の選択と宣言した選択を表示する。ほかには何も実行しない。plan は `tuned-adm verify` を実行しない。
- **プロファイルが存在する**とは、`/etc/tuned/profiles`、`/etc/tuned`、`/usr/lib/tuned/profiles`、`/usr/lib/tuned` のいずれかで `<dir>/<name>/tuned.conf` が通常ファイルであることをいう。存在しない場合、plan は失敗し、プロファイル名と 4 つのディレクトリを示す。plan の中の前のリソースがこれから作る可能性がある場合は、失敗ではなく注記を付け、apply がもう一度確認する。
- **apply** は root で `/usr/sbin/tuned-adm profile <name>` または `/usr/sbin/tuned-adm off` をシェルを使わずに実行する。コマンドの直前に状態ファイルをもう一度読む。その間に選択が変わっていたら、何も実行しない。終了コードが 0 以外なら失敗である。終了コード 0 だけでは成功としない。状態ファイルをもう一度読み、宣言した選択になっていなければリソースは失敗になる。ツールが強制終了された、タイムアウトした、接続が切れた場合は、選択が変わったかどうか分からないと報告する。成功とは報告しない。
- **選択がすでに宣言どおりなら、コマンドは何も実行しない。** サービスが停止していても同じである。その場合は結果に注記を付ける。プロファイルは選択されているが、サービスが停止している間は適用されない、という内容である。
- **`verify: true`。** 変更が成功した後、apply は `/usr/sbin/tuned-adm verify` を実行する。終了コード 0 は「適用されている」を表す。終了コード 1 は、システムがプロファイルと異なることを表す。このときリソースは**失敗になり、変更があったことも報告する**（選択は変わったが、チューニングは確認できなかった）。それ以外の終了コード、シグナル、タイムアウト、出力の切り捨ても失敗になり、プロファイルが適用されているかどうか分からないと報告する。verify は plan では実行しない。選択に変更がない場合も実行しない。`tuned-adm verify` に副作用がないかどうかを実測していないためである。verify を明示的に指定する項目にしているのも同じ理由による。
- **audit** は最大 3 つの項目を報告する。
  - `profile`: 選択が宣言と異なる（`recommended: true` の場合は、audit の中で観測した推奨プロファイルと異なる）。
  - `service`: プロファイルを宣言しているのに `tuned.service` が active でない（またはユニットが見つからない）。選択したプロファイルは適用されていない。
  - `applied`（`verify: true` のときだけ。上の 2 つに問題がない場合に限る）: `tuned-adm verify` が終了コード 1 で終わった。

  `tuned-adm` がないホスト、読めない状態ファイルや形式が違う状態ファイル、コマンドの失敗はエラーであり、ドリフトにはしない。

プロファイルを選択する plan と apply の結果には、必ず次の注記が付く。TuneD のプロファイルはカーネルパラメータなどの設定値を変更する。[`sysctl`](/ja/reference/resources/sysctl/) リソースや `/etc/sysctl.d` のファイルで設定した値は、プロファイルに上書きされることがある。逆もある（順序は TuneD の `reapply_sysctl` 設定で決まる）。Sinter はこれを調整しない。1 つの設定は 1 か所で宣言する。

## Sinter が選択を変更できない場合

4 つの場合で、メッセージが異なる。

| 場合 | Sinter のメッセージ |
|------|--------------------|
| TuneD がインストールされていない（`tuned-adm` がない） | "tuned is not supported on this host (tuned-adm was not found); install it with a package resource" |
| `tuned-adm` はあるが、ユニット `tuned.service` がない | "tuned-adm is installed but the unit tuned.service was not found …" |
| ユニットはあるが active でない | "TuneD is installed but its service is not running (tuned.service is inactive); start it with a service resource (Sinter does not start it)" |
| プロファイルが存在しない | "the profile NAME is not defined on this host (no NAME/tuned.conf in …)" |

plan では次のように扱う。1 つ目は、前のリソース（たとえばパッケージ）がツールを入れる可能性があれば、判断を apply に延ばす。2 つ目と 3 つ目は、`service` などの前のリソースが TuneD を起動する可能性があれば注記になる。4 つ目は、前のリソースがプロファイルを作る可能性があれば注記になる。

## Sinter がしないこと

- `tuned` パッケージはインストールしない。[`package`](/ja/reference/resources/package/) を使う。
- `tuned.service` の起動、再起動、有効化、停止はしない。[`service`](/ja/reference/resources/service/) を使う。
- プロファイルは書かない。[`file`](/ja/reference/resources/file/) または [`template`](/ja/reference/resources/template/) を使う。
- `tuned.service` が active であると観測できない限り、何も変更しない。
- `/etc/tuned/tuned-main.conf` と TuneD の自動プロファイルモードは、読みも変更もしない。プロファイルと `sysctl` の設定の衝突も調整しない。
- 複数のプロファイルを同時に選択すること（TuneD のプロファイルのマージ）はしない。状態ファイルに複数のプロファイルが書かれているホストは、観測エラーとして報告する。

## 権限

選択の変更には root が必要である。root で接続するか `--sudo` を使う。接続が root でない場合、plan はそのことを注記する。変更するものがない実行に root は要らない。

## 対応していないもの

- `/usr/sbin/tuned-adm` がないホスト: plan と apply は上のメッセージで失敗し、audit はエラーを報告する。
- 複数のプロファイルの同時選択。
- `[A-Za-z0-9][A-Za-z0-9_.-]{0,63}` に合わないプロファイル名。
- MCP からの利用: `tuned` は MCP のマニフェストでは拒否される。

## 対応 OS

RHEL、Rocky Linux、AlmaLinux の 9 と 10。Ubuntu 24.04 と 26.04 は、`tuned` パッケージがインストールされている場合に対応する。この型は OS の名前ではなく、`tuned-adm` があるかどうかで判断する。

## 制限

- 前のリソースが TuneD を起動する、またはプロファイルを書く可能性があるため `plan` で判断できない場合、結果は apply で判定（unknown）と報告する。
- Sinter は `tuned-adm` を実行する直前に `tuned.service` が動作中であることを確認する。そのわずかな間にサービスが止まると、TuneD のツール自身が起動を試みることがある。Sinter 自身は起動しない。
- 状態ファイル `/etc/tuned/active_profile` にハードリンクが複数あると拒否する。
- 1 つのレシピに `tuned` は 1 つだけ。バンドルの 2 つのレシピが同じホストに別のプロファイルを選んでも検出しない。apply のたびに切り替わる。

## 実ホストで検証していないこと

このリソースは Sinter のスクリプト化したテスト用ターゲットでのみ試験している。TuneD が入ったホストを使えなかったため、**次のどれも検証していない**。

- TuneD が選択したプロファイルを `/etc/tuned/active_profile` に「名前 1 つの 1 行」で書くこと。`tuned-adm off` の後にこのファイルが空になる（またはなくなる）こと。
- 対応するすべての OS で、パスが `/usr/sbin/tuned-adm` であること。
- TuneD の各リリースでの 4 つのプロファイルディレクトリと、ファイル名 `tuned.conf`。
- `tuned-adm recommend` の出力（プロファイル名だけの 1 行と仮定している）。サービスが停止している間も動くかどうか。
- `tuned-adm verify` の終了コード（0 は適用済み、1 は未適用と仮定している）。ホストの何かを変更するのか、TuneD のログに書くだけなのか。
- `tuned-adm profile` と `tuned-adm off` の終了コードと所要時間（Sinter は 300 秒まで待つ）。
- `tuned-adm profile` が TuneD を手動プロファイルモードに切り替えること。
- Ubuntu でのユニット名 `tuned.service`。
