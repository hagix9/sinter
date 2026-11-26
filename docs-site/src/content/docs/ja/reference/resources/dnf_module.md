---
title: dnf_module
description: DNF モジュールのストリームを有効にする、モジュールを無効にする、またはディストリビューションの既定に戻す。
---

**目的:** DNF 4 のホストで、1 つの DNF モジュールの状態を宣言する。あるストリームで有効、無効、またはディストリビューションの既定に戻した状態のいずれか。この状態によって、後の [`package`](/ja/reference/resources/package/) リソースが解決するパッケージが決まる。

## 書式

```yaml
- id: nodejs-stream
  type: dnf_module
  with:
    name: nodejs
    stream: "20"
    state: enabled
```

```toml
[[resources]]
id = "nodejs-stream"
type = "dnf_module"

[resources.with]
name = "nodejs"
stream = "20"
state = "enabled"
```

## パラメータ

| パラメータ | 必須 | 型 | デフォルト | 説明 |
|-----------|------|-----|-----------|------|
| `name` | はい | string | — | モジュール名。`[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}`。 |
| `stream` | `state: enabled` のとき | string | — | ストリーム名。使える文字は `name` と同じ。`state` が `enabled` のときは必須で、それ以外では指定できない。YAML では引用符で囲む（`"20"`）。数値のままでは拒否される。 |
| `state` | はい | string | — | `enabled`、`disabled`、`reset` のいずれか。 |
| `env` | いいえ | 文字列の map | — | `dnf module` コマンドだけに渡す環境変数（プロキシなど）。`package` と同じく、レシピ全体の `env` が土台になる。 |

- `name`、`stream`、`state` には変数を使えますが、fact、register、sensitive な値は使えません。レシピを読み込むときに解決して検査します。
- 1 つのレシピで、同じモジュール名の `dnf_module` は 1 つだけです。2 つ目は検証のエラーです。
- モジュールのプロファイルを指定するフィールドはありません。プロファイルのパッケージを入れる・消すのはパッケージのトランザクションです。必要なパッケージは [`package`](/ja/reference/resources/package/) リソースで宣言してください。

## 期待される動作

- **観測。** Sinter は、DNF 自身がモジュールについて記録しているファイル `/etc/dnf/modules.d/<name>.module` を読みます。`dnf` は実行せず、シンボリックリンクはたどりません。ファイルが無ければ、モジュールは既定の状態です。ファイルは DNF が書く形そのものでなければなりません。セクション `[<name>]` が 1 つで、キーは `name`、`stream`、`profiles`、`state` です。それ以外（別のセクション、知らないキーや重複したキー、コメント、CRLF の改行、`enabled`・`disabled`・空以外の `state`）は、plan、apply、audit のどれでもエラーです。Sinter は状態を推測しません。
- **比較。** `enabled` は、記録された状態が `enabled` で、ストリームが宣言と同じときに満たされます。`disabled` は記録が `disabled` のとき、`reset` はファイルが無いか記録された状態が空のときに満たされます。
- **plan** は変更を報告します（`state=default` → `state=enabled stream=20`）。リポジトリのメタデータは読まないので、有効なリポジトリに `<name>:<stream>` があるかどうかは分かりません。apply のときに dnf が確かめる、という注記を付けます。
- **apply** は、決まったコマンドを 1 つ、root で、シェルを使わずに実行します。`/usr/bin/dnf -y module enable <name>:<stream>`、`/usr/bin/dnf -y module disable <name>`、`/usr/bin/dnf -y module reset <name>` のいずれかです。終了コードが 0 以外なら失敗です。終了コード 0 だけでは成功としません。状態ファイルをもう一度読み、宣言どおりの状態でなければリソースは失敗します。dnf が kill された、タイムアウトした、接続が切れた場合、結果には「モジュールの状態は変わったかもしれないし、変わっていないかもしれない」と書きます。成功とは報告せず、そのリソースについてそれ以上のコマンドは送りません。
- 失敗したとき、dnf 自身の出力は結果に写しません（認証情報を含むリポジトリ URL が入ることがあるため）。理由には終了コードを書き、ホストで `dnf module list <name>` を実行するよう案内します。
- このコマンドのために、dnf がネットワーク経由でリポジトリのメタデータを更新することがあります。`env` のプロキシが使われます。
- 変更は、他のリソースと同じように handler に通知されます。2 回目の apply は何も変えず、dnf も実行しません。
- **audit** は、記録された状態と宣言を比べ、`state` や `stream` の違いを drift として報告します。読めない状態ファイル、想定外の内容、シンボリックリンク、対応していないホストはエラーで、drift にはしません。audit は dnf のコマンドを実行しません。

## Sinter が拒否すること

次のどれも、ホストを変えるコマンドを実行する前に、plan と apply を止めます。

- **ストリームの切り替え。** モジュールが別のストリームで有効になっている場合、Sinter は切り替えません。今のストリームから入れたパッケージを確認し、モジュールを明示的に reset してから（`state: reset` の `dnf_module` を、先の実行で）、新しいストリームを有効にしてください。上書きのオプションはありません。
- **インストール済みのプロファイル。** 状態ファイルにインストール済みのプロファイルがある場合、`disabled` と `reset` は拒否します。そのパッケージをどうするかは、パッケージについての判断だからです。
- **DNF 4 ではないホスト。** Debian と Ubuntu では「dnf_module is not supported on this host」となります。DNF 5（`/usr/bin/dnf` が `dnf5` へのリンク）は、このリリースでは対応していません。`/usr/bin/dnf` が DNF 4 のプログラム（`dnf-3`）へのシンボリックリンクでない場合も、正体の分からない dnf は実行せずに止まります。この確認は [`dnf_repository`](/ja/reference/resources/dnf_repository/) と共通です。
- **途中で変わった状態。** apply は、dnf を実行する直前に状態ファイルをもう一度読みます。判断のもとにした内容と違っていれば、何も変えずにリソースは失敗します。もう一度実行してください。
- **root ではない。** モジュールの変更には root が必要です（root で接続するか `--sudo` を使う）。plan は注記を付け、apply は dnf を実行する前に失敗します。
- MCP では使えません。この観測は、まだ実機で測定していないためです。

## 対応しているシステム

- Rocky Linux、RHEL、AlmaLinux 9 の DNF 4。
- EL 10 のディストリビューションは、リポジトリにモジュールストリームを持ちません。Sinter は OS のバージョンで特別扱いしません。EL 10 で `state: enabled` を指定すると、dnf がそのモジュールを見つけられず、apply で失敗します。これは対応している使い方ではありません。状態ファイルの無いモジュールの `disabled` と `reset` は、変更なしと報告します。
- Debian、Ubuntu、DNF 5 のホストは、上のとおり拒否します。

## まだ実機で確認していないこと

上の動作は、スクリプトで動く擬似的な対象でテストしています。次のことは、実際の Rocky Linux、RHEL、AlmaLinux のホストでまだ測定していません。

- `dnf module enable`、`disable`、`reset` の後の `/etc/dnf/modules.d/<name>.module` の正確な内容（特に、`reset` が空の `state=` を持つファイルを残すのか、ファイルを消すのか。どちらも受け付けます）。また、DNF 4 のどれかのバージョンが他のキーを書くかどうか。
- サポート対象のすべてのリリースで、`/usr/bin/dnf` が `dnf-3` へのシンボリックリンクであること。
- モジュールやストリームが無い場合と、EL 10 のモジュールに対する、`dnf module` の終了コードとメッセージ。
- 1 回の実行での順序: ストリームを有効にし、そこからパッケージを入れること。

## 例

ストリームを有効にして、そこからパッケージを入れる:

```yaml
version: 1
resources:
  - id: nodejs-stream
    type: dnf_module
    with:
      name: nodejs
      stream: "20"
      state: enabled
  - id: nodejs
    type: package
    depends_on: [nodejs-stream]
    with:
      name: nodejs
      state: present
```

```toml
version = 1

[[resources]]
id = "nodejs-stream"
type = "dnf_module"

[resources.with]
name = "nodejs"
stream = "20"
state = "enabled"

[[resources]]
id = "nodejs"
type = "package"
depends_on = ["nodejs-stream"]

[resources.with]
name = "nodejs"
state = "present"
```

モジュールをディストリビューションの既定に戻す（たとえば、後の実行で別のストリームを選ぶ前に）:

```yaml
- id: nodejs-reset
  type: dnf_module
  with:
    name: nodejs
    state: reset
```
