---
title: Resource Plugins
description: データのみの Resource Plugins、プラグインルート、sinter plugin コマンド、公式 firewalld プラグイン。
---

*v1.9.0 から利用できます。`sinter plugin` コマンド、firewalld 0.2.0、mutate の部分許可は v1.12.0 からです。*

Resource Plugin は、`<plugin>.<name>` という名前のリソースタイプをデータとして追加します。
プラグインのコードが Sinter の中で動くことはありません。プラグインが実行できるプログラムは
すべて capability catalog から来ます。catalog には、固定のプログラム、オペランドを検査する
引数テンプレート、各終了ステータスの意味が記載されています。

Sinter v1.12.0 は、公式プラグインを 2 つ（それぞれの catalog とともに）持っています。

| プラグイン | リソースタイプ | リリース |
|------------|----------------|----------|
| `firewalld` 0.1.0 | `firewalld.service`（present のみ） | v1.9.0 以降 |
| `firewalld` 0.2.0 | `firewalld.service`、`firewalld.port`、`firewalld.port_range`、`firewalld.protocol` | v1.12.0 以降 |

他者の catalog には対応していません。catalog は、この Sinter に組み込まれたレビュー済みの
公式 catalog である場合にだけ使われ、それ以外は pin してあっても拒否されます。v1.12.0 より前の
リリースは firewalld 0.2.0 を拒否します。

`plugins:` のないレシピの動作はこれまでと同じで、プラグインルートは読みません。

## プラグインルート

プラグインルートは、コントローラー上のディレクトリです。

```text
<plugin-root>/
  trust.toml                              (mode 0600)
  catalogs/firewalld-0.2.0.catalog.toml
  plugins/firewalld-0.2.0.plugin.toml
```

`validate`、`plan`、`apply`、`audit` と `sinter plugin` の各コマンドで `--plugin-root DIR` として
指定します。省略時は `$XDG_CONFIG_HOME/sinter/plugins`、なければ `~/.config/sinter/plugins` です。
レシピ、変数ファイル、MCP の入力がこれを選ぶことはできません。

ルートとその中のすべてのファイルは、root か実行ユーザーの所有で、グループやその他から
書き込めない必要があります。その上のディレクトリにも同じ条件が適用されます（sticky でも
構いません）。シンボリックリンクは拒否されます。問題があれば、何も実行する前に exit 2 で
レシピを拒否します。

- Sinter を root で実行する場合（`sudo` 経由など）は、`HOME` がどこを指していても、root 所有の
  プラグインファイルだけを受け付けます。
- Linux では、他者に書き込みを許す POSIX ACL のエントリは ACL マスクによって拒否されます。
  macOS では ACL を検出しません。
- Unix 以外のコントローラーではプラグインを拒否します。

## プラグインをインストールする

*v1.12.0 から。* Sinter は公式の plugin と catalog のバイト列をそのまま持っています。
`sinter plugin install` はそれをプラグインルートに書き込み、`trust.toml` にエントリを追加します。
何もダウンロードしません。

```sh
sinter plugin list                               # この Sinter が持つものと、インストール済みのもの
sinter plugin install firewalld@0.2.0 --dry-run  # 計画を表示するだけで、何も変えない
sinter plugin install firewalld@0.2.0            # "yes" と入力して確定する
sinter plugin verify firewalld@0.2.0
```

計画には、書き込むファイルと trust のエントリ、catalog のすべての observe 操作、許可されないまま
残る mutate 操作が表示されます。

- **確定は表明です。** `yes` の入力（端末がない場合は `--yes`）は、catalog の observe 操作を
  読み取り専用として受け入れる、という表明です。ホスト上でそれを Sinter が証明することは
  できず、分類は catalog のレビューに基づきます。
- **既定では mutate 操作を 1 つも許可しません。** `--yes` が許可することもありません。名前で
  `--allow-mutate OP[,OP...]`、またはリソースタイプ単位で `--allow-mutate-for TYPE[,TYPE...]`
  （そのタイプの変更操作すべて）を指定します。すべてを許可するオプションはありません。
- ファイルは mode 0600、ディレクトリは mode 0700 で作ります。既存のファイルを置き換えることは
  なく、既存の trust エントリの許可を広げたり狭めたりもしません。許可を変えるには
  `trust.toml` を自分で編集してください。
- 書き込みは同時に 1 つだけです。同じルートへの 2 つ目の install や remove は拒否されます。

`sinter plugin remove firewalld@0.2.0` は、プラグインを取り除きます。pin した公式のバイト列の
ままのファイルだけを消し、ほかの信頼済みプラグインが使う catalog は残し、それまでの trust
ファイルを `trust.toml.prev` に残します。変更されたファイルがあれば拒否し、何も変えません。

終了コード: 0 は完了、何もすることがない、または dry run。2 は拒否で、変更は残りません。
5 は変更を始めた後の失敗です（変更したものをレポートに列挙します）。`--json` は JSON を
1 つ出力し、計画とメッセージは標準エラーに出します。

`sinter plugin list` と `sinter plugin verify` は読むだけです。`verify` は、検査するものがない
場合（ルートがない、trust ファイルがない、何も pin されていない）、ファイルが pin と違う場合、
ローダーがプラグインを拒否する場合に exit 2 です。`sinter plugin` のどのコマンドもレシピを
読まず、ターゲットに接続しません。MCP にプラグインのツールはありません。

v1.12.0 より前のように手作業で用意したプラグインルートも、そのまま使えます。
[`plugins/first-party/`](https://github.com/hagix9/sinter/tree/main/plugins/first-party) の
ファイルを 1 バイトも変えずにコピーし、`trust.toml` で pin します。

```toml
format = 1

[[catalog]]
id = "firewalld"
version = "0.2.0"
sha256 = "d32ac3947279ec2581a7049f9fa931d29c904c91ea2484cafaa6759fe09c3641"
attested_observe = ["state", "zone_defined", "service_defined", "query_service_runtime", "query_service_permanent", "query_port_runtime", "query_port_permanent", "query_protocol_runtime", "query_protocol_permanent"]
allowed_mutate = ["add_port_runtime", "add_port_permanent"]

[[plugin]]
id = "firewalld"
version = "0.2.0"
sha256 = "e5819cfe0e2c017648f628a27d0ed6e4a18ed402f3ff6de072e61a724f0aa99a"
```

## mutate の部分許可

*v1.12.0 から。* observe と mutate の許可は別々です。プラグインのタイプが使う observe 操作は
すべて attest されている必要があり、そうでなければプラグイン全体を拒否します。
`allowed_mutate` に含まれない mutate 操作があっても、プラグインは拒否されません。

- `audit` は使えます（observe 操作だけを実行するため）。
- `plan` と `apply` は、許可されていない mutate 操作を必要としうるリソースがあると、
  ターゲットに接続する前に（`ssh -G`、接続、バックアップ、観測のどれもせずに）exit 2 で
  実行を拒否します。メッセージにはその操作の名前が出ます。

一部の mutate 操作を許可しても、ほかの操作、ほかのタイプの操作、プラグイン全体が許可される
ことはありません。

## レシピでプラグインを有効にする

レシピのトップレベルでプラグインを宣言します。

```yaml
plugins:
  - { id: firewalld, version: 0.2.0 }
```

そのうえで、`resources` の中でそのタイプを使います。

```yaml
- id: allow_https
  type: firewalld.port
  with: { zone: public, port: 443/tcp, state: present }
```

`plugins` はトップレベルのレシピでだけ使えます。include したファイルが宣言すると拒否されます。

## プラグインのリソースの動き

- `plan` と `audit` は observe 操作だけを実行します。
- `apply` は、観測した状態が違う部分にだけ mutate 操作を実行し、その後もう一度観測します。
- 結果は既存のステータスと終了コードを使い、JSON のキーは増えません。各プラグインリソースは、
  既存の `notes` か `reason` に出所の行（plugin、catalog とそれぞれの SHA-256）を 1 行持ちます。
- `sinter mcp` は、`plugins` を宣言するマニフェストをすべて拒否します。

catalog が observe と分類した操作が、ホスト上で読み取り専用であることを Sinter は証明でき
ません。その分類は catalog のレビューに基づきます。

## firewalld のタイプ

各タイプは、runtime と permanent の設定をそれぞれ別に扱います。何かを観測する前に、デーモンが
動いていること、ゾーン（service ではそのサービスも）が存在することを確認します。reload は
せず、ゾーンやインターフェースも変えません。操作にはターゲットでの root が必要です。root で
ログインするか、`--sudo` を使ってください。

| タイプ（版） | フィールド | `state` |
|--------------|------------|---------|
| `firewalld.service`（0.1.0、0.2.0） | `zone`、`service`、`state` | 0.1.0: `present`、0.2.0: `present` または `absent` |
| `firewalld.port`（0.2.0） | `zone`、`port`（`8443/tcp` のようにプロトコル付きの 1 ポート）、`state` | `present` または `absent` |
| `firewalld.port_range`（0.2.0） | `zone`、`port`（`8000-8099/udp` のような範囲）、`state` | `present` のみ |
| `firewalld.protocol`（0.2.0） | `zone`、`protocol`（`gre` など）、`state` | `present` または `absent` |

`ssh` サービスの削除と `22/tcp` の削除は拒否されます。Sinter 自身が使う接続を切るおそれが
あるためです。ポート範囲に `absent` はありません。範囲の一部だけが許可されていると
firewalld は「no」と答えるためです。ポートを閉じるには、`firewalld.port` で 1 つずつ指定して
ください。

## 検証

firewalld 0.1.0 と 0.2.0 は、次のシステムの実機で測定し、Sinter を通して実行しました。

| OS | firewalld |
|----|-----------|
| Rocky Linux 9.8 | 1.3.4 |
| Rocky Linux 10.2 | 2.4.3 |
| Ubuntu 24.04 | 2.1.1 |

検証していないこと:

- ほかの OS と firewalld の版。Sinter は版を確認しません。
- 8 ラベルの[リリース受入](/ja/compatibility/platforms/)は、ファイアウォールを変更しません。
  v1.12.0 からは `sinter plugin` のコマンドと、mutate の許可がない場合の `plan` と `apply` の
  拒否を確認しますが、firewalld の変更は確認しません。
- 実機での Sinter 自身のタイムアウト（結果が分からない変更で、indeterminate として報告されます）。
  テストでだけ確認しています。
- ハードリンクのないファイルシステムのコントローラーへのインストール（その場合 install は
  拒否されます）。
