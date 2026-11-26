---
title: crypto_policy
description: RHEL 系ホストのシステム全体の暗号ポリシーを update-crypto-policies で設定する。
---

**目的:** RHEL 系ホストのシステム全体の暗号ポリシー（`update-crypto-policies`）を宣言する。`DEFAULT` や `FUTURE` のようなベースポリシーと、必要なら `NO-SHA1` のようなサブポリシーを指定する。

## 書式

```yaml
- id: crypto
  type: crypto_policy
  with:
    policy: "DEFAULT:NO-SHA1"
```

```toml
[[resources]]
id = "crypto"
type = "crypto_policy"

[resources.with]
policy = "DEFAULT:NO-SHA1"
```

## パラメータ

| パラメータ | 必須 | 型 | デフォルト | 説明 |
|-----------|------|-----|-----------|------|
| `policy` | はい | string | — | `BASE[:SUBPOLICY...]`。各部分は `[A-Z0-9][A-Z0-9_-]{0,31}`。サブポリシーは 8 個まで。同じサブポリシーを 2 回書くことはできない。例: `DEFAULT`、`FUTURE`、`DEFAULT:NO-SHA1`。 |
| `allow_weaker` | いいえ | boolean | `false` | 暗号を弱めるおそれがあるとして Sinter が拒否する変更を受け入れるには、リテラルの `true` を書く（下記）。 |

- `policy` には変数を使えますが、fact、register、sensitive な値は使えません。レシピを読み込むときに解決して検査します。
- `allow_weaker` は変数から与えることができません。このフラグは、レシピの文面で見えていなければなりません。
- `crypto_policy` は 1 つのレシピに 1 つだけです。2 つ目は検証のエラーです。

## 暗号を黙って弱めないための規則

レシピを読み込むときに検査すること:

- ベースが `FIPS` のものは、`allow_weaker` があっても無くても拒否します。FIPS モードの切り替えには `fips-mode-setup` と再起動が必要で、Sinter はそれを行いません。
- ベースが `LEGACY` のものは、`allow_weaker: true` が無ければ拒否します。
- サブポリシー `NO-SHA1` と `NO-CAMELLIA` は受け付けます。それ以外のサブポリシー（`SHA1`、`AD-SUPPORT`、`AD-SUPPORT-LEGACY`、`NO-ENFORCE-EMS`、`OSPP`、サイトで定義したモジュールなど）は、`allow_weaker: true` が無ければ拒否します。それがポリシーを弱めるかどうかを、Sinter は判断できないためです。`OSPP` はポリシーを制限するベンダーのモジュールですが、アルゴリズムを取り除くだけであることを Sinter は確認していません。そのため、他のモジュールと同じ扱いです。

plan と apply で、ホストが報告するポリシーが宣言と違うときに検査すること:

- `LEGACY` < `DEFAULT` < `FUTURE` の順でベースを下げる変更は、`allow_weaker: true` が無ければ拒否します。
- この順序に無いベース（独自のポリシー、`EMPTY`）は、強弱を比べられません。そこから、またはそこへの変更は、`allow_weaker: true` が無ければ拒否します。
- ホストに適用されている強化用のサブポリシー（`NO-SHA1`、`NO-CAMELLIA`）を外す変更は、`allow_weaker: true` が無ければ拒否します。ポリシーを弱めるためです。`OSPP` を外す変更も、`allow_weaker: true` が無ければ拒否します。失われる制限かもしれないためです。それ以外の適用済みサブポリシーを外す変更（たとえば `DEFAULT:SHA1` から `DEFAULT`）には、フラグは要りません。宣言したポリシー自体が上の規則を満たしているので、結果は Sinter が知っているベースになります。
- **Sinter が強弱を判断する名前の、ローカルな定義。** 上の規則は `LEGACY`、`DEFAULT`、`FUTURE`、`NO-SHA1`、`NO-CAMELLIA` を名前で判断します。これが正しいのは、ベンダーの定義についてだけです。現在のポリシーまたは宣言したポリシーのベースがこの 3 つのどれかで、`/etc/crypto-policies/policies/<BASE>.pol` がある場合、または宣言した `NO-SHA1` / `NO-CAMELLIA` に `/etc/crypto-policies/policies/modules/<NAME>.pmod` がある場合、その変更は `allow_weaker: true` が無ければ拒否します。知らない定義の強弱を、Sinter は判断できないためです。そのパスにあるものは何でも対象です（ファイルでもシンボリックリンクでも）。同じ plan の中で前の `file` リソースがそのパスを書く場合も同じです。
- 現在のポリシーが `FIPS` のホストは、決して変更しません。

## 期待される動作

- **観測。** Sinter は `/usr/bin/update-crypto-policies --show` を実行します（読み取りのみ）。終了コード 0 で、標準出力がポリシー 1 行だけの場合に限って受け付けます。それ以外の終了コード、余分な行、空の出力や切り詰められた出力、タイムアウトはエラーです。Sinter はポリシーを推測しません。標準エラー出力は答えの一部ではありません。ポリシーの 1 行と一緒に標準エラー出力へ警告が出ていても、答えは有効です。警告の文は表示しません。
- **plan** は、その 1 行を `policy` と完全一致で比べます（サブポリシーの順序も含む）。違う場合、ベースが `<BASE>.pol` として、各サブポリシーが `modules/<SUB>.pmod` として、`/usr/share/crypto-policies/policies` か `/etc/crypto-policies/policies` の下にあることを確かめます。定義が無ければ、その名前を示して plan を止めます。存在しないポリシーは、何も実行する前に拒否されます。
- **apply** は、`/usr/bin/update-crypto-policies --set <POLICY>` を root で、シェルを使わずに実行します。その直前にポリシーをもう一度観測し、判断のもとにしたポリシーと違っていれば、何も変えずにリソースは失敗します（もう一度実行してください）。終了コードが 0 以外なら失敗です。終了コード 0 だけでは成功としません。ポリシーをもう一度観測し、`policy` と一致しなければリソースは失敗します。ツールが kill された、タイムアウトした、接続が切れた場合、結果には「ポリシーは適用されたかもしれないし、されていないかもしれない」と書きます。成功とは報告しません。
- 2 回目の apply は何も変えず、`--set` も実行しません。
- **audit** は、設定されているシステム全体のポリシーを `policy` と比べ、違いを `policy` の drift として報告します。動作中のサービスについては何も述べません。最後のポリシー変更より前に起動したサービスは、以前のポリシーを使い続けていることがあります。観測の失敗と、`update-crypto-policies` の無いホストはエラーです。

## サービスと SSH

このリソースのために、Sinter がサービスを再起動することも、再起動（reboot）することもありません。ポリシーを変更する plan と apply の結果には、必ず次の注記が付きます。

- `sshd` を含む動作中のサービスは、再起動するまで以前のポリシーを使い続けます。
- より厳しいポリシーでは、**新しい** SSH 接続が失敗することがあります（古い鍵の種類やアルゴリズム）。今の接続を閉じる前に、2 本目の接続を開いて確かめてください。
- ポリシーを完全に反映するために、ベンダーは再起動（reboot）を勧めています。

変更は、他のリソースと同じように handler に通知されます。そのため、レシピの `service` handler でアプリケーションを再起動できます。その方法で `sshd` を再起動するかどうかは、利用者が明示的に決めることです。Sinter が勧めたり、自分から行ったりすることはありません。

## 対応していない場合

- `/usr/bin/update-crypto-policies` の無いホスト（Debian、Ubuntu）: plan と apply は「crypto_policy is not supported on this host (update-crypto-policies was not found)」で失敗し、audit はエラーを報告します。
- FIPS モード（どちらの向きも）。
- ポリシーやサブポリシーの定義ファイルを書くこと。サイトで定義する `.pol`/`.pmod` ファイルには [`file`](/ja/reference/resources/file/) リソースを使い、`depends_on` に書いてください。同じ実行の先のリソースが定義を作る（またはツールをインストールする）可能性がある場合、plan は失敗せずにそのことを報告し、apply がもう一度確かめます。
- root ではない場合: plan は注記を付け、apply はツールを実行する前に失敗します。
- MCP では使えません。この観測は、まだ実機で測定していないためです。

## 対応しているシステム

- RHEL、Rocky Linux、AlmaLinux の 9 と 10。
- Debian と Ubuntu は対象外です。
- 使えるポリシーとサブポリシーはリリースによって異なります。ホストにないものは
  `plan` で拒否します。Rocky Linux 10.2 で確認した内容は次のとおりです。
  ポリシーは `DEFAULT`、`FUTURE`、`LEGACY`、`FIPS`、`EMPTY`。サブポリシーは
  `AD-SUPPORT`、`AD-SUPPORT-LEGACY`、`ECDHE-ONLY`、`NO-ENFORCE-EMS`、`NO-PQ`、
  `OSPP`、`TEST-PQ`。`NO-SHA1` と `NO-CAMELLIA` は**ありません**（EL 10 は既定で
  SHA-1 を無効にしています）。このページの `DEFAULT:NO-SHA1` の例は EL 9 向けです。
  ホストにあるものは
  `ls /usr/share/crypto-policies/policies /usr/share/crypto-policies/policies/modules`
  で確認できます。

## まだ実機で確認していないこと

上の動作は、スクリプトで動く擬似的な対象でテストしています。次のことは、実際の RHEL 系ホストでまだ測定していません。

- EL 9 と EL 10 で、`update-crypto-policies --show` が何も変更せず、ちょうど 1 行を出力し、サブポリシーを設定したときの形（`DEFAULT:NO-SHA1`）で出力すること。
- 存在しないポリシーやモジュールを指定した場合と、root でない場合の、`--set` の終了コードとメッセージ。
- 各リリースに含まれるサブポリシーのモジュール（たとえば `NO-CAMELLIA` と `OSPP` は、すべてのリリースにあるわけではありません。無ければ plan が止まります）。
- ベンダーの `OSPP` モジュールの正確な内容（アルゴリズムを取り除くだけかどうか）。同じ名前のポリシーやモジュールがベンダーのツリーと `/etc/crypto-policies/policies` の両方にあるとき、`update-crypto-policies` がどちらの定義を使うか。
- `--set` にかかる時間と、新しい SSH 接続への影響。

## 例

既定のポリシーから SHA-1 を外す:

```yaml
version: 1
resources:
  - id: crypto
    type: crypto_policy
    with:
      policy: "DEFAULT:NO-SHA1"
```

```toml
version = 1

[[resources]]
id = "crypto"
type = "crypto_policy"

[resources.with]
policy = "DEFAULT:NO-SHA1"
```

ポリシーを `FUTURE` に上げ、それを反映させたいアプリケーションを再起動する:

```yaml
version: 1
resources:
  - id: crypto
    type: crypto_policy
    notify: [restart-app]
    with:
      policy: FUTURE
handlers:
  - id: restart-app
    service: myapp
    action: restart
```

```toml
version = 1

[[resources]]
id = "crypto"
type = "crypto_policy"
notify = ["restart-app"]

[resources.with]
policy = "FUTURE"

[[handlers]]
id = "restart-app"
service = "myapp"
action = "restart"
```

ポリシーを明示的に `LEGACY` に下げる:

```yaml
version: 1
resources:
  - id: crypto
    type: crypto_policy
    with:
      policy: LEGACY
      allow_weaker: true
```

```toml
version = 1

[[resources]]
id = "crypto"
type = "crypto_policy"

[resources.with]
policy = "LEGACY"
allow_weaker = true
```
