---
title: Resource Plugins
description: データのみの Resource Plugins、プラグインルート、公式 firewalld プラグイン（v1.9.0〜v1.11.0）。
---

*v1.9.0 から利用できます。*

Resource Plugin は、`<plugin>.<name>` という名前のリソースタイプをデータとして追加します。
プラグインのコードが Sinter の中で動くことはありません。プラグインが実行できるプログラムは
すべて capability catalog から来ます。catalog には、固定のプログラム、オペランドを検査する
引数テンプレート、各終了ステータスの意味が記載されています。

v1.9.0 から v1.11.0 までのどのリリースでも、提供するプラグインは **`firewalld` 0.1.0** の
1 つだけで、リソースタイプは `firewalld.service` です（ファイルはすべての版で同じです）。
ソースリポジトリにある新しい版の firewalld は、まだどのリリースにも含まれておらず、
リリース版の Sinter はほかの catalog と同じように拒否します。他者の catalog には対応していません。catalog は、この Sinter に
組み込まれたレビュー済みの公式 catalog である場合にだけ使われ、それ以外は pin してあっても
拒否されます。

`plugins:` のないレシピの動作はこれまでと同じで、プラグインルートは読みません。

## プラグインルートを用意する

プラグインのファイルはソースリポジトリの
[v1.11.0 の `plugins/first-party/`](https://github.com/hagix9/sinter/tree/v1.11.0/plugins/first-party)
にあります（plugin と catalog のファイルは v1.9.0 と同じバイト列です）。リリースアーカイブには含まれず、これらを一覧・検査・
インストールするコマンドもリリースにはありません。編集せずにコントローラーへコピーしてください。
1 バイトでも変わると digest が変わり、Sinter はそのファイルを拒否します。

```text
<plugin-root>/
  trust.toml                              (mode 0600)
  catalogs/firewalld-0.1.0.catalog.toml
  plugins/firewalld-0.1.0.plugin.toml
```

`trust.toml` は、各プラグインと catalog を正確なバイト列の SHA-256 で pin し、使ってよい
オペレーションを列挙します。

```toml
format = 1

[[catalog]]
id = "firewalld"
version = "0.1.0"
sha256 = "27741bcc6b72dfbf69d918282fb454c324e7229b764873334a5c6c0af04707ff"
attested_observe = ["state", "zone_defined", "service_defined", "query_service_runtime", "query_service_permanent"]
allowed_mutate = ["add_service_runtime", "add_service_permanent"]

[[plugin]]
id = "firewalld"
version = "0.1.0"
sha256 = "47f33f171d239103cbb97450d17b57c857ce22436620ddf809fdd2be94948544"
```

ルートは `validate`、`plan`、`apply`、`audit` の `--plugin-root DIR` で指定します。
既定は `$XDG_CONFIG_HOME/sinter/plugins`、なければ `~/.config/sinter/plugins` です。

ルートとその中のすべてのファイルは、root または実行ユーザーの所有で、グループや他者が
書き込めない状態にしてください。ルートより上のディレクトリにも同じ条件が適用されます
（上のディレクトリは sticky でもかまいません）。シンボリックリンクは拒否します。問題があれば、
何も実行する前にレシピを exit 2 で拒否します。

- Linux では、他者に書き込みを許す POSIX ACL エントリを ACL マスクを通じて拒否します。
  macOS では ACL を検出しません。
- Unix 以外のコントローラーではプラグインを拒否します。

## レシピでプラグインを有効にする

レシピのトップレベルでプラグインを宣言します。

```yaml
plugins:
  - { id: firewalld, version: 0.1.0 }
```

`resources` の下で、そのタイプを使います。

```yaml
- id: allow_http
  type: firewalld.service
  with: { zone: public, service: http, state: present }
```

`plugins` を書けるのはトップレベルのレシピだけです。include されたファイルに書くと拒否します。

## プラグインリソースの実行

- `plan` と `audit` は observe オペレーションだけを実行します。
- `apply` は、観測した状態が異なる部分にだけ mutate オペレーションを実行し、そのあと再度観測します。
- 結果は既存のステータスと終了コードを使い、JSON のキーは増えません。各プラグインリソースには、
  由来を示す 1 行（プラグイン、catalog、それぞれの SHA-256）が既存の `notes` または `reason` に入ります。
- `sinter mcp` は `plugins` を宣言したマニフェストをすべて拒否します。

catalog が observe に分類したオペレーションがホスト上で読み取り専用であることを、Sinter は
証明できません。この分類は catalog のレビューに基づいています。

## `firewalld.service`

firewalld のゾーンにサービスが存在する状態にします。runtime と permanent の設定を別々に扱います。

| フィールド | 必須 | 説明 |
|-----------|------|------|
| `zone` | はい | ゾーン名。 |
| `service` | はい | firewalld のサービス名。 |
| `state` | はい | `present`。ほかの値は受け付けません。 |

プラグインは、何かを観測する前に、デーモンが動いていることと、ゾーンとサービスが存在することを
確認します。reload、サービスの削除、ゾーンやインターフェースの変更は行いません。

オペレーションにはターゲットの root 権限が必要です。root でログインするか `--sudo` を使ってください。

## 検証範囲

次の環境で、実機で測定し、Sinter を通して実行しました。

| OS | firewalld |
|----|-----------|
| Rocky Linux 9.8 | 1.3.4 |
| Rocky Linux 10.2 | 2.4.3 |
| Ubuntu 24.04 | 2.1.1 |

未検証のもの:

- ほかの OS と firewalld のバージョン。Sinter はバージョンを確認しません。
- 8 ラベルの[リリース受入](/ja/compatibility/platforms/)はプラグインを実行しないため、その結果は
  プラグインの動作を示しません。
- 実機での Sinter 自身のタイムアウト（結果が不明な変更を indeterminate と報告する動作）。
  テストでのみ確認しています。
