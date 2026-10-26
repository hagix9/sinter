---
title: レシピ
description: レシピの構造 — version、vars、includes、resources、handlers。
---

レシピは 1 つのターゲットに対する目的の状態を宣言します。YAML と TOML
は単一の意味モデルに対するフロントエンドであり、どちらの形式で書かれた
等価なレシピも等価な動作を生みます。

## トップレベルフィールド

| フィールド | 型 | 用途 |
|-----------|-----|------|
| `version` | integer（必須） | レシピフォーマットのバージョン。現在は `1`。 |
| `vars` | map | 省略可能な `sensitive` フラグを持つ名前付きリテラル値。 |
| `include` | list | このレシピにマージされる他のレシピファイル。 |
| `resources` | list | 目的の状態を表すリソース。順番に評価される。 |
| `handlers` | list | 遅延実行される `restart`/`reload` サービスアクション。 |

これ以外のトップレベルフィールドは許可されません。

## 変数

```yaml
vars:
  app_user:
    value: deploy
    sensitive: false
  db_password:
    value: s3cret
    sensitive: true
```

変数はリテラルのみです。他の変数を参照することはできません。
文字列フィールドやテンプレート内では `{{ vars.app_user }}` で参照します。

`sensitive: true` の値は、派生した値を含め、通常の出力、verbose モード、
diff、register された結果、診断情報、JSON 出力のいずれにも現れません。
sensitive な内容についてはハッシュとサイズも隠されます。

## インクルード

`include` は他のレシピファイルをモデルに展開します。相対パスは、インクルード
元のレシピファイルのディレクトリから解決され、絶対パスはそのまま使われます。
同じファイルが 2 回展開されることはありません。重複するインクルードや
インクルードの循環は拒否されます。

## リソース

```yaml
version: 1

resources:
  - id: other_id             # 下の depends_on が指すリソース
    type: directory
    with:
      path: /etc/example.d

  - id: unique_name          # 必須、一意な識別子
    type: file               # リソースタイプのいずれか
    sensitive: false         # このリソースの値を出力でマスクする
    when: "facts.os.family == 'debian'"
    depends_on: [other_id]
    notify: [handler_id]
    with:                    # タイプ固有のパラメータ
      path: /etc/example

handlers:
  - id: handler_id           # notify が指すハンドラ
    service: example
    action: restart
```

共通フィールド: `id`、`type`、`with`、`when`、`loop`、`depends_on`、
`notify`、`sensitive`。意味については[リソース](/ja/concepts/resources/)を、
タイプ別パラメータについては[リソースリファレンス](/ja/reference/resources/)を参照してください。

## ハンドラ

```yaml
handlers:
  - id: restart_app
    service: app.service   # ターゲット上の systemd ユニット名
    action: restart        # restart または reload
```

ハンドラには `type: service` を付けられます。付けなければサービスハンドラなので、
既存のレシピは変わりません。このバージョンで実装されているハンドラ種別は
`service`、`ca_trust`、`command`（下記）の 3 つです。それ以外の種別を使うレシピは、
無視されずに検証で拒否されます。

`service` は**ターゲット上の systemd ユニット名**です。Sinter のリソース id
から解決されることはありません。ハンドラは apply の最後に 1 回だけ実行され
ます。実際に変更があったリソースから通知された場合に限られます。同じ
ハンドラへの複数の通知は重複排除されます。systemd ユニットの入力が変更された
場合、またはユニットが `NeedDaemonReload=yes` を報告している場合、Sinter は
ハンドラの実行前にシステムマネージャを reload します（`systemctl daemon-reload`）。
reload は restart ではありません。
[service](/ja/reference/resources/service/#マネージャの自動同期)を参照して
ください。

### CA 信頼ストアのハンドラ

```yaml
resources:
  - id: company_ca
    type: file
    with:
      path: /usr/local/share/ca-certificates/company.crt   # Debian/Ubuntu
      source: files/company.crt
    notify: [refresh_ca]
handlers:
  - id: refresh_ca
    type: ca_trust
```

`ca_trust` ハンドラは、通知元のファイルが変更されたときに、システムの CA 信頼ストアを
更新します。他のフィールド（`service`、`action`）は持ちません。証明書の配置は
`file` リソースの役割で、ハンドラは何も配置しません。

| 対象 | 実行されるコマンド（固定。シェルなし） |
|------|-----------------------------------------|
| Debian、Ubuntu | `/usr/sbin/update-ca-certificates`（`--fresh` なし。ストアを再構築しません） |
| RHEL、Rocky Linux、AlmaLinux | `/usr/bin/update-ca-trust extract` |

OS の判定は、検出された OS ファミリーで行い、「存在するツール」では決めません。
それ以外の OS で、リソースが `ca_trust` ハンドラに通知する場合は、ターゲットに接続した
時点（plan、apply、audit とも）で、どのリソースも実行される前にレシピが拒否されます。
ハンドラには root が必要です。root で接続するか `--sudo` を付けてください。root が
なければハンドラは失敗し、何も実行しません。ツールがターゲット上で実行可能でなければ
失敗し、何も実行しません。Debian の証明書は `/usr/local/share/ca-certificates/` の下に
`.crt` の名前で、RHEL の証明書は `/etc/pki/ca-trust/source/anchors/` の下に置いてください
（各ツールの期待どおりです）。

成功は、ツールが終了コード 0 で終わったことを意味します。特定の証明書が信頼されることまでは
確認しません。`plan` と `audit` はツールを実行しません。`plan` はハンドラを保留中のハンドラ
として表示します。ハンドラは宣言順に実行されるので、新しいストアを参照する `service`
ハンドラより前に `ca_trust` ハンドラを宣言してください。自動の `systemctl daemon-reload` とは
無関係です。

実機での検証済み: まだありません（スクリプト化したターゲットでのみテスト済み）。

### command ハンドラ

```yaml
resources:
  - id: app_config
    type: file
    with:
      path: /etc/myapp/config.yaml
      source: files/config.yaml
    notify: [rebuild_cache]
handlers:
  - id: rebuild_cache
    type: command
    with:
      program: /usr/bin/myapp
      args: [cache, rebuild]
      timeout_seconds: 300
```

`command` ハンドラは、通知したリソースが変更されたときに、プログラムを 1 つ実行します。
キャッシュの再生成や設定の再読み込みなど、変更に付随するアプリ固有の手順のためのものです。
apply のたびに実行したい処理には使わないでください（それには `command` リソースを使います）。

| フィールド（`with` の中） | 必須 | 補足 |
|---------------------------|------|------|
| `program` | はい | 絶対パス。`PATH` から探しません。`.` や `..` は不可。静的なテキスト。 |
| `args` | いいえ | 文字列のリスト。最大 64 個、各 4096 バイトまで。NUL は不可。 |
| `timeout_seconds` | いいえ | 1〜3600 の整数。既定は 300。 |

値は静的なテキストなので、`{{` を含む値は、そのまま実行されるのではなく拒否されます。
プログラムは、これらの引数そのままで直接実行されます。シェルを経由しないので、
クォートや展開は関係ありません。環境は `command` リソースと同じ固定のものです。`cwd`、
`env`、`success_codes` は使えません（拒否されます）。この制限はハンドラだけのもので、
`command` リソースは従来の制限のままです。

実行権限は `command` リソースと同じで、実行全体の権限（root、または `--sudo`）です。
自分で昇格することはなく、事前に root かどうかを確認することもしません。root が必要な
プログラムが root なしで実行されれば、そのプログラム自身の終了ステータスで失敗します。
プログラムがターゲット上の実行可能ファイルでなければ、ハンドラは失敗し、何も実行しません。

結果は終了ステータスです。0 が成功で、それ以外のステータスやシグナルは、プログラムが
途中まで変更していたとしても失敗です。タイムアウトや接続断は indeterminate で、
再試行されません。失敗または indeterminate のハンドラでハンドラフェーズは止まり、
それ以降のハンドラは pending として報告されます。レポートには、ハンドラ（`type: command`、
action は `run`）と、失敗時のプログラム名およびその標準エラーの先頭 1 行が載りますが、
引数は載りません。`sensitive: true` のハンドラ（および sensitive なリソースから通知された
ハンドラ）は完全にマスクされます。

`plan` と `audit` はプログラムを実行しません。`plan` はハンドラを保留中のハンドラとして
表示します。ハンドラは宣言順に実行されるので、依存する `ca_trust` や `service` ハンドラ
との前後関係に合わせて宣言してください。

実機での検証済み: まだありません（スクリプト化したターゲットでのみテスト済み）。

## 式

`when` と `changed_when` では意図的に小さな式言語が使われます:

- 名前空間: `vars.<name>`、`facts.hostname`、`facts.os.name`、
  `facts.os.family`、`facts.os.version`、`facts.os.version_major`（整数）、`facts.arch`、
  `registers.<name>.<field>`、`item`（loop 内）、`result.<field>`
  （`changed_when` 内）。名前空間なしの裸の名前は許可されません。
- 演算子: `==`、`!=`、`<`、`<=`、`>`、`>=`、`&&`、`||`、`!`、括弧。
- `when`/`changed_when` は boolean に評価される必要があります。
  truthiness による型変換はありません。
