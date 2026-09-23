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
resources:
  - id: unique_name          # 必須、一意な識別子
    type: file               # リソースタイプのいずれか
    sensitive: false         # このリソースの値を出力でマスクする
    when: "facts.os.family == 'debian'"
    depends_on: [other_id]
    notify: [handler_id]
    with:                    # タイプ固有のパラメータ
      path: /etc/example
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

`service` は**ターゲット上の systemd ユニット名**です。Sinter のリソース id
から解決されることはありません。ハンドラは apply の最後に 1 回だけ実行され
ます。実際に変更があったリソースから通知された場合に限られます。同じ
ハンドラへの複数の通知は重複排除されます。

## 式

`when` と `changed_when` では意図的に小さな式言語が使われます:

- 名前空間: `vars.<name>`、`facts.hostname`、`facts.os.name`、
  `facts.os.family`、`facts.os.version`、`facts.arch`、
  `registers.<name>.<field>`、`item`（loop 内）、`result.<field>`
  （`changed_when` 内）。名前空間なしの裸の名前は許可されません。
- 演算子: `==`、`!=`、`<`、`<=`、`>`、`>=`、`&&`、`||`、`!`、括弧。
- `when`/`changed_when` は boolean に評価される必要があります。
  truthiness による型変換はありません。
