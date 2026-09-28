---
title: レシピフォーマット
description: 完全なレシピスキーマ — トップレベルフィールド、式、補間。
---

レシピは YAML または TOML で書けます。どちらも同じ意味モデルに
コンパイルされます。以下の YAML の例は TOML にも等しく適用されます。

## 骨格

```yaml
version: 1                    # 必須

vars:                         # 省略可
  <name>: { value: ..., sensitive: <bool> }

include: [...]                # 省略可。レシピファイルのリスト

resources: [...]              # 省略可。リソースのリスト

handlers: [...]               # 省略可。ハンドラのリスト

targets: { hosts: [...], groups: [...] }   # 省略可。v1.1.0 以降（インベントリ実行）

backup: { paths: [...] }      # 省略可。v1.1.0 以降（apply 前にコピー）
```

許可されるトップレベルフィールド: `version`、`vars`、`include`、
`resources`、`handlers`、および（v1.1.0 以降）`targets` と `backup`。
それ以外はスキーマエラーです。

## targets

*Sinter v1.1.0 以降で利用できます。*

```yaml
targets:
  groups: [web]        # インベントリのグループ名
  hosts: [db01]        # インベントリのホスト名（グループとの和集合）
```

`--inventory` と組み合わせたときに、このレシピを実行してよいインベントリの
ホストを指定します。1 つ以上の名前が必要で、名前は静的です。`targets` は
実行するレシピにだけ書け、include されるファイルには書けません。
`--inventory` 使用時に `targets` の**ない**レシピはエラーです（インベントリに
あることは実行の許可になりません）。インベントリなし（`--host` または
localhost）では `targets` は無視され、従来の単一ターゲット動作のままです。
[複数ホスト](/ja/reference/cli/#複数ホスト)参照。

## backup

*Sinter v1.1.0 以降で利用できます。*

```yaml
backup:
  paths:
    - /etc/ssh/sshd_config
    - /etc/nginx
```

`apply` が何かを変更する前に、選択された各ターゲット上でコピーする静的な
絶対パスです。バックアップが失敗すると、リソースを 1 つも実行せずに apply
が止まります。`plan` は一覧表示のみ、`audit` は扱いません。include された
ファイルにも書けますが重複は不可で、`/` は指定できません。
[apply 前のバックアップ](/ja/reference/cli/#apply-前のバックアップ)参照。

## vars

```yaml
vars:
  port:
    value: 8080
    sensitive: false
  token:
    value: abc123
    sensitive: true
```

- `value` はリテラルです。変数が他の変数を補間することはできないため、
  前方参照や循環は存在し得ません。
- `sensitive: true` は、その値とそこから派生するすべてを、あらゆる
  出力と診断情報でマスクします。

## resources

| フィールド | 必須 | 型 | 補足 |
|-----------|------|-----|------|
| `id` | はい | string | 一意。`depends_on`、`notify`、`registers` でも使われる。 |
| `type` | はい | string | `file`、`directory`、`link`、`template`、`command`、`package`、`service`。 |
| `with` | はい | map | タイプ固有のパラメータ（各リソースページを参照）。 |
| `when` | いいえ | string | このリソースと依存先をゲートする boolean 式。 |
| `loop` | いいえ | list | アイテムごとに 1 回展開。フィールド内で `{{ item }}`。 |
| `depends_on` | いいえ | list | 先に完了している必要があるリソース id。 |
| `notify` | いいえ | list | 変更時に起動されるハンドラ id。 |
| `sensitive` | いいえ | bool | このリソースのすべての値をマスクする。 |

## handlers

| フィールド | 必須 | 補足 |
|-----------|------|------|
| `id` | はい | リソースとハンドラをまたいで一意。 |
| `service` | はい | 対象サービス。 |
| `action` | はい | `restart` または `reload`。 |
| `sensitive` | いいえ | ハンドラの詳細をマスクする。 |

ハンドラは apply の最後に 1 回だけ実行されます。変更されたリソースが
通知した場合に限られます。

## 補間

文字列には `{{ expression }}` を埋め込めます:

```yaml
content: "listen = {{ vars.port }}"
```

フィールド全体が 1 つの `{{ ... }}` トークンの場合、型付きの値が
保持されます（整数は整数のまま、など）。

## 式

`when`、`changed_when`、補間で使われます:

- 入力: `vars.<name>`、`facts.hostname`、`facts.os.name`、
  `facts.os.family`、`facts.os.version`、`facts.arch`、
  `registers.<name>.<field>`、`item`、`result.<field>`
  （`changed_when` 内）。
- 演算子: `==` `!=` `<` `<=` `>` `>=` `&&` `||` `!` と括弧。
- ユーザ定義関数なし。裸の識別子なし。
- `when`/`changed_when` は boolean を生成する必要があります。
  truthiness による型変換はありません。
- 順序比較は数値と文字列にのみ適用されます。等値比較は同じ型の
  オペランドが必要です（int/float は数値として比較可能）。
- 未知の値との比較は unknown を返します。リソースは推測されるのでは
  なく indeterminate になります。

## 厳格性

- YAML フロントエンドはエイリアス/アンカー、マージキー、重複キー、
  非有限の浮動小数点を拒否します。
- TOML フロントエンドは日時と非有限の浮動小数点を拒否します。
- リソースやハンドラ id の重複は拒否されます。リソース id と衝突する
  ハンドラ id はエラーです。
- 2 つのステートフルなファイルシステムリソースが完全に同じパスを
  管理することはできません。
