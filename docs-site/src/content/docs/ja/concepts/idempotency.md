---
title: 冪等性
description: 目的の状態に達した後、繰り返しの apply は変更を行わない。
---

Sinter のリソースは冪等です: ターゲットがすでに目的の状態と一致して
いる場合、そのリソースに対して `apply` は何も変更しません。

## 実際の意味

```sh
sinter apply --host web01 --sudo recipe.yaml   # 変更が適用される
sinter apply --host web01 --sudo recipe.yaml   # ok — 変更ゼロ
```

- `package` リソースはインストール済みのパッケージを再インストール
  せず、存在しないパッケージを再削除しません。
- 目的の content、mode、所有者をすでに持つ `file` リソースは
  書き換えられません。
- すでに `running` かつ `enabled` の `service` はそのままです。
- ハンドラは何かが変更されたときだけ実行されます。冪等な 2 回目の
  apply ではハンドラは起動しません。

## 再計画ではなく再観測

`apply` は過去の `plan` を信用しません。すべてのステートフルな
リソースは、変更の判断の直前に改めて観測されるため、plan と apply
の間に生じたドリフトも正しく処理されます。

## command リソースとガード

`command` は本質的には冪等ではありません — 到達すれば実行されます。
`creates` または `removes` ガードを使って冪等にしてください:

```yaml
- id: update_index
  type: command
  with:
    program: /usr/bin/touch
    args: ["/var/lib/myapp/indexed"]
    creates: /var/lib/myapp/indexed
```

`/var/lib/myapp/indexed` が存在する場合、コマンドは実行されません。
リソースは変更なしの成功を報告し、依存関係は満たされたままです。

## 誠実な報告

変更に成功した後に後続のステップで失敗したリソースも、変更があった
ことを誠実に報告します。検証の失敗が「成功」に丸められることは
ありません。
