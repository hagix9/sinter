---
title: はじめてのレシピ
description: ファイル、サービス、ハンドラを扱う完全なレシピ。
---

このレシピは設定ファイルを書き込み、サービスが起動していることを保証
します。変数、依存関係、遅延ハンドラという Sinter レシピの中核となる
構成要素を使います。

```yaml title="recipe.yaml"
version: 1

vars:
  greeting:
    value: hello
    sensitive: false

resources:
  - id: motd
    type: template
    with:
      path: /etc/motd
      source: templates/motd
      mode: "0644"
    notify:
      - restart_motd

  - id: sshd
    type: service
    with:
      name: sshd
      state: running
      enabled: true

handlers:
  - id: restart_motd
    service: motd
    action: restart
```

## 各要素の役割

- `version: 1` — レシピフォーマットのバージョン（必須）。
- `vars` — フィールドやテンプレート内で `{{ vars.greeting }}` として
  参照するリテラル値。`sensitive: true` の値はすべての出力で
  マスクされます。
- `resources` — 目的の状態を順序付きで列挙。それぞれ `id`、`type`、
  `with`（パラメータ）、および省略可能な `when`、`loop`、`depends_on`、
  `notify`、`sensitive` を持ちます。
- `notify` — `motd` が変更された後、ハンドラ `restart_motd` が apply の
  最後に 1 回だけ実行されます（遅延実行・重複排除）。
- `handlers` — 遅延実行される `restart`/`reload` サービスアクション。

## テンプレート

```text title="templates/motd"
{{ vars.greeting }} — managed by sinter
```

テンプレートのソースはレシピファイルからの相対パスで解決されます。
`with.vars` でテンプレートローカルな値を渡し、`{{ template.name }}`
として参照することもできます。

## 実行する

```sh
sinter validate recipe.yaml
sinter plan --host web01.example.com --sudo recipe.yaml
sinter apply --host web01.example.com --sudo recipe.yaml
```

## 期待される動作

- 1 回目の apply: ファイルがアトミックに書き込まれ、サービスが
  running/enabled に保証され、ハンドラが `motd` を 1 回再起動します。
- 2 回目の apply: すべてのリソースが変更なし — 変更はゼロで、
  ハンドラは実行されません。
- いずれかのリソースが失敗した場合、実行は停止します（fail-fast）。
  残りのリソースは blocked として報告されます。

完全なモデルは[レシピ](/sinter/ja/concepts/recipes/)へ、各リソースの
詳細は[リソースリファレンス](/sinter/ja/reference/resources/)へ進んで
ください。
