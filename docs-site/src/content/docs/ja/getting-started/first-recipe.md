---
title: はじめてのレシピ
description: 最初の実践的なレシピ — 変数とレンダリングされるテンプレート。
---

このレシピはコントローラ側のテンプレートをターゲットにレンダリングします。
変数とレンダリングされるテンプレートという Sinter レシピの中核となる構成
要素を使います。

```yaml title="recipe.yaml"
version: 1

vars:
  greeting:
    value: hello
    sensitive: false

resources:
  - id: greeting
    type: template
    with:
      path: /etc/sinter-motd
      source: templates/greeting
      mode: "0644"
```

この例では、どちらの対応ターゲットにもデフォルトでは存在しないパスである
`/etc/sinter-motd` を意図的に使います。`/etc/motd` は Rocky ではパッケージ
所有のファイルであり、Ubuntu では `/etc/update-motd.d` によって動的に管理
されるためです。

## 各要素の役割

- `version: 1` — レシピフォーマットのバージョン（必須）。
- `vars` — フィールドやテンプレート内で `{{ vars.greeting }}` として
  参照するリテラル値。`sensitive: true` の値はすべての出力で
  マスクされます。
- `resources` — 目的の状態を順序付きで列挙。それぞれ `id`、`type`、
  `with`（パラメータ）、および省略可能な `when`、`loop`、`depends_on`、
  `notify`、`sensitive` を持ちます。
- `id: greeting` — リソースの id です。`depends_on` や `notify` で使われる
  ラベルであり、`service` リソースのユニット名とは何の関係もありません。

## テンプレート

```text title="templates/greeting"
{{ vars.greeting }} — managed by sinter
```

テンプレートのソースはレシピファイルからの相対パスで解決されます。
`with.vars` でテンプレートローカルな値を渡し、`{{ template.name }}`
として参照することもできます。

## 実行する

```sh
sinter validate recipe.yaml
sinter plan --host web01.example.com recipe.yaml
sinter apply --host web01.example.com --sudo recipe.yaml
```

## 期待される動作

- `validate` はターゲットに一切接続せず、レシピが ok であることを
  報告します。
- `plan` はターゲットを観測し、書き込まれるファイルをプレビューします。
  作成も変更も行いません。
- 1 回目の apply: テンプレートがコントローラ上でレンダリングされ、結果が
  `root:root`、モード `0644` で `/etc/sinter-motd` にアトミックに
  公開されます。
- 2 回目の apply: すべてのリソースが変更なし — 変更はゼロです。
- いずれかのリソースが失敗した場合、実行は停止します（fail-fast）。
  残りのリソースは blocked として報告されます。

## サービスを追加する

`service` リソースの基本は[クイックスタート](/sinter/ja/getting-started/quick-start/)
に含まれています。1 つのルールを覚えておいてください。`service` リソースと
ハンドラの `service:` はどちらも**ターゲット上の systemd ユニット名**を
指定します。ユニット名はディストリビューションによって異なります —
SSH デーモンは Ubuntu では `ssh.service`、Rocky Linux では
`sshd.service` です。そのようなリソースは、ドキュメント化されている
`when` 式でプラットフォームごとにスコープできます:

```yaml
  - id: ssh_service
    type: service
    with:
      name: ssh          # RHEL 系ターゲットでは sshd
      state: running
    when: "facts.os.family == 'debian'"
```

リソースが変更されたときにだけサービスを再起動したい場合はハンドラを
追加します。完全なハンドラモデルは[レシピ](/sinter/ja/concepts/recipes/)
を参照してください。

完全なモデルは[レシピ](/sinter/ja/concepts/recipes/)へ、各リソースの
詳細は[リソースリファレンス](/sinter/ja/reference/resources/)へ進んで
ください。
