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

## ターゲットに対して実行する

`plan` と `apply` にはターゲット — 状態を観測する対象のマシン — が
必要です。この例ではリモートホストを使い、Sinter は SSH 経由でそこに
接続します:

- `--host web01.example.com` — ターゲットマシンの SSH ホスト名（または
  アドレス）。Sinter は SSH で接続し、すべての観測と変更をそのホスト上で
  実行します。ターゲットには何もインストールされません。`--host` を
  省略すると、`sinter` を実行しているマシン自身がターゲットになります。
- `--sudo` — ターゲット側のすべての操作を非対話型の `sudo -n` 経由で
  root として実行します。この例では `/etc` 配下への書き込みに、
  非 root ユーザーに対して通常 root 権限が必要となるためです。
  ターゲット側のアカウントにパスワードなし sudo が
  設定されている必要があります。`--sudo` なしでは、パーミッションの
  失敗は昇格されず、そのまま失敗として報告されます。

`validate` には `--host` がありません。レシピの構造と意味だけを
コントローラ上でチェックし、どのターゲットにも接続しないためです。
この例で `plan` と `apply` にターゲットが必要なのは、特定のマシン上の
`/etc/sinter-motd` の実際の状態を観測し（`apply` は変更も行い）ます。

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

## もう 2 つのリソースを試す

Sinter は 7 つのリソースタイプを実装しています。一覧は
[リソースリファレンス](/sinter/ja/reference/resources/)を参照して
ください。このレシピの小さなバリエーション 2 つで、さらに 2 つの
タイプを試せます。

### `file` でインラインコンテンツ

`file` リソースはテンプレートファイルなしでインラインの内容を
書き込みます。これは完全なレシピです — 表示されているとおりに
そのままコピーしてください:

```yaml
version: 1

resources:
  - id: motd
    type: file
    with:
      path: /etc/sinter-motd
      content: "managed by sinter\n"
      mode: "0644"
```

テンプレート版と同様に、内容はアトミックに公開され、再 apply では
何も変更されません。インラインの `content` も補間されます — たとえば
`content: "token={{ vars.token }}"` は動作します。違いはソースに
あります: `file` はリテラルな文字列を書き込み（または `source`
ファイルをそのままコピーし）ます。一方 `template` は外部の
テンプレートファイルをレンダリングし、`with.vars` のテンプレート
ローカルな値を `{{ template.name }}` として使うこともできます。

### ディレクトリとシンボリックリンク

```yaml
version: 1

resources:
  - id: appdir
    type: directory
    with:
      path: /etc/myapp
      mode: "0755"

  - id: current_config
    type: link
    with:
      path: /etc/myapp/config
      target: /etc/sinter-motd
    depends_on: [appdir]
```

`directory` は指定した 1 つのディレクトリだけを作成します — 親
（`/etc`）がすでに存在している必要があり、再帰的な作成はありません。
`link` は `path` のシンボリックリンクが `target` を指すことを保証
します。`depends_on` によってリンクはディレクトリの後に実行されます。

これらはすべて上で示したのと同じコマンドで実行できます。より大きな
構成要素 — ガード付きの `command` リソース、`package`/`service` の
ベースライン、ハンドラ — については
[レシピ概要](/sinter/ja/recipes/overview/)を参照してください。

完全なモデルは[レシピ](/sinter/ja/concepts/recipes/)へ、各リソースの
詳細は[リソースリファレンス](/sinter/ja/reference/resources/)へ進んで
ください。
