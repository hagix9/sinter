---
title: レシピ概要
description: Sinter v0.2.0 がサポートする機能で構成されたレシピ例。
---

以下の例はすべて v0.2.0 に実装されたリソースタイプとフィールドのみを
使います。すべてのレシピはプラットフォーム中立で、同じ YAML が Ubuntu
と Rocky の両方のターゲットに適用できます。

## パッケージ + サービスのベースライン

```yaml
version: 1

resources:
  - id: nginx
    type: package
    with:
      name: nginx
      state: present

  - id: nginx_service
    type: service
    with:
      name: nginx
      state: running
      enabled: true
    depends_on: [nginx]
```

## ハンドラ付きの管理対象設定ファイル

```yaml
version: 1

resources:
  - id: app_conf
    type: file
    with:
      path: /etc/myapp/config.ini
      content: |
        [server]
        listen = 8080
      mode: "0640"
      owner: root
      group: root
    notify: [restart_app]

  - id: app_service
    type: service
    with:
      name: myapp
      state: running
      enabled: true

handlers:
  - id: restart_app
    service: myapp
    action: restart
```

ハンドラは apply の最後に `myapp` を 1 回だけ再起動します。ファイルが
実際に変更された場合に限られます。

## ガード付きのワンショットコマンド

```yaml
version: 1

resources:
  - id: mark_provisioned
    type: command
    with:
      program: /usr/bin/touch
      args: ["/var/lib/myapp/provisioned"]
      creates: /var/lib/myapp/provisioned
```

`creates` がコマンドを冪等にします。マーカーが存在しない場合だけ実行
されます。

## プラットフォーム条件付きリソース

```yaml
version: 1

resources:
  - id: debian_only
    type: package
    when: "facts.os.family == 'debian'"
    with:
      name: unattended-upgrades
      state: present
```

## register されたコマンド結果

```yaml
resources:
  - id: probe
    type: command
    with:
      program: /usr/bin/test
      args: ["-f", "/etc/myapp/ready"]
      success_codes: [0, 1]
      changed_when: "false"
      register: probe_result

  - id: follow_up
    type: file
    when: "registers.probe_result.exit_code == 0"
    with:
      path: /etc/myapp/confirmed
      content: "ready\n"
```

完全なスキーマは[レシピフォーマット リファレンス](/sinter/ja/reference/recipe-format/)と
[リソースリファレンス](/sinter/ja/reference/resources/)を参照してください。

:::note[公式レシピコレクション]
キュレーションされたレシピコレクション（例えば `linux-baseline`
セット）は将来のプロダクト改善であり、まだ存在しません。このページは
v0.2.0 が実装しているものだけを記述しています。
:::
