---
title: レシピ概要
description: Sinter v1.1.3 がサポートする機能で構成されたレシピ例。
---

以下の例はすべて v1.1.3 に実装されたリソースタイプとフィールドのみを
使います。すべてのレシピはプラットフォーム中立で、同じ YAML が Ubuntu
と RHEL 系の両方のターゲットに適用できます。

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

## ハンドラ付きの systemd ユニットファイル

```yaml
version: 1

resources:
  - id: app_unit
    type: file
    with:
      path: /etc/systemd/system/myapp.service
      content: |
        [Unit]
        Description=My app

        [Service]
        ExecStart=/opt/myapp/bin/myapp

        [Install]
        WantedBy=multi-user.target
      mode: "0644"
      owner: root
      group: root
    notify: [restart_app]

  - id: app_service
    type: service
    with:
      name: myapp.service
      state: running
      enabled: true
    depends_on: [app_unit]

handlers:
  - id: restart_app
    service: myapp.service
    action: restart
```

`systemctl daemon-reload` は Sinter が実行するため、そのための `command`
リソースは不要です。ユニットファイルが変更されたので、`service` リソースが
判断する前にマネージャが reload されます。ハンドラが実行される前にもマネージャの
状態は確認されますが、新しい変更またはマネージャの古い状態がある場合にだけ再度
reload されます。同期済みの同じ変更では 2 回目の reload は行われません。
`depends_on` でユニットファイルをサービスより前に置いています。Sinter は
リソースの順序を並べ替えないためです。reload はユニット定義を読み直すだけで、
変更したユニットファイルを稼働中のプロセスに反映するのは `restart` ハンドラ
です。何も変更がなければ、2 回目の apply では reload も restart も行われません。
[service](/ja/reference/resources/service/#マネージャの自動同期)を参照して
ください。

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

完全なスキーマは[レシピフォーマット リファレンス](/ja/reference/recipe-format/)と
[リソースリファレンス](/ja/reference/resources/)を参照してください。

:::note[公式レシピコレクション]
キュレーションされたレシピコレクション（例えば `linux-baseline`
セット）は将来のプロダクト改善であり、まだ存在しません。このページは
v1.1.3 が実装しているものだけを記述しています。
:::
