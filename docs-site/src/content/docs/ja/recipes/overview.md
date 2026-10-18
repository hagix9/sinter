---
title: レシピ概要
description: Sinter v1.5.2 がサポートする機能で構成されたレシピ例。
---

以下の例はすべて v1.5.2 に実装されたリソースタイプとフィールドのみを
使います。
リソースタイプはプラットフォーム中立で、Sinter はターゲットに応じて `apt` か `dnf` を
選びます。ただし、パッケージ名やサービス名は Ubuntu と RHEL 系で同じとは限りません
（例: `apache2` / `httpd`）。そのようなリソースは、プラットフォーム条件付きの例のように、
`facts.os.family` の `when` で選んでください。

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
version: 1

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
    depends_on: [probe]   # register を読めるのは直接依存するリソースだけ
    when: "registers.probe_result.exit_code == 0"
    with:
      path: /etc/myapp/confirmed
      content: "ready\n"
```

完全なスキーマは[レシピフォーマット リファレンス](/ja/reference/recipe-format/)と
[リソースリファレンス](/ja/reference/resources/)を参照してください。

## RHEL 系のレシピ（v1.5.1）

Rocky Linux / RHEL 8、9、10 向けの完成したレシピは、リポジトリの
[`examples/recipes/`](https://github.com/hagix9/sinter/tree/main/examples/recipes) にあります。各ファイルの冒頭に説明があります。リリースごとの
分岐には `facts.os.version_major` を使い、v1.5.1 の検証で Rocky Linux 8.10、9.8、
10.2 で実測しました。

| ファイル | 内容 |
|----------|------|
| `python-el8.yaml` | EL8 の Python 3.6、3.11（+ pip）、3.12 を実際のパッケージ名で導入 |
| `postgresql-os.yaml` | OS の PostgreSQL 16（EL8 / EL9 は stream `postgresql:16`）、検証付きの `postgresql.conf` / drop-in（`--config-file={{ staged }}`）、SCRAM の `pg_hba.conf`、`postgresql_role` |
| `postgresql-pgdg17.yaml` | PGDG の PostgreSQL 17。指紋を照合して固定した鍵と、リポジトリのファイル（`gpgcheck` / `repo_gpgcheck` を有効） |
| `epel-crb.yaml` | EPEL と CRB / PowerTools、それぞれのパッケージ。2 回目の apply は変更なし |
| `signed-repo.yaml` | 任意の署名付き RPM リポジトリ（鍵のファイル、リポジトリのファイル、パッケージ） |
| `apache-htpasswd.yaml` | Basic 認証付きの httpd。パッケージが作る `apache` アカウントを先に宣言し、htpasswd はシークレット、設定ファイルは `httpd -t` で検証 |

## OpenStack 2026.1 All-in-One

[`examples/openstack/`](https://github.com/hagix9/sinter/tree/main/examples/openstack) は、1 台の Rocky Linux 10.2 に
OpenStack 2026.1 を構築します（検証・デモ用の構成で、本番向けの安全強化はしていません）。
[OpenStack のチュートリアル](/ja/tutorials/openstack-aio/overview/)で、2026-10-17 の実機受入のコマンドを使って
手順ごとに説明しています。

:::note[公式レシピコレクション]
キュレーションされたレシピコレクション（例えば `linux-baseline`
セット）は将来のプロダクト改善であり、まだ存在しません。このページは
v1.5.2 が実装しているものだけを記述しています。
:::
