---
title: systemd_timer
description: systemd タイマーのユニットファイルと、その有効化・起動状態を管理する。
---

**目的:** system manager の systemd タイマーを 1 つ宣言する。ユニットファイル
`/etc/systemd/system/<name>.timer` と、必要ならタイマーを有効にするか・起動するかを管理する。

## 書式

```yaml
- id: backup-timer
  type: systemd_timer
  with:
    name: backup
    on_calendar: "*-*-* 03:00:00"
    persistent: true
    randomized_delay_sec: 10min
    state: running
    enabled: true
```

## パラメータ

| パラメータ | 必須 | 型 | デフォルト | 説明 |
|-----------|------|-----|-----------|------|
| `name` | はい | string | — | `.timer` を除いたタイマー名。`[A-Za-z0-9:_.-]`、1〜200 バイト、`.` や `-` で始めない。テンプレート（`@`）は使えない。 |
| `unit` | いいえ | string | `<name>.service` | タイマーが起動するユニット（`Unit=`）。`.timer` 以外のユニット接尾辞で終わること。 |
| `on_calendar` | いいえ | string またはリスト | — | `OnCalendar=` の式。1 つにつき 1 行。 |
| `on_boot_sec` | いいえ | string | — | `OnBootSec=` の時間。 |
| `on_unit_active_sec` | いいえ | string | — | `OnUnitActiveSec=` の時間。 |
| `persistent` | いいえ | boolean | — | `Persistent=`。`on_calendar` が必要。 |
| `accuracy_sec` | いいえ | string | — | `AccuracySec=` の時間。 |
| `randomized_delay_sec` | いいえ | string | — | `RandomizedDelaySec=` の時間。 |
| `description` | いいえ | string | `Sinter timer <name>` | `Description=`。 |
| `state` | いいえ | string | — | `running`、`stopped`、`absent` のいずれか。 |
| `enabled` | いいえ | boolean | — | タイマーを有効にするかどうか。 |

- `on_calendar`、`on_boot_sec`、`on_unit_active_sec` の少なくとも 1 つが必要です。ただし `state: absent` のときは `name` だけを指定できます。
- `name` と `unit` には変数を使えますが、fact と register は使えません。
- 時間は、整数（秒）か、`5min`、`1h 30m`、`2.5s` のような並びです。単位は `us`、`ms`、`s`/`sec`、`m`/`min`、`h`/`hr`、`d`/`day`、`w`/`week`、`M`/`month`、`y`/`year`（と長い形）。systemd の時間の文法のそれ以外は受け付けません。
- `on_calendar` と `description` は、`\` と `%` を含まず、前後に空白の無い、印字可能な ASCII です（`on_calendar` は `-` で始めない）。指定子や行の継続によって、書かれる内容が変わることはありません。
- `state` と `enabled` のどちらも無ければ、ユニットファイルだけを管理します。

## 期待される動作

- ユニットファイルは決まった形で書かれ（所有者 `root:root`、mode `0644`）、[`file`](/ja/reference/resources/file/) リソースと同じコードで扱われます（内容の比較、バックアップ、安全な置き換え）。最後は必ず `[Install]` の `WantedBy=timers.target` です。
- ユニットファイルの書き込みは manager への入力なので、タイマーを有効化・起動する前に、Sinter の[マネージャの自動同期](/ja/reference/resources/service/#マネージャの自動同期)が `systemctl daemon-reload` を実行します。動作中のタイマーの内容を変えると、manager を reload しますが、タイマーの restart、stop、start はしません。
- 有効化、無効化、起動、停止は、ユニット `<name>.timer` に対して [`service`](/ja/reference/resources/service/) リソースと同じように動きます。
- `state: running` か `enabled: true` を指定したときは、reload の後に起動対象のユニットが存在しなければなりません。無ければタイマーを有効化も起動もせず、リソースは失敗します（書いたユニットファイルは変更として報告します）。
- `state: absent` は、タイマーを停止・無効化し、ユニットファイルを削除し、manager を reload し、ユニットが無くなったことを確かめます。
- 何かを変える前に、すべての `on_calendar` の式を対象の上で `systemd-analyze calendar <expr>` によって検査します。不正な式や、`systemd-analyze` の無い対象では、リソースは失敗します。`on_boot_sec`/`on_unit_active_sec` だけの `systemd_timer` はこの検査をしません。
- 次の場合は、何も変えずに拒否します（plan、apply、audit とも）: mask されたタイマー。ユニットファイルが `/etc/systemd/system` の外にあるタイマー（ベンダーのユニットなど。Sinter は上書きも削除もしません）。drop-in（`<name>.timer.d/`）のあるタイマー（Sinter は drop-in を管理しません）。
- 同じパスの file、template、link リソースや、同じ名前の 2 つ目の `systemd_timer` は、検証のエラーです。
- 変更は、他のリソースと同じように handler に通知されます。
- audit は、内容、有効化、状態、起動対象のユニットが無いことを drift として報告し、上の拒否はエラーとして報告します。
- `--user` の manager には対応していません。
- MCP ではまだ使えません。対象の上での calendar の検査が、サポート対象のすべての OS で読み取り専用だと確かめられていないためです。

## `service` との関係

[`service`](/ja/reference/resources/service/) リソースでも、既にある `<name>.timer` ユニット（たとえば `file` リソースで書いたもの）を有効化・起動できます。`systemd_timer` は、ユニットファイル、その検査、削除を加えます。

## 例

```yaml
version: 1
resources:
  - id: backup-service
    type: file
    with:
      path: /etc/systemd/system/backup.service
      content: |
        [Service]
        Type=oneshot
        ExecStart=/usr/local/bin/backup
  - id: backup-timer
    type: systemd_timer
    depends_on: [backup-service]
    with:
      name: backup
      on_calendar: daily
      persistent: true
      state: running
      enabled: true
```
