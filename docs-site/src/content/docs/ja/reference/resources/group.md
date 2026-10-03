---
title: group
description: ローカルの Linux グループを存在（または不在）させ、必要なら gid を固定する。
---

:::caution[未リリース]
`group` と `user` は v1.1.3 より後の `main` ブランチにあります。v1.1.3 の
リリースバイナリには**含まれません**。次のリリースで提供されます。
:::

**目的:** **ローカル**の Linux グループ（`/etc/group`）を宣言する。
存在（`present`）または不在（`absent`）、および任意の固定 `gid`。ほかの
リソースと同様に plan・apply・audit の対象になります。

## 書式

```yaml
- id: app_group
  type: group
  with:
    name: app
    gid: 990
    system: true
```

## パラメータ

| パラメータ | 必須 | 型 | デフォルト | 説明 |
|-----------|------|-----|-----------|------|
| `name` | はい | string | — | グループ名。静的（`vars` や `item` は使用可）。`[a-z_][a-z0-9_-]*`、最大 32 文字。 |
| `state` | いいえ | string | `present` | `present` または `absent`。 |
| `gid` | いいえ | integer | 管理しない | 必須の gid（1〜4294967294）。`0` は不可。 |
| `system` | いいえ | boolean | `false` | システムグループとして作成（`groupadd --system`）。作成時のみ有効で、監査も後からの変更もしません。 |

未知のフィールドはスキーマエラーです。`members`、`password`、`force`
フィールドはありません。

## 期待される動作

- **ローカルのみ。** グループは `getent -s files group` で観測します。別の
  ID ソース（LDAP、SSSD、NIS）だけが提供するグループは**エラー**です。それを
  覆い隠すローカルグループを作ることはありません。
- `present` でグループがない → `groupadd [--system] [-g gid] name`。
- `present` でグループがある → 何も変更しません。宣言した `gid` が既存の
  gid と異なる場合は**拒否**されます（plan エラー / apply 失敗）。`audit` は
  `gid` の `DRIFT` を報告します。既存グループの番号振り直しは行いません
  （所有ファイルが孤立するため）。
- 別のローカルグループが使用中の `gid` での作成は、何も実行する前に拒否
  されます。
- `absent` でグループがある → `groupdel name`（force なし）。root グループ、
  この実行が使うグループ、いずれかのローカルユーザーの**プライマリ**グループ
  である場合は拒否されます（該当ユーザーが示されます）。その gid が所有する
  ファイルには触れません。
- メンバーシップは [`user`](/ja/reference/resources/user/) リソースの
  `groups` で管理し、ここでは扱いません。

## 冪等性

すでに一致している（名前、および宣言した場合は `gid`）グループは何も変更
しません。

## plan と audit

- `plan` は観測のみで、作成や削除を変更として報告します。
- `group` が、`depends_on` に挙げた `group` リソースで作られるグループ名の
  場合、その `file`・`directory`・`template` は plan を失敗させず**保留**
  （apply まで unknown）されます。推測は行いません。`depends_on` がなければ、
  未知のグループによる plan エラーのままです。
- `audit` は `state` と `gid` のドリフトを報告します。外部の ID ソースが
  提供するグループは `ERROR` です。

## 失敗時の動作

- `groupadd`/`groupdel` の失敗は、変更の*可能性あり*・検証不明の失敗です。
  失敗したコマンドの後は再観測しません。終了コード 0 の場合は再観測し、
  宣言した状態にならなければ検証失敗です。
- 失敗したグループに依存するリソースは実行されません。

## プラットフォームに関する補足

Ubuntu 24.04 / 26.04、Rocky Linux・RHEL・AlmaLinux 9 / 10 で
`/usr/sbin/groupadd`、`/usr/sbin/groupdel`、`getent` を使います。各ディストリ
ビューションの実機での動作は実 OS 受入検証待ちです。

## 関連

[user](/ja/reference/resources/user/) ·
[リソース](/ja/concepts/resources/)
