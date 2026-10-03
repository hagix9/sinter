---
title: user
description: ローカルの Linux ユーザーを存在（または不在）させ、uid・プライマリグループ・シェル・ホーム記録・補助グループを宣言する。
---

:::caution[未リリース]
`group` と `user` は v1.1.3 より後の `main` ブランチにあります。v1.1.3 の
リリースバイナリには**含まれません**。次のリリースで提供されます。
:::

**目的:** **ローカル**の Linux ユーザー（`/etc/passwd`）を宣言する。存在
（`present`）または不在（`absent`）、そして指定した項目 — uid、プライマリ
グループ、シェル、ホームディレクトリの記録、補助グループ — だけを対象と
します。指定しない項目は変更も監査もされません。

## 書式

```yaml
- id: app_group
  type: group
  with:
    name: app
    gid: 990
    system: true

- id: app_user
  type: user
  depends_on: [app_group]
  with:
    name: app
    uid: 990
    group: app
    groups: [systemd-journal]
    shell: /usr/sbin/nologin
    home: /var/lib/app
    system: true

- id: app_state
  type: directory
  depends_on: [app_user]
  with:
    path: /var/lib/app
    owner: app
    group: app
    mode: "0750"
```

## パラメータ

| パラメータ | 必須 | 型 | デフォルト | 説明 |
|-----------|------|-----|-----------|------|
| `name` | はい | string | — | ユーザー名。静的。`[a-z_][a-z0-9_-]*`、最大 32 文字。 |
| `state` | いいえ | string | `present` | `present` または `absent`。 |
| `uid` | いいえ | integer | 管理しない | 必須の uid（1〜4294967294）。`0` は不可。 |
| `group` | いいえ | string | 管理しない | プライマリグループ（**名前**で指定）。事前に存在している必要があります（依存関係を参照）。 |
| `groups` | いいえ | string のリスト | 管理しない | 補助グループ（名前）。**追加のみ**: ユーザーをこれらに追加し、どのグループからも削除しません。プライマリグループを重複して指定できません。 |
| `shell` | いいえ | string | 管理しない | ログインシェルの絶対パス（`/usr/sbin/nologin`）。`/etc/shells` との照合は行いません。 |
| `home` | いいえ | string | 管理しない | ホームディレクトリとして記録する絶対パス。**記録のみ**を設定し、作成も移動も行いません。 |
| `create_home` | いいえ | boolean | `false` | ホームディレクトリを作成（`useradd -m`）。作成時のみ有効。`false` のときは `-M` を明示的に渡します。 |
| `system` | いいえ | boolean | `false` | システムユーザーとして作成（`useradd --system`）。作成時のみ有効で、監査も後からの変更もしません。 |

未知のフィールドはスキーマエラーです。パスワード、ロック、有効期限、SSH 鍵、
`move_home`、`remove_home`、`force`、`non_unique` のフィールドはありません。
これらはこのリソースの対象外です。

項目を宣言しない場合、作成時にはディストリビューション既定の `useradd` が
適用されます（たとえば `group` を省略すると同名のプライベートグループ。同名のグループがすでにある場合、または `group` の依存先が作る場合は、拒否して `group:` の宣言を求めます）。
ホームディレクトリ自体は [`directory`](/ja/reference/resources/directory/)
リソースで管理してください。

## 期待される動作

- **ローカルのみ。** ユーザーは `getent -s files passwd` で観測します。別の
  ID ソースだけが提供するユーザーは**エラー**です。それを覆い隠すローカル
  ユーザーを作ることはありません。`group`/`groups` に指定したグループも同様
  です。
- `present` でユーザーがいない → `useradd` を 1 回
  （`[--system] [-u uid] [-g group] [-G g1,g2] [-s shell] [-d home] (-m|-M) name`）。
  別のローカルユーザーが使用中の `uid` での作成は拒否されます。
- `present` でユーザーがいる → 最大 1 回の `usermod`
  （`-g`、`-s`、`-d`、足りないグループだけの `-a -G`）。`-m` は渡さないため、
  **ホームディレクトリは移動しません**。
- **既存ユーザーの uid 不一致は拒否**され、修復されません（`usermod -u` は
  ホーム外のファイルの所有者を直しません）。`audit` は `uid` の `DRIFT` を
  報告します。
- 補助グループのメンバーシップは**追加のみ**です。すでに所属しているグループ
  や宣言していないグループには触れません。完全一致（exact）には対応して
  いません。
- `absent` でユーザーがいる → `-r` も `-f` もなしの `userdel name`。ホーム
  ディレクトリとメールスプールは残り、その uid が所有するファイルも残ります
  （結果に明記されます。ファイルシステムは検索しません）。ディストリ
  ビューションの `userdel` が同名のプライベートグループも削除した場合は、
  その旨が結果に記載されます。`root`、uid 0、この実行が使うアカウント、
  セッションを実行・接続しているアカウントは拒否されます。実行中のプロセスが
  あるユーザーでは `userdel`/`usermod` が失敗し、失敗として報告されます。

## 依存関係

依存関係は明示的です。推測は行いません。

- `group`/`groups` が `group` リソースで作られるグループを指す場合、その
  リソースを `depends_on` に挙げる必要があります。`plan` では、そのような
  ユーザーは失敗せず**保留**（apply まで unknown）され、それに依存する
  すべても同様です。依存関係のないグループ欠落は、その旨を示す plan エラー
  です。
- `owner`/`group` が `user`/`group` リソースで作られるアカウントを指す
  `file`・`directory`・`template` は、そのリソースを自身の `depends_on` に
  挙げていれば `plan` で保留されます。`depends_on` がなければ、まだ存在しない
  所有者の plan は従来どおり未知のアカウントのエラーで失敗します。

## 冪等性

宣言したすべての項目に一致するユーザーは何も変更しません。収束後の 2 回目の
`apply` は `useradd`/`usermod`/`userdel` を実行しません。

## audit

`audit` は宣言した項目 — `state`、`uid`、`group`、`groups`、`shell`、`home` —
を個別にドリフトとして報告します。別の ID ソースだけが提供するアカウントは
`ERROR` です。`create_home` と `system` は作成時のオプションで、監査されません。

## 失敗時の動作

- アカウントコマンドの失敗は、変更の*可能性あり*・検証不明の失敗です。失敗した
  コマンドの後は再観測しません。終了コード 0 の場合は再観測し、宣言した状態に
  ならなければ検証失敗です。
- 拒否（番号振り直し、保護対象アカウント、使用中の ID、グループ欠落、外部
  提供のアカウント）はコマンド実行前に行われ、`plan` では plan エラーです。
- 失敗したユーザーに依存するリソースは実行されません。

## プラットフォームに関する補足

`/usr/sbin/useradd`、`usermod`、`userdel` と `getent` を argv のみ・シェルなしで
使います。Ubuntu 24.04 / 26.04、Rocky Linux・RHEL・AlmaLinux 9 / 10 の実機で
の動作は実 OS 受入検証待ちです。

## 関連

[group](/ja/reference/resources/group/) ·
[directory](/ja/reference/resources/directory/) ·
[リソース](/ja/concepts/resources/)
