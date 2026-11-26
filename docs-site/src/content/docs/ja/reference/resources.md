---
title: リソースリファレンス
description: v1.15.0 に実装されているすべての組み込み Sinter リソースタイプ。
---

Sinter v1.15.0 は 12 の組み込みリソースタイプを実装しています（`postgresql_role` は v1.5.1 で追加、`systemd_timer` と `nm_connection` は v1.15.0 で追加）。v1.15.0 の後に `file_merge`、`dnf_repository`、`dnf_module`、`crypto_policy`、`sysctl`、`hostname`、`tuned` の 7 つを追加しましたが、**まだリリースには含まれていません**。[Resource Plugins](/ja/reference/resource-plugins/) で追加することもできます。以下の
パラメータはサポートされる完全なセットであり、未知の `with`
フィールドはスキーマエラーです。

| タイプ | 用途 | 主要パラメータ |
|--------|------|----------------|
| [file](/ja/reference/resources/file/) | 通常ファイルの内容とメタデータ | `path`、`state`、`content`/`source`、`owner`、`group`、`mode` |
| [directory](/ja/reference/resources/directory/) | ディレクトリの存在とメタデータ | `path`、`state`、`owner`、`group`、`mode` |
| [link](/ja/reference/resources/link/) | シンボリックリンク | `path`、`target`、`state` |
| [template](/ja/reference/resources/template/) | コントローラ側テンプレートのレンダリング | `path`、`source`、`vars`、`mode` |
| [command](/ja/reference/resources/command/) | 正確な argv によるプログラム実行 | `program`、`args`、`creates`/`removes`、`changed_when`、`register` |
| [package](/ja/reference/resources/package/) | パッケージのインストール/削除（apt/dnf） | `name`、`state` |
| [service](/ja/reference/resources/service/) | systemd の状態と有効化 | `name`、`state`、`enabled` |
| [systemd_timer](/ja/reference/resources/systemd_timer/) | systemd タイマーのユニットと有効化 | `name`、`on_calendar`、`on_boot_sec`、`state`、`enabled` |
| [nm_connection](/ja/reference/resources/nm_connection/) | NetworkManager の Ethernet プロファイル(v1.15.0 から) | `name`、`ifname`、`autoconnect`、`ipv4`、`ipv6`、`state`、`active` |
| [group](/ja/reference/resources/group/) | ローカル Linux グループ | `name`、`state`、`gid`、`system` |
| [user](/ja/reference/resources/user/) | ローカル Linux ユーザー | `name`、`state`、`uid`、`group`、`groups`、`shell`、`home`、`create_home`、`system`、`password_hash` |
| [file_merge](/ja/reference/resources/file_merge/) | 既存テキストファイルの一部（行、目印付きブロック、`key = value`）（未リリース） | `path`、`merge`、`line` / `marker`+`content` / `key`+`value`、`state`、`create` |
| [dnf_repository](/ja/reference/resources/dnf_repository/) | `/etc/yum.repos.d` のリポジトリ 1 セクション（未リリース） | `name`、`file`、`enabled`、`baseurl`、`gpgcheck`、`gpgkey`、`state` |
| [dnf_module](/ja/reference/resources/dnf_module/) | DNF 4 のモジュールストリームの状態（未リリース） | `name`、`stream`、`state` |
| [crypto_policy](/ja/reference/resources/crypto_policy/) | システム全体の暗号ポリシー（RHEL 系）（未リリース） | `policy`、`allow_weaker` |
| [sysctl](/ja/reference/resources/sysctl/) | カーネルパラメータ 1 つ: 実行中の値と永続設定（未リリース） | `name`、`value`、`state`、`runtime`、`persist` |
| [hostname](/ja/reference/resources/hostname/) | 静的ホスト名（未リリース） | `name` |
| [tuned](/ja/reference/resources/tuned/) | 選択中の TuneD プロファイル（未リリース） | `profile` / `recommended` / `state: off`、`verify` |
| [postgresql_role](/ja/reference/resources/postgresql_role/) | ローカルの PostgreSQL サーバーのロール（v1.5.1 から） | `name`、`state`、`login`、`superuser`、…、`connection_limit`、`password_verifier` |

## 共通の規約

- `path` 系パラメータは絶対パスです。親パスはあらかじめ存在し、
  信頼境界チェック（予期しないシンボリックリンクがないこと。`/tmp` や
  `/var/tmp` のようなスティッキーで root 所有の共有ディレクトリは許容され、
  root として実行する場合は非特権アカウント自身のディレクトリ配下のパスも
  許容されます）を通過する必要があります（[file § 信頼境界](/ja/reference/resources/file/#信頼境界)参照）。
- `mode` は常に引用符付きの 4 桁 8 進数文字列（`"0644"`）です。
- `state` はファイルシステム系リソースでは `present` がデフォルト
  です。`package` では明示的に必須です。
- 内容の公開はアトミック（rename）です。省略された既存のメタデータは
  保持されます。
- すべてのタイプは冪等です。収束済みのリソースは再適用しても
  何も変更しません。
