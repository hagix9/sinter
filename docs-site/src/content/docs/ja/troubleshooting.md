---
title: トラブルシューティング
description: よくある Sinter の失敗とその意味。
---

## 終了コード

| コード | 意味 | 典型的な原因 |
|--------|------|--------------|
| 0 | 成功 | audit: DRIFT も ERROR もなし — `NOT_AUDITABLE`/`NOT_APPLICABLE` のリソースが存在してもよい |
| 2 | バリデーション/スキーマエラー | レシピの構文誤り、未知のフィールド、不正な値 |
| 3 | 接続/capability/セキュリティエラー | SSH、ホスト鍵、非対応プラットフォーム |
| 4 | plan 未完了 | plan を安全に生成できない |
| 5 | apply 失敗 | リソースが失敗した |
| 6 | apply indeterminate / audit の ERROR | apply: ディスパッチ後のタイムアウト、応答の喪失、シグナルの不確実性。audit: 1 件以上の ERROR — エラーは DRIFT より優先 |
| 7 | audit の DRIFT | 1 件以上の DRIFT、ERROR なし |

## SSH / known_hosts

**`unknown host key` / `host key changed`**

Sinter は自動登録しません。対処: 選択された `known_hosts` ファイル
（デフォルト `~/.ssh/known_hosts`）に正しい鍵を追加するか、
`--known-hosts <path>` を渡してください。

**デフォルト以外のポートが拒否される**

ポート 22 はポートなしの `host` エントリを使います。それ以外のすべての
ポートには `[host]:port` が必要です。ポートなしのエントリは
デフォルト以外のポートを認可しません。

**ハッシュ化された known_hosts**

ハッシュ化された（`|1|…`）エントリに対応しています。ハッシュ化された
ホストが未知と報告される場合は、同じアイデンティティ（ポート 22 なら
`host`、それ以外は `[host]:port`、または設定された `HostKeyAlias`）で
記録されているか確認してください。

**ホストに `ProxyJump` / `ProxyCommand` が設定されている**

Sinter 内蔵の SSH トランスポートは踏み台を使えません。直接到達できる
アドレスに接続するか、`--no-ssh-config` で OpenSSH の設定を無視して
ください（その場合は直接接続します）。

**`SSH authentication failed for user@host`**

ホスト鍵の検証には成功しましたが、鍵が受け付けられませんでした。鍵が
利用可能か確認してください: 鍵を保持する ssh-agent、明示的な `--identity
<path>`、OpenSSH 設定の `IdentityFile`、またはデフォルトの
`~/.ssh/id_ed25519` / `id_ecdsa` / `id_rsa`。パスフレーズ付きの鍵は
ssh-agent 経由でのみ使えます（先に `ssh-add` してください）。対応する
公開鍵がターゲットユーザーとしてあらかじめ許可されている必要があります。
Sinter が鍵をプロビジョニングすることはありません。（これは上記のホスト鍵
チェックとは別のものです。）

## 権限昇格

**`sudo` の失敗**

`--sudo` は非対話の `sudo -n` を使います。ターゲットユーザが
パスワードなしの sudo を持つことを確認してください（`sudo -n true`）。
Sinter はパーミッション失敗を昇格してリトライすることはありません。
失敗は失敗のままです。

## プラットフォーム検出

**`package resources require a supported target platform`**

ターゲットの `/etc/os-release` が対応プラットフォームとして識別
されませんでした。対応: Ubuntu 24.04 / 26.04 LTS amd64（apt）、
Rocky Linux 9 / 10、RHEL 9 / 10、AlmaLinux 9 / 10 x86_64（dnf）。
Oracle LinuxはRHEL系として認識されます（dnf）が、受入検証は未実施です。

## リソースの失敗

**`parent path` / シンボリックリンクのエラー**

ファイルシステムの変更には信頼できる親パスが必要です。予期しない
シンボリックリンクや安全でない親（`/tmp` 直下など）は拒否されます。
`path` を信頼できる場所に向けてください。

**`service unit ... was not found`**

ユニットがターゲット上に存在しません。先にパッケージをインストール
してください（`depends_on`）。またはユニット名を確認してください。

**`daemon-reload` の失敗（終了コード 5）**

管理対象のユニットファイル、drop-in、alias リンク、`system.conf` が変更された場合、
またはユニットが `NeedDaemonReload=yes` を報告した場合、Sinter は systemd
システムマネージャを自動的に reload します。`systemctl daemon-reload` が
非ゼロで終了すると実行は失敗します。依存する service リソースやハンドラは何も
行わず、先行するファイルの変更は `changed` のまま残り（ロールバックは
されません）、同じ実行内で reload が再試行されることもありません。報告された
理由を確認してください（systemd のレート制限 `ReloadLimit*`、認可、壊れた
ユニットファイルがよくある原因です）。修正してから再度 apply してください。
タイムアウトまたは応答を失った reload は indeterminate（終了コード 6）として
報告されます。再適用の前にマネージャの状態を調べてください。

**reload の後も `NeedDaemonReload` が `yes` のまま（"unresolved"）**

Sinter は原因ごとに 1 回だけ reload し、ループしません。reload の後もユニットが
`NeedDaemonReload=yes` を報告する場合、Sinter の外部で何かがユニットを変更し
続けている（またはユニットロードパス外のフラグメントが関与している）ため、
apply は失敗します。`systemctl show -p FragmentPath,DropInPaths <unit>` と
`systemctl status <unit>` でユニットのファイルを確認してください。

**`UnitPath` を読み取れない、または解析できない**

管理対象のパスがユニット、drop-in、リンクの入力に見える場合、Sinter は
`systemctl show --property=UnitPath` でマネージャのロードパスを取得します。これが
失敗すると、そのリソースは変更の前に失敗します（`plan` では plan エラー、
`audit` では `ERROR`）。Sinter がパスを推測することはありません。systemd が
動作していること、接続ユーザー（`--sudo` を使う場合はそれも含む）で
`systemctl` が使えることを確認してください。

**停止した実行の後でマネージャが未同期**

管理対象のユニット入力が変更された後に apply が途中で停止した場合（リソースまたは
ハンドラの失敗）、新たな reload は開始されず、レポートには reload が実行
**されなかった**ことが記載されます。再度 apply するか、手動で
`systemctl daemon-reload` を実行してください。Sinter は実行をまたぐジャーナルを
持たないため、後の apply で reload が行われるのは、`NeedDaemonReload=yes` を
観測した場合か、新たな変更があった場合だけです。`sinter audit` を実行すると、
保留中の reload が `manager_reload` ドリフトとして表示されます。

**Indeterminate な apply（終了コード 6）**

Sinter が変更が完了したか確認できませんでした。闇雲にリトライしないで
ください。まずターゲットの状態を調べ、安全であれば再適用してください。

## dnf 固有

**RHEL 系ターゲットでのメタデータ/キャッシュの失敗**

インストールは `/var/tmp/sinter-dnf.*` 配下のプライベートメタデータ
スナップショット（モード 0700）を使います。スナップショットの残骸は
実行後に残らないはずです。残っている場合は
[バグとして報告](/ja/contributing/#バグの報告)してください。

## 詳細を得るには

- `--verbose` でリソースごとの詳細
- `--format json` で機械可読な結果
