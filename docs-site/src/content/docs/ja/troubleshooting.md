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

`--sudo` は、すべてのコマンドを非対話の `sudo -n -u root -- …` として送ります。
ターゲットユーザがパスワードなしで root としてコマンドを実行できることを確認して
ください（`sudo -n -u root true`）。ターゲットユーザがすでに root なら、sudo を
使わずに直接実行します（sudo は不要です）。
sudo での最初のコマンドが失敗すると、接続時のエラーが原因を示します。sudo が
導入されていない、パスワードが必要（sudo 1.9 は、ルールの無いユーザーや root を
許さないルールでもこう表示します）、sudoers がユーザーを拒否している、または
Sinter が原因を特定できない、のいずれかです。
Sinter はパーミッション失敗を昇格してリトライすることはありません。
失敗は失敗のままです。

**plan の `needs root`**

ターゲットユーザが root でなく、`--sudo` も指定していないとき、plan は root にしか
できない変更（パッケージ、ユーザー、グループ、ユーザー自身の領域の外のファイル）に
`needs root:` の注記を付けます。注記だけです。plan は sudo を実行も確認もせず、
状態も変わりません。apply は、root で接続するか `--sudo` を加えない限り失敗します。

## プラットフォーム検出

**`package resources require a supported target platform`**

ターゲットの `/etc/os-release` が対応プラットフォームとして識別
されませんでした。対応: Ubuntu 24.04 / 26.04 LTS amd64（apt）、
Rocky Linux 9 / 10、RHEL 9 / 10、AlmaLinux 9 / 10 x86_64（dnf）。
Oracle LinuxはRHEL系として認識されます（dnf）が、受入検証は未実施です。

## リソースの失敗

**`parent path` / シンボリックリンクのエラー**

ファイルシステムの変更には信頼できる親パスが必要です。予期しない
シンボリックリンク、スティッキーな共有ディレクトリでないグループ/その他
書き込み可能な親、第三のアカウントが所有する親は変更前に拒否されます。
`/tmp` や `/var/tmp` のようなスティッキーで root 所有のディレクトリは信頼され、
root として実行する場合は非特権アカウント自身のディレクトリ配下のパスも
許容されます。[file § 信頼境界](/ja/reference/resources/file/#信頼境界)を参照してください。

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

インストールは、ターゲットの dnf メタデータのプライベートなスナップショット
（`/var/tmp/sinter-dnf.*`、モード 0700）に対して cache-only で実行され、
スナップショットが live cache を削除・コピーすることはありません。スナップショットは
有効なすべてのリポジトリの dnf メタデータキャッシュが完全である必要があります。
有効なリポジトリのメタデータが未キャッシュの場合（`dnf makecache` を一度も実行して
いないホストや、直前に追加したリポジトリなど）、Sinter はターゲット自身の dnf
メタデータキャッシュを一度だけ更新し（未キャッシュのメタデータのみ。キャッシュ済みは
そのまま）、スナップショットを検証し直します。手動での準備は不要です。それでも
メタデータを確立できない場合は、パッケージを変更する前に fail-closed になります。
live cache にダウンロード済みのパッケージをトランザクションのペイロードと誤認しなく
なりました。スナップショットは、失敗を含めて結果が確定したときには必ず削除されます。
意図して残すのは 1 つの場合だけです。導入そのものの完了が不明なとき（timeout や接続の
切断。`indeterminate` と報告されます）は、dnf がまだ動いている可能性があるので、Sinter は
ターゲットに何も送らず、`/var/tmp/sinter-dnf.*` をそのまま残します。`dnf` のプロセスが
動いていないことを確かめてから、そのディレクトリを削除して、もう一度 apply してください。
それ以外の結果の後に残っている場合はバグです。[報告](/ja/contributing/#バグの報告)してください。

**dnf が導入を拒否した理由**（v1.5.1）

理由には dnf が報告した原因が表示され、何も導入されていません。

| 理由 | 対処 |
|------|------|
| `… is not a package name: dnf resolves it through a provides match to package X` | `name: X` と宣言してください（EL8 では `python3` → `python36`、`python311` → `python3.11`）。 |
| `no package named … is installed, but dnf reports the request already satisfied by installed package X` | その名前は導入済みの `X` が provides しています。`name: X` と宣言してください。 |
| `dnf found no package named …` | 名前と、そのパッケージを提供するリポジトリが有効かを確認してください。 |
| `dnf cannot resolve the dependencies of …: nothing provides …` | 依存を提供するリポジトリを有効にしてください（EPEL のパッケージでは CRB / PowerTools が多い）。 |
| `dnf refused a package signature … (GPG check FAILED …)` | 署名が無い、またはリポジトリの `gpgkey` が一致しません。鍵のファイルを直してください。`gpgcheck` を無効にしないでください。 |
| `dnf could not download the metadata of repository <id> …` | そのリポジトリに到達できないか、設定が誤っています。有効なリポジトリはすべて使える必要があります。 |
| `… bytes of unrecognized dnf error output withheld` | ターゲットで同じ導入を素の `dnf` で実行し、メッセージを確認してください。 |

[package の「dnf が拒否した理由」](/ja/reference/resources/package/#dnf-が拒否した理由dnf) も参照してください。

**plan で `unknown group: apache`（またはユーザー）**

そのアカウントはパッケージの scriptlet が作るので、plan の時点では存在しません。
パッケージより前に、パッケージと同じ属性（`apache` は uid / gid 48、home
`/usr/share/httpd`、shell `/sbin/nologin`）で `group` / `user` を宣言してください。
plan はそれに依存するものを遅延として扱い、scriptlet は宣言したアカウントを
そのまま使います。`examples/recipes/apache-htpasswd.yaml` を参照してください。

**`postgresql_role` が失敗する**

- `postgresql_role needs root` → `--sudo` を使ってください（psql はクラスタの
  所有者として実行します）。
- `cannot observe PostgreSQL role …: psql exited 2` → サーバーが動いていないか、
  `psql` / `port` が別のものを指しています（PGDG では `psql: /usr/pgsql-17/bin/psql`）。
- `could not be verified to keep statements out of the server log … not sent` →
  セッションでログの設定を変更または確認できませんでした。パスワードの verifier を
  含むものは何も送っていません。

## 詳細を得るには

- `--verbose` でリソースごとの詳細
- `--format json` で機械可読な結果
