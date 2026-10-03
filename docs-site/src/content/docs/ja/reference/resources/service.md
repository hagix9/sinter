---
title: service
description: systemd サービスの起動状態と有効化を管理する。
---

**目的:** systemd ユニットが `running`/`stopped` および/または
`enabled`/`disabled` であることを保証する。

## 書式

```yaml
- id: sshd
  type: service
  with:
    name: sshd
    state: running
    enabled: true
```

## パラメータ

| パラメータ | 必須 | 型 | デフォルト | 説明 |
|-----------|------|-----|-----------|------|
| `name` | はい | string | — | systemd ユニット名。 |
| `state` | いいえ | string | — | `running` または `stopped`。 |
| `enabled` | いいえ | boolean | — | `true`/`false`。 |

`state` と `enabled` の少なくとも一方が必須です。

## 期待される動作

- `state: running` は必要に応じてユニットを起動します。`stopped` は
  停止します。
- `enabled: true`/`false` は起動時有効化を設定します。
- Ubuntu と RHEL 系を問わず、あらゆる systemd ターゲットで動作します。
- service リソースがユニットを観測する前に、必要であれば Sinter が
  systemd システムマネージャを同期します（`systemctl daemon-reload`）。
  詳細は[マネージャの自動同期](#マネージャの自動同期)を参照してください。
  その後ユニットを再観測し、start/stop/enable/disable の判断には
  その新しい状態だけを使います。
- 観測では `LoadState,ActiveState,UnitFileState,NeedDaemonReload` の
  4 プロパティだけを要求します。プロパティの欠落・重複・不正・途中切れ、
  非ゼロ終了、UTF-8 でない出力は失敗となり、`NeedDaemonReload=no` と
  解釈されることはありません。
- `enable`/`disable` は systemctl 自身の暗黙の reload をそのまま使います
  （Sinter は `--no-reload` を使いません）。enable/disable の後、`start` が
  まだ必要かを判断する前に、Sinter は再度観測します。

## マネージャの自動同期

必要な場合、Sinter はシステムマネージャに対して `systemctl daemon-reload`
を実行します。そのための `command` リソースを書く必要はありません。

**reload が必要になる場合**

- [`file`](/ja/reference/resources/file/)、
  [`template`](/ja/reference/resources/template/)、
  [`link`](/ja/reference/resources/link/) リソースが、systemd マネージャの
  入力を実際に変更した場合（作成・変更・削除、シンボリックリンクの
  作成/置換/削除）。対象は次のとおりです: ユニットファイル
  （`*.service`、`*.socket`、`*.target`、`*.timer`、`*.path`、`*.mount`、
  `*.automount`、`*.swap`、`*.slice`。`foo@.service` のようなテンプレートを含む）、
  drop-in（`<unit>.d/*.conf`、型全体の `service.d/*.conf`、
  プレフィックス `foo-.service.d/*.conf`）、alias/mask/`.wants`/`.requires`
  リンクのうち、マネージャ自身のユニットロードパスのルート直下にあるもの
  （Sinter は `systemctl show --property=UnitPath` で読み取り専用に取得し、
  パスを字句的に比較します。`/etc/systemd/system` を前提にしません）、
  またはシステムマネージャ設定 `/etc/systemd/system.conf` と
  `system.conf.d/*.conf`（`/etc`、`/run`、`/usr/lib`、`/usr/local/lib` の
  `systemd/` 配下）。
- 新しい観測で、レシピが使うユニット（`service` リソース、通知される
  ハンドラのサービス、単一のユニットを指す管理対象のユニットファイル/
  drop-in）について `NeedDaemonReload=yes` が報告された場合。

メタデータのみの変更（chmod/chown）、ディレクトリ、通常のアプリケーション
設定、`/etc/systemd/journald.conf`、`user.conf`、`/etc/systemd/user/...` などは
reload を引き起こしません。`UnitPath` の問い合わせは、管理対象パスのファイル名が
ユニット/drop-in/リンクの入力に見える場合にだけ行われます。それを実行または
解析できない場合、そのリソースは変更の**前**に失敗します（`plan` では
plan エラー）。Sinter が推測することはありません。

**reload が行われる場所**

1. `service` リソースが観測して判断する前（「すでに一致している」という
   早期 return の前）。
2. 通知された各ハンドラ（`restart`/`reload`）の実行前。
3. 成功した apply の最後。ファイルだけのユニット更新でも reload されます。

1 回の reload は、その時点で保留中のすべての変更をまとめて反映します。
ユニット A → サービス A → ユニット B → サービス B の順では、reload は 2 回
（消費側の境界ごとに 1 回）行われます。「1 回の実行につき最大 1 回」という
規則はありません。保留中の変更がなく `NeedDaemonReload=no` であれば reload は
行われません。そのため、変更のない 2 回目の apply では reload は発生せず、
通常の設定ファイルによる notify restart でも reload は発生しません。

Sinter はリソースの順序を並べ替えません。ユニットを作るリソースは
`depends_on` または宣言順で、使う側より前に置いてください。サービスより後ろに
ある生成側は、そのサービスをやり直しません。ただし最後の reload は行われます。

reload の後も `NeedDaemonReload=yes` のままであれば、apply は「unresolved」
として失敗します（リトライのループはありません。原因ごとに最大 1 回:
保留中の入力、観測された陳腐化）。

**`daemon-reload` は restart ではありません。** マネージャのユニット定義を
読み直すだけで、実行中のプロセスは古い設定のまま動き続けます。新しい
ユニットの内容を実行中のプロセスに反映するには、`restart` ハンドラ
（サービスが `ExecReload` をサポートする場合は `reload` ハンドラ）を
notify してください。マネージャの reload（`daemon-reload`）、
`systemctl restart foo`、`systemctl reload foo` は 3 つの別々の操作です。
ハンドラの順序は、マネージャ reload → 新しい観測 → ハンドラのアクション →
検証 です。

**パッケージ → サービス。** パッケージが変更されただけで apply が reload を
行うことはありません。サービスが明示的に依存している（`state: present`）
パッケージが*変更*され、それでもユニットが見つからない場合、Sinter は
探索のための reload をちょうど 1 回行って再観測します。それでも見つからなければ
失敗します（リトライなし）。

**制限事項**

- 管理対象はシステムマネージャのみです。ユーザーマネージャ
  （`systemctl --user`、`~/.config/systemd/user`、`/etc/systemd/user`、
  `user.conf`）は管理対象外で、Sinter が `--user` を使うことはありません。
  `daemon-reexec` も行いません。
- reload はシステムマネージャ全体に作用します。ディスク上の他の保留中の
  編集も読み込まれ、ジェネレータも再実行されます。サービスの再起動は
  行いません。
- systemd のレート制限（`ReloadLimit*`）や認可により reload が失敗する
  ことがあります。`system.conf` を reload しても、すべてのディレクティブが
  有効になるとは限りません。
- `NeedDaemonReload` は、同じまたは過去の mtime を持つ外部からの編集を
  検知できません。
- `UnitPath` のルートとのパス比較は字句的です。`/lib` と `/usr/lib` の
  ようなエイリアスは同一視されず、認識されないパスはそれだけでは reload を
  引き起こしません。優先度の高いルートに隠されたユニットファイルでも
  reload は行われます。ロードパス外からリンクされたフラグメントは
  `NeedDaemonReload` を通してのみ検知されます。
- 対応する各ディストリビューションでの実 OS 上の動作は、別途検証されます。

## plan と audit

`plan` は読み取り専用です。`daemon-reload`、enable/disable、
start/stop/restart/reload を実行することはありません。plan 内の先行リソースが
管理対象の systemd 入力を変更する場合、またはマネージャが現在そのユニットに
`NeedDaemonReload=yes` を報告している場合、サービスは unknown（`?`、
「deferred/unknown until manager synchronization at apply…」）として
報告されます。「変更なし」でも失敗でもありません。apply が行う reload は、
`manager_reloads` に別途一覧されます。

`audit` は読み取り専用で、reload は行いません。独立したドリフト次元
`manager_reload`（観測値 "daemon-reload pending (`NeedDaemonReload=yes`)"、
期待値 "manager synchronized"）を、active/enabled が一致していても
service に対して、また単一のユニットを指す管理対象のユニットファイルや
drop-in に対して報告します。これは content/mode/owner のドリフトや
state/enabled のドリフトとは別です。`NeedDaemonReload=yes` が修復済みと
扱われることはありません。`NeedDaemonReload=no` は限定的な観測です
（systemd は内容のハッシュではなく mtime/パスを比較します）。読み込まれている
定義がディスク上のバイト列と等しいことの証明にはなりません。単一のユニットに
対応付けられない管理対象の入力（テンプレート、型全体またはプレフィックスの
drop-in、`system.conf`）には、「manager consistency not verified…」という
注記が付きます。`NeedDaemonReload`/`UnitPath` を観測できない場合は観測エラー
（集約結果は `indeterminate`）となり、`no_drift` になることはありません。
`link` リソースには audit でマネージャの観点は付きません。

## 冪等性

完全に冪等です — すでに目的の状態にあるユニットは再起動も再有効化も
されず、すでに同期済みのマネージャが reload されることもありません。

## 失敗時の動作

- ユニットが見つからない → 失敗（`plan` では、まだ適用されていない
  パッケージに依存するサービスが deferred/unknown を報告することが
  あります）。
  見つからないユニットが `stopped` として扱われることはありません。
  そのため、ユニットを停止してからそのユニットファイルを削除するレシピは
  1 回目は成功しますが、再度 apply すると失敗します
  （「service unit … was not found」）。ユニットを廃止したら `service`
  リソースを外し、`state: absent` の `file` リソースを残してください。
- `masked` ユニットに `running` を要求 → 失敗。`static` ユニットに
  `enabled` → 失敗。
- 観測の失敗は失敗/indeterminate として報告され、変更として報告
  されることはありません。
- `daemon-reload` が非ゼロで終了 → 失敗（`apply_failed`）。依存する
  service リソースや通知されたハンドラは何も行わず（start/enable/restart なし）、
  先行して成功した file/template/link の結果は `changed` のまま残り、
  ロールバックはされず、同じ実行内で reload が再試行されることもありません。
- `daemon-reload` がタイムアウト、シグナルによる終了、または応答の喪失 →
  `indeterminate`。成功としても「変更なし」としても報告されません。
- reload は成功したが、その後の新しい観測が失敗 → reload は実行済み/changed
  としてレポートに残り、消費側は失敗します（検証失敗）。
- 先に停止した実行（リソースまたはハンドラの失敗）は、新たな reload を
  開始しません。管理対象の入力が変更されていた場合、レポートには reload が
  実行**されなかった**こと、およびマネージャが未同期であることが記載されます。
  再度 apply するか、手動で `systemctl daemon-reload` を実行してください。
  Sinter は実行をまたぐジャーナルを持たないため、以前の apply が reload の前に
  停止したことを覚えていられません。後の実行で reload が行われるのは、
  `NeedDaemonReload=yes` が観測された場合か、新たな変更があった場合だけです。

## プラットフォームに関する補足

ターゲットに systemd が必要です（すべての対応プラットフォーム）。

## 関連

[package](/ja/reference/resources/package/) ·
[handlers](/ja/concepts/recipes/)
