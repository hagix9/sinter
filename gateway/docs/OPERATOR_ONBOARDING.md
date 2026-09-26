# Sinter Plugin — 管理者向けオンボーディング Runbook

公開 Gateway の運用者が、新しい利用者を 1 人追加・案内・無効化するための手順です。
利用者向けの手順は ChatGPT Plugin ガイド（`docs-site/.../guides/chatgpt-plugin`）を参照してください。

現在の方式は **招待制（運用者が仲介）** です。
- 利用者のアカウント対応付け（Logto）と、bridge 用 registration token の発行は運用者が行います。
- セルフサービス登録はありません。
- 利用希望の正式な窓口は [Fulltrust お問い合わせフォーム](https://fulltrust.co.jp/contact/index.html) です。問い合わせにサーバー情報・credential・token が書かれていた場合は、その値を使わず、利用者に破棄・再発行を案内してください。
- registration token は 15 分で失効します。利用者が Sinter と sinter-bridge を用意し終えてから発行してください。

## 0. 全体像（誰が何をするか）

| # | 実施者 | 操作 | 手段 |
|---|---|---|---|
| 0 | 利用希望者 | お問い合わせ内容に「Sinter利用希望」と記載して連絡（サーバー情報・credential・token は書かない） | [Fulltrust お問い合わせフォーム](https://fulltrust.co.jp/contact/index.html)（正式な access request 窓口） |
| 1 | 運用者 | Logto にユーザーを作成し、`customData.sinter_account` を設定 | Logto Console（手動） |
| 2 | 運用者 | registration token を発行 | `sinter-gw-admin issue <account>` |
| 3 | 運用者 | サインイン情報と token を別経路で利用者へ渡す | 表示された handoff 文面 |
| 4 | 利用者 | Sinter と sinter-bridge を用意し、`sinter-bridge register`（1 回だけ） | 利用者ガイド |
| 5 | 利用者 | bridge を常駐（Linux は systemd user unit） | `gateway/contrib/systemd/` |
| 6 | 利用者 | ChatGPT にアプリを追加（MCP URL + OAuth）し、Logto でサインイン | ChatGPT |
| 7 | 運用者・利用者 | 疎通確認 | `sinter-gw-admin status <account>` と ChatGPT |

仕組みの要点（実装で確認済み）:
- **account の一致:** Gateway は、access token の `sinter_account` claim と一致する account の controller にだけ配送します。
  - この claim は Logto Custom JWT が `customData.sinter_account` から付与します。対応付けがない場合はトークン発行が拒否されます。
  - registration token を発行した account 名と、Logto の `customData.sinter_account` は **完全に一致** している必要があります。
- **registration token:** `reg_` + 256 bit のランダム値です。
  - 有効期限は **15 分** で、**1 回だけ** 使えます。
  - Gateway は SHA-256 だけを保存し、平文は発行時に 1 回だけ表示されます。
- **controller:** 1 account につき有効な controller（bridge）は 1 つです。登録済みの account に 2 つ目を登録すると 409 になります。
- **bridge credential:** `ctrlk_` + 64 hex です。
  - 利用者のマシンにのみ保存され、Gateway は SHA-256 だけを保存します。
  - 失効は `--revoke-controller` で行い、次の poll から即時に反映されます。

## 1. 事前準備（運用者のマシンで一度だけ）

1. `gcloud auth login` 済みで、Gateway VM に **IAP 経由** で SSH できること（`gcloud compute ssh <Gateway VM 名> --project <GCP project> --zone <zone> --tunnel-through-iap`）。
   - 本番では、インターネットからの直接 SSH（tcp/22）を firewall で遮断しています。Gateway VM の network tag に限定した 2 つのルールで実現しています。
     - IAP の送信元 `35.235.240.0/20` からの tcp/22 を許可（priority 900）
     - それ以外からの tcp/22 を拒否（priority 950）
   - IAP API（`iap.googleapis.com`）の有効化と、`roles/iap.tunnelResourceAccessor` が必要です（project owner は保有）。
   - VM 上の sudo はパスワード不要である必要があります。
   - IAP 経由の接続時に表示される NumPy の警告は無害です。
2. 設定ファイル `~/.config/sinter/gw-admin.env` を作成し、`chmod 600` にします。秘密情報は含みません。Git に入れないでください。

   ```sh
   SINTER_GW_ADMIN_TRANSPORT=gce
   SINTER_GW_ADMIN_GCE_PROJECT=<GCP project>
   SINTER_GW_ADMIN_GCE_ZONE=<zone>
   SINTER_GW_ADMIN_GCE_INSTANCE=<Gateway VM 名>
   SINTER_GW_ADMIN_GCE_IAP=1          # 本番は IAP 経由のみ（直接 SSH は遮断）
   SINTER_GW_ADMIN_PUBLIC_URL=https://<Gateway ホスト>
   ```

3. 動作確認（読み取りのみ）:

   ```sh
   gateway/scripts/sinter-gw-admin list
   ```

### 緊急時（IAP が使えない場合）

firewall は GCP の API で操作でき、SSH を必要としません。そのため、IAP が使えなくても管理不能にはなりません。緊急時は次の手順で、一時的に直接 SSH を戻します。

1. Gateway VM の tag を対象とする tcp/22 の拒否ルールを確認します。
   ```sh
   gcloud compute firewall-rules list --project <GCP project> --filter="targetTags:<gateway tag>"
   ```
2. 拒否ルールを削除します。直接 SSH は既存の `default-allow-ssh` で再び通るようになります。
3. 復旧後、同じ定義（tcp/22、`0.0.0.0/0`、priority 950、同じ tag）で拒否ルールを作り直します。
4. IAP 経由の SSH が成功することと、直接 SSH が拒否されることを、両方確認します。

`sinter-gw-admin` の動作:
- Gateway 既存の CLI（`sinter-gateway --issue-registration-token` / `--revoke-controller`）を、Gateway の service user として、Gateway の env を読み込んだ状態で実行します。
- 状態表示は identity DB を **読み取り専用**（SELECT のみ、`mode=ro`）で参照します。credential や token のハッシュは読みません。DB を直接編集することはありません。

## 2. 新規利用者を追加する

### 2.1 account 名を決める

- 形式は `[a-z0-9][a-z0-9._-]{1,62}` です（例: `acme-alice`）。スクリプトもこの形式を検証します。
- 利用者ごとに 1 つ使います。既存の account と重複しないよう、`sinter-gw-admin list` で確認してください。

### 2.2 Logto でユーザーを作成する（手動）

1. Logto Console → **User management** → **Add user**。username と初期パスワードを設定します（このテナントはセルフサインアップが無効です）。
2. 作成したユーザーの詳細画面 → **Custom data** に次を設定して保存します。

   ```json
   { "sinter_account": "<account>" }
   ```

3. 次の設定は変更しないでください。
   - Custom JWT スクリプト
   - API Resource `https://<Gateway ホスト>`
   - Dynamic app（CIMD）の Permissions（`profile` と `email` を許可済み）
   - Account center（Account API は **無効のまま**）。有効にすると、利用者が customData を書き換えられる可能性があります。

### 2.3 registration token を発行する

```sh
gateway/scripts/sinter-gw-admin issue --dry-run <account>   # 事前確認だけ（token は発行しない）
gateway/scripts/sinter-gw-admin issue <account>             # account 名の再入力を求められる
```

スクリプトの動作:
- 既存の active な controller がある場合は **中止** します（登録しても 409 になるため）。
- 未使用の token が残っている場合は注意を表示します。
- 確認入力が一致しなければ何もしません。
- 成功すると、利用者に渡す手順（handoff）と token を **1 回だけ** 表示します。token はどこにも保存されません。

## 3. 利用者に渡すもの

| 渡すもの | 経路 |
|---|---|
| Logto のサインイン情報（username と初期パスワード） | 経路 A |
| registration token（15 分以内に使用、1 回限り） | **経路 A とは別の** 経路 B（パスワード共有機能、別メッセージなど） |
| handoff 文面（Gateway URL、MCP URL、ガイド URL、register と起動のコマンド） | どちらでも可（秘密情報を含まない） |

- token をチケット・Git・共有ドキュメント・チャット履歴に残さないでください。
- `issue` の出力をファイルにリダイレクトしないでください。
- 15 分を過ぎた場合は、新しい token を発行するだけで構いません。古い token は自動的に失効します。

## 4. bridge が online になったことを確認する

```sh
gateway/scripts/sinter-gw-admin status <account>
```

| 表示 | 意味 |
|---|---|
| controllers に `<account> active` | 利用者の `register` が成功した |
| audit に `registration_token_consumed` と `controller_registered` | 同上（時刻付き） |
| Gateway log に `controller registered … account=<account>` | 登録時、または Gateway 再起動後の最初の poll |
| Gateway log に `mcp session created account=<account>` | ChatGPT から認証付きで利用された |

Gateway は account ごとの通常の poll を記録しません。**bridge が今 online であること** は、次のどちらかで確認します。

- 利用者側で、bridge のログに `bridge polling https://…/` が出ており、その後に `WARN` がないこと。
  - systemd の場合: `journalctl --user -u sinter-bridge`
- 手順 5 の ChatGPT での疎通確認。

## 5. ChatGPT から疎通確認する

1. 利用者が ChatGPT（プレビュー期間中は developer mode）でアプリを追加します。
   - MCP サーバーの URL: `https://<Gateway ホスト>/mcp`
   - 認証: OAuth
2. Logto のサインイン画面で、手順 2.2 のユーザーでサインインし、同意します。
3. 新しいチャットで「Sinter のバージョンを教えて」と聞くと、例えば `0.5.1` と read-only が返ります。
4. 運用者は `sinter-gw-admin status <account>` を実行し、`mcp session created account=<account>` が出ていることを確認します。

## 6. registration に失敗した場合

| 利用者側の表示 | 原因 | 対処 |
|---|---|---|
| `register rejected: HTTP 410` | token の期限切れ（15 分） | `issue <account>` で再発行 |
| `register rejected: HTTP 409` | token が使用済み、または account に既に有効な controller がある | `status <account>` で確認。controller がある場合: 利用者の旧 bridge を置き換えるなら `revoke <ctl_…>` → `issue` |
| `register rejected: HTTP 401` | token の誤り | token を再送するか再発行 |
| `register rejected: HTTP 429` | register の rate limit（Caddy 背後では全体共通） | 数分待って再試行 |
| bridge が `controller authentication failed — retrying every 300s` | credential が失効または誤り | 手順 7 |
| ChatGPT で `controller_offline` | bridge が停止中（最後の poll から約 130 秒） | 利用者に bridge の起動を依頼 |
| ChatGPT のサインインが失敗する | Logto の `customData.sinter_account` がない、または綴りが違う | 手順 2.2 を確認 |
| 約 1 時間後に「接続の有効期限が切れています」 | 既知の制約（refresh token が未発行） | 利用者が ChatGPT でアプリを再接続 |

## 7. credential を紛失・漏洩した場合

```sh
gateway/scripts/sinter-gw-admin list <account>                 # controller id を確認
gateway/scripts/sinter-gw-admin revoke --dry-run <ctl_…>
gateway/scripts/sinter-gw-admin revoke <ctl_…>                 # account 名の再入力で確定
gateway/scripts/sinter-gw-admin issue <account>                # 新しい token を発行して利用者へ
```

- 失効は即時に反映されます。旧 credential での poll は 401 になり、ChatGPT からの呼び出しは `controller_offline` になります。
- 利用者には、旧 `bridge.cred` を削除し、新しい token で `register` し直してから bridge を再起動してもらいます。
- `/v1/rotate`（credential の入れ替え）の API はありますが、bridge 側に rotate コマンドはありません。漏洩時は上記の revoke → 再登録を使ってください。

## 8. 利用者を無効化する場合

1. 即時停止: `sinter-gw-admin list <account>` → `revoke <ctl_…>`。以後、その account への配送は行われません。
2. 新規トークンの停止: Logto Console で該当ユーザーの `sinter_account` を削除するか、ユーザーを停止または削除します。
   - 既に発行済みの access token は最長で有効期限（現在 3600 秒）まで残りますが、controller を失効済みなので処理は配送されません。
3. `sinter-gw-admin status <account>` で `revoked` を確認します。

## 9. 安全上の注意

- token と credential を Git に入れないでください。ファイルに保存したり、コマンドライン引数に渡したりもしないでください。
  - `sinter-bridge register` は token を標準入力または環境変数から読みます。
  - `issue` は画面にだけ表示します。
- `sinter-gw-admin` が受け付けるのは account 名と controller id だけです。どちらも形式を検証し、確認入力を求めます。
- identity DB（`/var/lib/sinter-gateway/identity.db`）を手作業で編集しないでください。変更は必ず `sinter-gateway` の CLI 経由で行います（`sinter-gw-admin` はそのラッパーです）。
- 隔離環境での自己検証（本番には触れません）:
  - `SINTER_BIN=<sinter> gateway/scripts/sinter-gw-admin-selftest <sinter-gateway と sinter-bridge のあるディレクトリ>`
  - issue → register → 単回使用 → 事前チェック → revoke の 16 項目を検証します。
