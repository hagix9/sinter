---
title: ChatGPT Plugin
description: 公開 Sinter Gateway とご自身の sinter-bridge を経由して、ChatGPT から Sinter を利用する（read-only）。
---

Sinter ChatGPT Plugin を使うと、ChatGPT から **ご自身の** Sinter 環境にある
**read-only** の MCP tool（recipe の検証・構造確認・plan、名前付き SSH target の
plan / audit）を呼び出せます。

:::caution[プレビュー]
Sinter for ChatGPT は現在招待制で、ChatGPT の Plugin ディレクトリにはまだ
掲載されていません。利用を希望する場合は [Fulltrust お問い合わせフォーム](https://fulltrust.co.jp/contact/index.html) から、
お問い合わせ内容に「Sinter利用希望」と記載してご連絡ください。フォームには
サーバー情報・認証情報・トークンを記載しないでください。承認後、Gateway 運用者が
サインインアカウントを用意し、1 回限りの registration token をお送りします
（[クイックスタート](#クイックスタート)参照）。
:::

## 仕組み

```text
ChatGPT
  → Sinter Plugin（HTTPS 上の MCP、OAuth サインイン）
  → 公開 Sinter Gateway  https://gateway.fulltrust.co.jp/mcp
  → あなたのアカウントの controller（サインイントークン内のアカウントで照合）
  → あなたの sinter-bridge（あなたのマシンで動作、外向き HTTPS のみ）
  → あなたのローカル `sinter mcp`（read-only tool、名前付き target へ SSH）
```

- **Gateway** は Fulltrust が運用する共用の公開中継です。ChatGPT からの
  リクエストを OAuth access token で認証し、あなたのアカウントに登録された
  controller へ MCP リクエストを転送します。Gateway はあなたの Sinter ホスト
  **ではありません**。Sinter を実行せず、SSH 設定を持たず、あなたのサーバーへ
  接続もしません。
- **sinter-bridge** はあなたのマシンで動作します。外向き HTTPS で Gateway を
  long-poll し（待ち受けポートなし・受信方向の firewall 変更不要）、各リクエストを
  ローカルの `sinter mcp` 子プロセスへ渡して結果を返します。
- **`sinter mcp`** はあなたの権限でローカルに動作します。ホストへのアクセスは、
  あなた自身の targets ファイルにある名前付き target を通じてのみ行われます。

## 前提条件

| 項目 | 内容 |
|---|---|
| Sinter | v0.5.1 以降（`sinter mcp`）。[インストール](/ja/getting-started/installation/)参照 |
| sinter-bridge | 本リポジトリの `gateway/` crate からビルド（リリースアーカイブには未同梱）。Rust toolchain が必要 |
| bridge ホスト | Linux x86_64（リリースアーカイブ）、または Sinter をソースからビルドする他の Unix 系マシン（例: macOS）。`https://gateway.fulltrust.co.jp` へ外向き HTTPS（443）で到達でき、Plugin 利用中は起動し続けていること |
| ChatGPT | apps / plugins を利用できる ChatGPT プラン。プレビュー期間中はアプリ追加に developer mode が必要 |
| サインインアカウント | 運用者によって Sinter アカウントの対応付けが設定されたアカウント |
| 任意 | `sinter_plan_host` / `sinter_audit_host` を使う場合は targets ファイル（`--targets-file` 形式） |

## クイックスタート

1. **Sinter をインストール**（v0.5.1 以降）。Linux x86_64 の場合:

   ```sh
   curl -fsSL https://sinter.fulltrust.co.jp/install.sh | sh
   $HOME/.local/bin/sinter --version
   ```

   インストーラーは Linux x86_64 のみ対応です。それ以外（例: macOS）では、
   手順 2 で clone したリポジトリのルートで `cargo build --release` を実行して
   Sinter をビルドしてください（binary: `target/release/sinter`）。

2. **sinter-bridge をビルド**:

   ```sh
   git clone https://github.com/hagix9/sinter.git
   cd sinter/gateway
   cargo build --release --bin sinter-bridge
   # binary: gateway/target/release/sinter-bridge（以降のコマンドは sinter/gateway で実行）
   ```

3. **利用を申請**。[Fulltrust お問い合わせフォーム](https://fulltrust.co.jp/contact/index.html) から、お問い合わせ内容に
   「Sinter利用希望」と記載してご連絡ください（サーバー情報・認証情報・トークンは
   記載しないでください）。運用者がサインインアカウントを作成し、そのサインイン情報と、
   別途 **1 回限りの registration token** をお送りします。token の有効期限は 15 分、
   使用は 1 回だけです。期限切れの場合は再発行を依頼してください。

4. **bridge を登録**（`register` は 1 回だけ実行してください。token を消費します）。
   token はコマンドライン引数ではなく標準入力から読み込まれ、標準出力には
   credential だけが出力されます:

   ```sh
   mkdir -p ~/.config/sinter && umask 077
   SINTER_BRIDGE_GATEWAY_URL=https://gateway.fulltrust.co.jp \
     ./target/release/sinter-bridge register > ~/.config/sinter/bridge.cred
   # プロンプトに registration token を貼り付ける
   chmod 600 ~/.config/sinter/bridge.cred
   ```

5. **bridge を起動**:

   ```sh
   export SINTER_BRIDGE_GATEWAY_URL=https://gateway.fulltrust.co.jp
   export SINTER_BRIDGE_CREDENTIAL_FILE=~/.config/sinter/bridge.cred
   # 任意: export SINTER_BRIDGE_SINTER_BIN=/path/to/sinter   （既定: PATH 上の sinter）
   # 任意: export SINTER_BRIDGE_TARGETS_FILE=~/.config/sinter/targets.toml
   ./target/release/sinter-bridge --check   # 設定と子プロセス起動を検証し "ok" を表示
   ./target/release/sinter-bridge           # "bridge polling https://gateway.fulltrust.co.jp/" を出力
   ```

6. **ChatGPT にアプリを追加**（プレビュー期間中は developer mode）:
   - MCP サーバーの URL: `https://gateway.fulltrust.co.jp/mcp`
   - 認証: OAuth

7. ChatGPT がサインイン画面を開いたら **サインイン** し、アクセスを許可します。

8. **動作確認**: 新しいチャットで Sinter アプリにバージョンを尋ねます（[例](#例)参照）。

## 例

> Sinter のバージョンを教えて

ChatGPT は `sinter_get_version` を呼び出し、あなたの bridge がローカルの
Sinter から応答します。例: `{"name":"sinter","readOnly":true,"version":"0.5.1"}`

その他の read-only な例:

- 「この Sinter recipe を検証して」（YAML/TOML を貼り付け）→ `sinter_validate_manifest`
- 「この recipe を rocky9 で plan して」→ `sinter_plan`（supplied-facts スナップショット、ホスト接続なし）
- 「Sinter の target 一覧を見せて」→ `sinter_list_targets`
- 「web01 をこの recipe で audit して」→ `sinter_audit_host`（targets ファイル内の名前付き target）

## Tool と権限

すべての tool は read-only です。apply・install・コマンド実行の tool はありません。
すべての tool に `readOnlyHint: true`、`destructiveHint: false`、
`openWorldHint: false` の annotation が付いています。

| Tool | 内容 |
|---|---|
| `sinter_get_version` | Sinter のバージョンと read-only 宣言 |
| `sinter_classify_platform` | `/etc/os-release` の内容を分類 |
| `sinter_validate_manifest` | recipe テキストを検証 |
| `sinter_inspect_manifest` | recipe の構造要約（値は返さない） |
| `sinter_plan` | 組み込みの supplied-facts スナップショットに対する plan（SSH なし） |
| `sinter_list_targets` | 設定済み target の名前（接続情報は返さない） |
| `sinter_plan_host` | 名前付き target に対する read-only な plan |
| `sinter_audit_host` | 名前付き target の read-only な audit |
| `sinter_get_profile` | Gateway が追加。アカウント ID（サインイントークンに含まれる場合は名前・メール）を返し、ChatGPT が接続を識別できるようにする |

MCP の recipe はインライン内容のみ受け付けます（`include:` / `source:` は拒否）。
そのため recipe を通じてあなたのマシン上のファイルを読むことはできません。
[Core MCP](/ja/reference/mcp/) を参照してください。

## bridge を起動し続ける

Plugin を使う間は bridge が起動している必要があります。停止すると、最後の poll から
約 130 秒後に tool 呼び出しが `controller_offline` で失敗します。

- **フォアグラウンド**: ターミナルで `sinter-bridge` を実行します。Gateway に到達
  できない場合はバックオフ（1 秒から倍増、最大 60 秒）で再接続し、`sinter mcp`
  子プロセスは 5 分間に最大 5 回まで再起動します。
- **systemd（Linux）**: リポジトリの `gateway/contrib/systemd/` に user unit と
  環境変数テンプレートがあります。`sinter/gateway` ディレクトリで:

  ```sh
  install -D -m 755 target/release/sinter-bridge ~/.local/bin/sinter-bridge
  install -D -m 644 contrib/systemd/sinter-bridge.service ~/.config/systemd/user/sinter-bridge.service
  install -D -m 600 contrib/systemd/bridge.env.example ~/.config/sinter/bridge.env
  # ~/.config/sinter/bridge.env の /home/USER をご自身のホームディレクトリに置き換える
  systemctl --user daemon-reload
  systemctl --user enable --now sinter-bridge
  loginctl enable-linger "$USER"             # ログアウト後・起動時も継続
  journalctl --user -u sinter-bridge -f      # "bridge polling …" を確認
  ```

  `bridge.env` には絶対パスを記述してください。systemd はこのファイル内の `~` を
  展開せず、user service の `PATH` には `~/.local/bin` が含まれないため、
  `SINTER_BRIDGE_SINTER_BIN` で `sinter` binary を明示します。
  `systemctl --user stop sinter-bridge` で正常停止し、異常終了時は 10 秒後に
  再起動されます。

- **launchd（macOS）**: launchd 定義は提供していません。フォアグラウンドで実行して
  ください。スリープ・ログアウト・再起動で停止します。

## トラブルシューティング

| 症状 | 原因と対処 |
|---|---|
| tool 呼び出しが `controller_offline` / "no controller for account" で失敗 | bridge が起動していないか、約 130 秒以上 poll していません。起動してログに `bridge polling …` が出ることを確認してください。 |
| bridge が `controller authentication failed — retrying every 300s` を出力 | credential が失効しているか誤っています。運用者に新しい registration token を依頼して再登録してください。 |
| `register rejected: HTTP 410` / `409` / `401` | 410: registration token の期限切れ（15 分）。409: 使用済み、またはあなたのアカウントに有効な bridge が既にある（運用者による旧 bridge の失効が必要）。401: token が無効。運用者に新しい token を依頼してください。 |
| ChatGPT でサインインに失敗する（OAuth エラー / アクセス拒否） | サインインアカウントに Sinter アカウントの対応付けがまだありません。運用者に依頼してください。 |
| 「Authentication succeeded, action discovery failed」 | サインインは成功したが tool を一覧できませんでした。多くの場合 bridge が停止中（上記）か、Gateway に到達できません。 |
| 以前は動いたが、再サインインを求められる / ツールを更新できない | access token が期限切れで更新できませんでした。ChatGPT でアプリを切断して再接続し、再度サインインしてください。 |
| tool 呼び出しが `account_unbound`（HTTP 403）を返す | サインイントークンに Sinter アカウントの対応付けがありません。運用者に依頼してください。 |
| Gateway に到達できない、DNS / TLS エラー | bridge ホストから `curl -sS https://gateway.fulltrust.co.jp/healthz` が HTTP 200 を返すか確認してください。社内プロキシではこのホストへの外向き HTTPS の許可が必要です。 |
| `sinter_plan_host` / `sinter_audit_host` で target が見つからない | target 名が `SINTER_BRIDGE_TARGETS_FILE` にありません。`sinter_list_targets` で名前を確認してください。 |
| ホストで permission denied | bridge ホストからあなた自身の認証情報で target へ SSH できませんでした。同じ target を `sinter` CLI で確認してください。 |
| credential ファイルの警告 "group/world-accessible" | `chmod 600 ~/.config/sinter/bridge.cred` を実行してください。 |

## セキュリティとプライバシー

- **通信**: ChatGPT ↔ Gateway は HTTPS（Let's Encrypt の TLS 証明書）です。
  bridge ↔ Gateway も HTTPS のみで、リダイレクトは無効化されているため、bridge の
  credential は設定した Gateway オリジンにしか送られません。
- **認証**: すべての MCP リクエストに OAuth access token が必要です。Gateway は
  署名（固定 JWKS、RS256/ES256）、issuer、audience、有効期限、Sinter アカウント
  claim を検証します。有効な token がなければ HTTP 401、アカウント対応付けの
  ない token は 403 になります。
- **アカウント分離**: リクエストは token 内のアカウントに登録された controller に
  のみ配送されます。1 アカウントにつき有効な controller は 1 つです。
- **Gateway が保存するもの**: アカウント ID、controller ID、registration token と
  controller credential の SHA-256 ハッシュ、登録 / 失効の監査イベント。OAuth token、
  平文の bridge credential、MCP リクエスト / レスポンスの内容は保存しません。
- **Gateway を通過するもの**: ChatGPT からの MCP リクエストと、あなたの Sinter の
  結果（例: 貼り付けた recipe テキスト、target に関する plan / audit 結果）。これらは
  メモリ上で中継され、ChatGPT にも届きます。送信する recipe に秘密情報を含めない
  でください。
- **ログ**: 公開 Gateway のアクセスログには method、path（クエリなし）、status、
  サイズ、処理時間が記録され、header とクライアント IP は削除されます。Gateway の
  サービスログにはアカウント・controller・リクエストの ID と status code が記録され、
  token やペイロードは記録されません。
- **credential**: bridge の credential はあなたのマシンにのみ保存されます。
  `chmod 600` を維持してください。運用者はいつでも失効できます。
- **read-only**: どの tool もあなたのシステムを変更しません。Sinter 自身の安全規則
  （MCP recipe はインラインのみ、名前付き target のみ）も引き続き適用されます。
