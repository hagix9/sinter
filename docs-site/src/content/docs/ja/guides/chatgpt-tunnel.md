---
title: Secure MCP Tunnel 経由の ChatGPT
description: OpenAI Secure MCP Tunnel を通して、ChatGPT を自分の読み取り専用 sinter mcp につなぐ。sinter serve または文書化された systemd unit を使う。
---

このガイドは、公式の OpenAI `tunnel-client` を使い、OpenAI の **Secure MCP
Tunnel** を通して ChatGPT を **ご自身の** [`sinter mcp`](/ja/reference/mcp/) に
つなぐ方法を説明します。`sinter serve` とその設定コマンドは Sinter v1.14.0 で
公開されました。

```text
ChatGPT（カスタム MCP アプリ: 接続 = Tunnel）
  → OpenAI Secure MCP Tunnel   （controller からの外向き HTTPS のみ）
  → 公式 tunnel-client         （sinter serve または systemd が起動）
  → sinter mcp                 （stdio の子プロセス。読み取り専用の 8 ツール）
  → 名前付き SSH ターゲット     （targets file にあるものだけ）
```

## これは何か、何ではないか

- **Core MCP**（`sinter mcp`）は読み取り専用のツールサーバーです。ツールは 8 つ
  で、apply もコマンド実行もなく、ターゲットは管理者の targets file にあるもの
  だけです。[MCP リファレンス](/ja/reference/mcp/)を参照してください。
- **`sinter serve`** は公式の `tunnel-client` をフォアグラウンドで起動するだけで、
  `tunnel-client` が `sinter mcp` を子プロセスとして動かします。listener を開かず、
  HTTP クライアントも持たず、tunnel の処理を実装せず、何も再起動せず、中央サーバー
  でもエージェントでもありません。起動して得られるのは読み取り専用ツールへの接続
  だけです。
- **WebMCP** はドキュメントサイトがブラウザに提供する読み取り専用の検索ツール
  です（[WebMCP リファレンス](/ja/reference/webmcp/)）。ホストやこの tunnel とは
  関係ありません。
- **ChatGPT からの変更適用はありません。** 「Tunnel apply」は将来の設計課題に
  すぎず（脅威モデルは ADR 0003）、このガイドの内容でホストを変更することは
  できません。

経路上に Sinter プロジェクトが運用するものはありません。Sinter の gateway、
relay、OAuth サーバー、アカウントデータベースは存在しません。

## 始める前に

- Linux の controller（ほかの OS では `sinter serve` は exit 3）。
- ご自身でインストールした公式の `tunnel-client`（Sinter は同梱・改変・
  ダウンロードしません）。
- OpenAI Platform でご自身が作成した既存の tunnel と、Tunnels Read と Use の
  権限を持つ Restricted API key。Sinter はどちらも作成できません。
- ChatGPT が plan と audit をしてよいホストを並べた
  [targets file](/ja/reference/mcp/#named-target--targets-file)（各ホストに
  `known_hosts` が必要）。
- ChatGPT 側で、接続先をこの tunnel にしたカスタム MCP アプリ（ご自身で追加）。

## 誰が使えるか

stdio サーバーには、ユーザー、ワークスペース、接続の識別情報が届きません。
ChatGPT からこの tunnel を使える人は全員、同じ targets file に対して同じ読み取り
専用の権限を持ちます。Sinter は ChatGPT ユーザーの認証も認可も追加しません。
境界は OpenAI 側にあります（組織の Tunnels Use 権限と、tunnel のワークスペース）。
利用者ごとに権限を分けたい場合は、tunnel、targets file、OS ユーザーを分けて
ください。

## 設定と実行

1. 設定ファイルと鍵ファイルを書きます（ターミナルで実行。鍵はエコーなしで読み、
   0600 のファイルに保存します。設定ファイルには鍵を書かず、既存のファイルは
   置き換えません）。

   ```bash
   sinter serve init --client /usr/local/bin/tunnel-client --targets-file /etc/sinter/targets.toml
   ```

   tunnel ID（識別子で、秘密ではありません）と鍵を尋ね、検査と
   `tunnel-client doctor` を実行します。`--check-online` を付けると、鍵で tunnel
   を読めるかを公式クライアントにも確かめさせます。

2. 起動も書き込みもせずに、いつでも設定を確認できます。

   ```bash
   sinter serve check --online
   ```

3. 必要な間だけ、フォアグラウンドで接続を開始します。

   ```bash
   sinter serve --max-duration 1h
   ```

   Ctrl+C、`SIGTERM`、`SIGHUP`、`--max-duration` の終了で停止します（10 秒後に
   `SIGKILL`）。exit 0: 要求どおり、または制限時間で停止。2: 設定が不正で何も
   起動していない。3: クライアントを起動できなかった、または自分で終了した。

4. 鍵を替えるときは `sinter serve rotate-key`。

`sinter serve` は何かを起動する前に、設定ファイル、鍵ファイル（通常ファイルで、
非公開、自分の所有。内容は読みません）、クライアントの実行ファイル、targets file
を確認します。クライアントには許可リストだけの空の環境を渡すので、鍵が環境変数
を通じてクライアントや `sinter mcp` に届くことはありません。

## systemd で動かす

`contrib/systemd/sinter-tunnel.service` は、`sinter serve` を使わずに公式
クライアントを直接動かし、鍵は systemd の credential として渡します。`[Install]`
節がないので起動時には始まりません。明示的に開始・停止してください
（`systemctl start sinter-tunnel`、`systemctl stop sinter-tunnel`）。
`sinter serve init --systemd`（root で実行）は鍵を `LoadCredential=` 用に root
所有で保存し、値を埋めた unit を表示します（インストールはしません）。unit の
先頭に書かれたプレースホルダーをすべて置き換えてからインストールしてください。

## 確認済みのことと未確認のこと

`CHANGELOG.md` の v1.14.0 の項より:

- v1.14.0 の公開前に開発ビルドで 1 回確認しました。一時的な Ubuntu 24.04
  x86_64 の controller 1 台、`tunnel-client` v0.0.21 で、ChatGPT が
  `sinter_get_version`、`sinter_list_targets`、`sinter_validate_manifest`、
  `sinter_inspect_manifest`、`sinter_plan_host`、`sinter_audit_host` を実ターゲット
  1 台に対して呼び出し、Ctrl+C で exit 0 となり、プロセスは残りませんでした。
- 設定コマンドは実際の Restricted key で 1 回確認しました（`init --check-online`、
  `check --online`、`rotate-key --check-online`）。
- 未確認: 公開されたビルドそのものの実機での動作、ほかの controller の
  ディストリビューション、`init` が書いた設定での ChatGPT からの呼び出し、
  クライアント検査の失敗時に HTTP ステータスを読む処理（修正後）の実サービス
  での動作、`tunnel-client` v0.0.21 での systemd unit（それ以前に Sinter v1.5.2 と
  `tunnel-client` v0.0.16 で確認済み）。

## 制限

- 異常終了の後にすべてのプロセスが終わることは保証しません。tunnel ID ごとの
  ロックはありません（1 つの tunnel につき 1 インスタンスで運用してください）。
  ユーザーごとの認可はありません。
- 読み取り専用のツール一覧、名前付きターゲットのモデル、必須の `known_hosts`、
  秘密情報の参照の拒否は `sinter mcp` のものそのままです。
- このガイドは企業のセキュリティレビューではありません。組織としてのレビューは
  別の判断です。
