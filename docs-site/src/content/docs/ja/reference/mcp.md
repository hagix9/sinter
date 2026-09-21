---
title: Core MCP
description: sinter mcp — stdio経由でSinterの操作を観測する読み取り専用のModel Context Protocolエンドポイント。
---

Core MCPはSinterのオペレーショナルなMCP surfaceです: `sinter mcp`が
stdio上で動作する最小限のstrictly **読み取り専用**なMCP（Model Context
Protocol）エンドポイントを提供し、MCP対応クライアントやエージェントが
recipeの検証、構造の確認、supplied-factsターゲットへのplan、実ホストの
named targetへの観測を行えます — いかなる変更も行いません。

本サイトの**ドキュメント WebMCP**とは無関係です。WebMCPはブラウザ側の
機能で、ドキュメントページの検索のみを行います。Core MCPはSinter自身の
操作を公開します。

## サーバの起動

```sh
sinter mcp                          # ターゲットなし。host toolはfail closed
sinter mcp --targets-file targets.toml
```

トランスポートはstdin/stdout上のnewline-delimited JSON-RPC 2.0です
（プロトコルリビジョン `2025-03-26`）。stdoutはプロトコルフレームのみを
運び、diagnosticはstderrへ出力されます。サポートするメソッド:
`initialize`、`ping`、`tools/list`、`tools/call`、JSON-RPC batch、
`notifications/*`。

クライアント設定例（stdioサーバ）:

```json
{ "mcpServers": { "sinter": { "command": "sinter", "args": ["mcp"] } } }
```

## ツール

8つのツールはすべて読み取り専用です。apply、exec、shellツールは
意図的に存在しません。

| ツール | 目的 |
|--------|------|
| `sinter_get_version` | crateバージョンとread-only capabilityの表明。 |
| `sinter_classify_platform` | `/etc/os-release`の内容からプラットフォームを分類（family、package backend）。実際のplatform modelを使用。 |
| `sinter_validate_manifest` | 実際の`load_model`パーサでrecipeテキストを検証。構造化されたdiagnosticsを返す。 |
| `sinter_inspect_manifest` | recipeの構造的サマリ: resource identity、type、依存関係、sensitive flag。値は返しません。 |
| `sinter_plan` | **supplied-facts**なターゲットスナップショット（`ubuntu2404`、`ubuntu2604`、`rocky9`、`rocky10`）に対してrecipeをplan。in-processのscripted targetを使用 — 実際のplanningコードを使いますが、SSHも実ホストも使わず、`Mode::Plan`のみ。 |
| `sinter_list_targets` | 管理者が設定したSSHターゲットプロファイルのopaqueな名前を一覧（名前のみ — 接続情報は返しません）。 |
| `sinter_plan_host` | **named** SSHターゲットプロファイルに対してrecipeをplan。productionの`Mode::Plan`パスによる実ホストの読み取り専用観測。 |
| `sinter_audit_host` | named SSHターゲットがrecipeを満たすかを、productionの`run_audit`パスで監査。`no_drift`/`drift`とリソースごとの`PASS`/`DRIFT`/`NOT_AUDITABLE`/`NOT_APPLICABLE`/`ERROR`詳細を報告。 |

## Named target（`--targets-file`）

`--targets-file`は管理者が所有するSSHプロファイルのTOMLレジストリを
指します。起動時に一度だけ読み込まれ、稼働中はimmutableです:

```toml
[targets.web01]
host = "web01.example.com"
port = 22                                        # 省略可、デフォルト22
user = "deploy"
known_hosts = "/secure/path/known_hosts"
identity_files = ["/secure/path/id_ed25519"]     # 省略可
sudo = false                                     # 省略可の権限ポリシー

[targets.db01]
host = "10.0.0.20"
user = "ops"
known_hosts = "/secure/path/known_hosts"
sudo = true
```

- プロファイル名: `[A-Za-z0-9_-]`、英数字で開始、最大64文字。
- ファイルがない、読めない、malformed、構造的に不正な場合、
  `sinter mcp`は起動時に中断します — 部分的なレジストリで動作しません。
- `--targets-file`なしの場合、host toolは登録されますがfail closedです:
  `sinter_list_targets`は空リストを返し、host呼び出しは
  `unknown target`を報告します。
- `identity_files`を省略または空にした場合、既存のSinter SSH認証動作に
  従い、デフォルトのidentity解決を使うことがあります。認証を無効化する
  ものではありません。

## planとauditの違い

- `sinter_plan_host`は「何が変わるか」を答えます — 観測のみの
  非権威的なpreview。
- `sinter_audit_host`は「ターゲットが現在recipeを満たすか」を答えます —
  リソースごとのcompliance/drift分類。観測のみ。

どちらもnamed targetへの実SSH観測であり、終始読み取り専用です。

## セキュリティモデル

- **読み取り専用は構造的に強制されます。** host toolはmutation permitを
  生成できない`TargetFs`上で`Mode::Plan`のengineを構築し、すべての
  変更操作がそのpermitを要求します。`run_audit`はpermitを生成し得る
  engineをさらに拒否します。commandリソースは実行されず
  `NOT_AUDITABLE`と分類されます。
- **接続権限はサーバ側に留まります。** 呼び出し側はopaqueな名前のみで
  ターゲットを参照でき、host、port、user、known_hosts、identity file、
  sudoをツール引数で指定・上書きできません — 予期しないパラメータは
  その場で拒否されます。
- **厳格なホスト鍵検証。** プロファイルの`known_hosts`は必須です。
  未知または変更されたホスト鍵は接続失敗となります。自動登録も
  insecureなフォールバックもありません。
- **manifestの権限は制約されています。** MCP manifestはinline content
  のみ受け付けます: `include:`と`source:`はパース済み構造上でロード前に
  拒否されるため、MCP manifestはcontrollerローカルのファイルシステム
  読み取り権限を与えません。stagingはprivateな0700ディレクトリと
  `create_new`の0600ファイルを使います。通常のCLI recipeは引き続き
  完全な`include:`/`source:`をサポートします。
- **入力はboundedです。** manifestテキストは4MiBまで。SSHのセットアップ、
  ソケット、コマンドごとの操作はすべて時間制限付きです。
- **redaction。** プロファイル内部情報とstagingパスはツール向け
  diagnosticから除去され、host planのfile/template content diffは
  manifestのsensitiveフラグに関係なく常にredactされます。

## MCPが意図的に行わないこと

- applyや修復 — mutationツールは存在しません。
- 任意コマンドやshellの実行。
- 任意ホストへの接続 — 管理者が命名したプロファイルのみ到達可能です。
- controllerファイルの読み取り — MCP manifestでは`include:`/`source:`が
  拒否されます。
- リモートのfileやtemplate bodyの返却 — content diffはMCP境界で常に
  redactされます。

## 制限事項

- stdioトランスポートのみ。組み込みのネットワークリスナはありません。
  リモートクライアントへの公開には、Sinterの外で運用する別の
  トランスポートブリッジが必要です。
- リクエストは逐次処理。サーバは単一のstdioプロセスです。
- SinterはLinux x86_64アーティファクトのみを配布します。他の
  プラットフォームでの`sinter mcp`はソースビルドのcapabilityであり、
  配布物ではありません。
