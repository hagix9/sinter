# Sinter

[English](README.md) | **日本語**

**ドキュメント:** <https://sinter.fulltrust.co.jp/ja/> ([English](https://sinter.fulltrust.co.jp/))

**Small enough to understand, strong enough to trust.**

Sinterは、Itamaeに着想を得た軽量なエージェントレス構成管理ツールです。
単一のRustバイナリからOSの構成を記述・適用し、管理対象ホストには
SinterエージェントやSinterランタイム、Ruby、Pythonを必要としません。

<p align="center">
  <img src="assets/demo/sinter-demo.svg" alt="Sinter ターミナルデモ: plan → apply → audit" width="720">
</p>

## Sinterの特徴

- **エージェントレス・単一バイナリ**
  管理対象ホストにSinterのエージェントやランタイムを導入する必要はなく、
  RubyやPythonのランタイムも必要ありません。

- **`plan` は観測のみ**
  `sinter plan` は対象の状態を観測するだけで、stagingデータのアップロード、
  権限・所有者の変更、パッケージの追加・削除、サービス変更、
  commandリソースの実行を行いません。

- **`apply` は変更直前に再観測**
  以前のplan結果を現在状態として信用しません。stateful resourceは、
  Sinterが変更の要否を判断する直前に再び観測されます。

- **判断できない状態では安全側に停止**
  危険な親ディレクトリ、想定外のsymlink、未登録・変更済みSSHホスト鍵、
  検証失敗、indeterminateな状態を成功扱いして処理を継続しません。

- **変更結果を正直に表現**
  必要に応じてexecution / change / verification / dispositionを分離し、
  changed、failed、indeterminate、possible、verified、blockedなどの状態を
  単純な成功・失敗の1ビットに潰しません。

- **厳格なSSHホスト識別**
  指定された`known_hosts`を信頼の基準とし、未知ホストの自動登録や
  insecureなフォールバックを行いません。非標準SSHポートでは
  明示的な`[host]:port` identityを要求します。

- **冪等性を前提に設計**
  stateful resourceがすでに望ましい状態なら、同じrecipeを再度applyしても
  そのリソースに対する変更は0件になります。

## クイック例

```yaml
version: 1

resources:
  - id: tree
    type: package
    with:
      name: tree
      state: present
```

```sh
sinter validate recipe.yaml
sinter plan --host server.example.com recipe.yaml
sinter apply --host server.example.com --sudo recipe.yaml
sinter audit --host server.example.com --sudo recipe.yaml
```

このリポジトリは、`GOALS.md`と`DESIGN.md`で定義された
**Sinter v0.2**を実装しています。これら2ファイルが正式な仕様であり、
v0.2はv0.1のcontractにRHEL系platform対応（Rocky Linux、RHEL、
AlmaLinux — `dnf`）を追加しています。roles、plugins、inventory、orchestration、
embedded scriptingは依然として実装対象に含めません。

## インストール

Sinter **v0.5.0** は、対応するすべての Linux x86_64 プラットフォーム
ラインを1つの `sinter-v0.5.0-linux-x86_64.tar.gz` アーティファクトで
配布します。UbuntuとRockyのラインに加え、受入検証済みの
RHEL 9 / 10、AlmaLinux 9 / 10 対応が追加されました。

```sh
curl -fsSL https://sinter.fulltrust.co.jp/install.sh | sh
$HOME/.local/bin/sinter --version
```

受入検証したpoint release（v0.4.1）は Ubuntu 24.04.5 LTS、
Ubuntu 26.04.1 LTS、Rocky Linux 9.8、Rocky Linux 10.2、RHEL 9.8、
RHEL 10.2、AlmaLinux 9.8、AlmaLinux 10.2（すべてx86_64）です。
他の各point releaseを個別に受入検証したという意味ではありません。

インストーラは公式GitHubの最新安定版を選び、展開前にSHA256SUMSを検証し、
sudoを使わず `$HOME/.local/bin` に配置します。必要なら自分でPATHへ追加して
ください。シェル設定は変更しません。実行前の内容確認と手動ダウンロードは
[インストール](https://sinter.fulltrust.co.jp/ja/getting-started/installation/)を参照してください。

## ビルド

```sh
cargo build --release
# binary: target/release/sinter
```

## 基本ワークフロー

```sh
sinter validate recipe.yaml
sinter plan --host host.example recipe.yaml
sinter apply --host host.example recipe.yaml
sinter audit --host host.example recipe.yaml
```

- `validate` は対象ホストへ接続せず、recipeの構造と意味を検証します。
- `plan` は観測のみを行い、`apply` が何を変更するかの非権威的な
  previewを生成します。ファイル書き込み、stagingデータのアップロード、
  権限・所有者変更、パッケージやサービスの変更、commandリソースの
  実行は行いません。
- `apply` はstateful resourceを変更するか判断する直前に再観測します。
- `audit` も読み取り専用ですが、問いが異なります：ターゲットが現在
  レシピと一致しているかを報告します。リソースごとに `PASS`/`DRIFT`/
  `NOT_AUDITABLE`/`NOT_APPLICABLE`/`ERROR` を報告し — `command`
  リソースは常に `NOT_AUDITABLE` で実行されません — drift 時は
  終了コード 7、観測エラー時は 6 で終了します。

`--host`を省略した場合はローカルホストが対象になります。
SSHおよびpasswordless `sudo -n`は`--host … --sudo`で利用できます。

### CLI終了コード

| Code | 意味 |
|------|------|
| 0 | 正常終了。planで差分が存在しても0。auditではDRIFTもERRORもなし（`NOT_AUDITABLE`/`NOT_APPLICABLE`のリソースが存在してもよい） |
| 2 | validation/schema error |
| 3 | target connection/capability/security error |
| 4 | planを安全に完了できなかった |
| 5 | apply failed |
| 6 | apply became indeterminate。auditでは1件以上のERRORが記録された（ERRORはDRIFTより優先） |
| 7 | auditがDRIFTを検出（ERRORなし） |

## Recipeモデル

YAMLとTOMLは共通のsemantic IRに対するfrontendです。
同等のrecipeはどちらの形式でも、typed value、resource identity、順序、
desired state、ChangeSet、実行動作が同等になります。

トップレベルのフィールドは`version`、`vars`、`include`、`resources`、
`handlers`です。

v0.2のresource typeは`file`、`directory`、`template`、`link`、
`command`、`package`、`service`です。
handlerは遅延実行されるserviceの`restart` / `reload`アクションです。

最小構成のrecipe例:

```yaml
version: 1
vars:
  greeting:
    value: hello
    sensitive: false
resources:
  - id: motd
    type: template
    with:
      path: /etc/motd
      source: templates/motd
      mode: "0644"
    notify:
      - restart_motd
handlers:
  - id: restart_motd
    service: motd
    action: restart
```

## セキュリティと安全性

- planは観測のみを行い、対象状態を変更できません。
- applyはすべての変更判断の直前に状態を再観測します。plan結果を
  現在状態として再利用しません。
- stateful resourceは冪等です。2回目のapplyでは不要な変更を行いません。
- SSHは指定された`known_hosts`にすでに存在するホストのみ受け入れます。
  未知または変更された鍵は接続失敗となり、insecureなフォールバックや
  自動登録は行いません。
- リモートコマンドは意図しないshell展開を避け、argvを正確に保持します。
  NUL byteは拒否されます。
- `--sudo`指定時は、target側のすべての操作をnon-interactiveな
  `sudo -n`経由でeffective UID 0として実行します。指定しない場合は
  target userとして実行します。権限エラー後に勝手にsudoで再試行しません。
- command resourceは固定のbaseline environment
  (`PATH`, `LANG`, `LC_ALL`, `HOME`)を使用します。
  controller、SSH session、sudo、login shellの環境変数を継承しません。
  予約済みの変数名をrecipeから上書きすることはできません。
- filesystem mutationでは親pathのtrust boundaryを検証し、想定外の
  symlinkを拒否します。省略された既存metadataを保持し、
  未対応のsecurity metadataを勝手に破棄せず、内容はrenameによって
  atomicにpublishします。
- timeout after dispatch、応答消失、signal不確実性などのindeterminateな
  mutationは自動再試行しません。
- fail-fastにより、最初のfailedまたはindeterminate resourceで後続実行を
  停止し、残りのresourceはblockedとして報告します。
- sensitive valueは通常出力、verbose、diff、registered result、
  diagnostics、structured outputに表示しません。sensitive contentでは
  hashやsizeも非表示にします。
- failed、indeterminate、verification failure、possible-changeを
  実際の結果に沿って報告します。

## サポートプラットフォーム

managed target:

| Platform | Architecture | Package backend | Status |
|----------|--------------|-----------------|--------|
| Ubuntu 24.04 LTS | amd64 | apt | Supported, acceptance-tested |
| Ubuntu 26.04 LTS | amd64 | apt | Supported, acceptance-tested |
| Rocky Linux 9 | x86_64 | dnf | Supported, acceptance-tested |
| Rocky Linux 10 | x86_64 | dnf | Supported, acceptance-tested |
| RHEL 9 | x86_64 | dnf | Supported, acceptance-tested |
| RHEL 10 | x86_64 | dnf | Supported, acceptance-tested |
| AlmaLinux 9 | x86_64 | dnf | Supported, acceptance-tested |
| AlmaLinux 10 | x86_64 | dnf | Supported, acceptance-tested |
| Oracle Linux | x86_64 | dnf | Expected compatible — not acceptance-tested |

package recipeはplatform-neutralです。同じ`type: package` / `state:
present` resourceを、Ubuntuでは`apt`、RHEL系では`dnf`が処理します。
backendは検出した`/etc/os-release`のidentityから選択されます。

Oracle LinuxはRHEL系platformとして認識され、SinterのDNF backendを
使用します。対応するRHEL系実装と互換性があると見込まれますが、現在
Sinterの実ホスト受入マトリクスには含まれていません。

Sinter v0.4.1は8台の実x86_64 Linuxホストで受入検証を実施しました —
[インストール](#インストール)に記載のpoint releaseです。8台すべてが
同一の凍結済みcandidateバイナリと同一の論理受入シナリオを実行し、
**344/344チェックが通過**しました。以前のVM検証とリリース証跡は
履歴として保持します。

すべてのmanaged targetには、systemd、OpenSSH server、`/bin/sh`、
`attr` package（`/usr/bin/getfattr`。書き込み前に拡張属性とPOSIX ACLを
確認するために使用。各ターゲットで `test -x /usr/bin/getfattr` を確認し、
不在なら apt または dnf で `attr` をインストールしてください）、および権限昇格が必要な場合の
passwordless `sudo -n`が必要です。controllerのreference environmentは
macOS、Ubuntu 24.04 LTS、Ubuntu 26.04 LTS、Rocky Linux 9、
Rocky Linux 10、RHEL 9、RHEL 10、AlmaLinux 9、AlmaLinux 10、
およびバイナリをbuildできるその他のx86_64 Linux環境です。

## テスト

テストスイートは`src/`内のunit testと、`tests/`内の
integration / acceptance testに分かれています。

| Suite | 対象 |
|-------|------|
| lib unit tests | value model, frontends, expressions/Unknown, paths, argv quoting, package states |
| `frontends` | YAML/TOML equivalence and IR fixtures, schema rejection, includes |
| `engine` | file/directory/link/template, plan safety, idempotency, fail-fast, static identifiers |
| `commands` | guards, registers, changed_when, environment baseline, exit codes |
| `handlers` | delayed handlers, dedup, fail-fast, verification gating |
| `package_service` | apt install/remove/idempotency, systemd state/enabled combinations |
| `file_safety` | trust boundary, symlink rejection, metadata preservation, atomic publication, failure injection |
| `truthfulness` | result-dimension matrix, ordering, dependency blocks |
| `cli` | exit codes, JSON output, sensitive-output redaction |
| `ssh` | real SSH integration (known_hosts, sudo, argv exactness, timeouts, signals) |

reference targetでフルスイートを実行します。

```sh
cargo test
```

SSH integration testは、使い捨てのUbuntu targetを指す環境変数で有効化します。

```sh
export SINTER_TEST_SSH_HOST=127.0.0.1
export SINTER_TEST_SSH_PORT=22
export SINTER_TEST_SSH_USER=ubuntu
export SINTER_TEST_SSH_KNOWN_HOSTS=/path/to/known_hosts
export SINTER_TEST_SSH_IDENTITY=/path/to/test_key
cargo test --test ssh
```

外部観測とinstrumented command logの両方を使い、planがmutationを
行わないこと、および冪等な2回目のapplyでmutation operationが
発行されないことを検証します。

## リポジトリ構成

```text
src/
  value.rs         common semantic value model
  yaml.rs          YAML frontend (rejects aliases/anchors/merge/dupes/non-finite)
  toml_front.rs    TOML frontend (rejects datetimes/non-finite)
  document.rs      schema validation of parsed documents
  ir.rs            intermediate representation constants
  model.rs         include expansion, loops, static identifiers, graph validation
  expressions.rs   expression language, interpolation, Unknown semantics
  facts.rs         target fact model
  executor.rs      local/SSH execution, known_hosts, sudo, exact argv
  targetfs.rs      target filesystem trust checks and atomic publication
  resources.rs     resource implementations
  engine.rs        plan/apply engine, ordering, dependencies, handlers, fail-fast
  audit.rs         read-only audit engine (per-resource compliance/drift)
  result.rs        result dimensions (execution/change/verification/disposition)
  diff.rs          truthful, sanitized diff rendering
  output.rs        human and JSON rendering with sensitive redaction
  error.rs         error kinds and exit codes
  mcp.rs           read-only MCP stdio adapter
  targets.rs       administrator-owned named SSH target profiles for MCP
  main.rs          CLI
tests/             acceptance and integration test suites
```

## MCPインターフェイス

**ステータス:** v0.5.0でリリース。

`sinter mcp` は、stdio上で動作する最小限のstrictly **読み取り専用**な
MCP（Model Context Protocol）エンドポイントを提供します
（newline-delimited JSON-RPC 2.0）。authoritative coreの薄い
アダプタであり、validation、platform、planningの規則を再実装しません。

ツール（すべて読み取り専用。apply/execute/installツールは意図的に
存在しません）:

| ツール | 目的 |
|--------|------|
| `sinter_get_version` | crateバージョンとread-only capabilityの表明。 |
| `sinter_classify_platform` | `/etc/os-release`の内容からターゲットを分類（family、package backend）。実際のplatform modelを使用。 |
| `sinter_validate_manifest` | 実際の`load_model`パーサでrecipeテキストを検証。構造化されたdiagnosticsを返す。 |
| `sinter_inspect_manifest` | recipeの構造的サマリ: resource identity、type、依存関係、sensitive flag。値は返しません。 |
| `sinter_plan` | **supplied-facts**なターゲットスナップショット（`ubuntu2404`、`ubuntu2604`、`rocky9`、`rocky10`）に対してrecipeをplan。in-processのscripted targetを使用 — 実際のplanningコードを使いますが、SSHも実ホストも使わず、`Mode::Plan`のみ。 |
| `sinter_list_targets` | 管理者が設定したSSHターゲットプロファイルのopaqueな名前を一覧（名前のみ — 接続情報は返しません）。 |
| `sinter_plan_host` | **named** SSHターゲットプロファイルに対してrecipeをplan。productionの`Mode::Plan`パスによる実ホストの読み取り専用観測。 |
| `sinter_audit_host` | named SSHターゲットがrecipeを満たすかを、productionの`run_audit`パスで監査。読み取り専用。 |

利用できないもの: apply、任意コマンド実行、あらゆるmutation。
リモートアクセスは管理者が設定したnamed targetを**通じてのみ**可能です
（後述）。

MCP manifestはinline contentのみ受け付けます: `include:`と`source:`は
パース済み構造上で、すべてのmanifest消費ツールでロード前に拒否されるため、
manifestがcontrollerローカルのファイルシステム読み取り権限を与えることは
ありません。この制限はMCP固有です — 通常のCLI recipeは引き続き完全な
`include:`/`source:`をサポートします。

クライアント設定例（stdioサーバ）:

```json
{ "mcpServers": { "sinter": { "command": "sinter", "args": ["mcp"] } } }
```

### Named target（`--targets-file`）

`sinter mcp --targets-file targets.toml` は、起動時に読み込まれ
immutableなnamed SSHプロファイルのレジストリを通じて、実ホストの
読み取り専用観測を有効にします。MCPクライアントはターゲットを
**opaqueな名前でのみ**参照でき、host、port、user、known_hosts、
identity file、sudo、その他の接続パラメータを指定できません。
これらは管理者が所有するプロファイルポリシー専用です。

```toml
[targets.web01]
host = "web01.example.com"
port = 22                    # optional, default 22
user = "deploy"
known_hosts = "/secure/path/known_hosts"
identity_files = ["/secure/path/id_ed25519"]  # optional
sudo = false                 # optional: profile-owned privilege policy

[targets.db01]
host = "10.0.0.20"
user = "ops"
known_hosts = "/secure/path/known_hosts"
sudo = true
```

- プロファイル名: `[A-Za-z0-9_-]`、英数字で開始、最大64文字。
- ファイルは起動時に一度だけパースされます。ファイルがない、読めない、
  malformed、構造的に不正な場合、`sinter mcp`はエラーで中断します。
  暗黙のデフォルトパスも環境変数による探索もありません。
- `--targets-file`なしの場合、host toolは登録されますがfail closedです:
  `sinter_list_targets`は空リストを返し、plan/audit呼び出しは
  `unknown target`を報告します。
- host toolはproductionのPlan/Auditパスを再利用します: read-onlyな
  `TargetFs`上の`Mode::Plan`（mutation permitは取得不能）、command
  resourceは実行されず、`run_audit`はpermitを生成し得るengineを
  さらに拒否します。
- `sinter_list_targets`は名前のみを返します。underlying diagnosticは
  sanitizeされ、プロファイル内部情報（host、user、key path）がMCP出力に
  届きません。
- `identity_files`を省略または空にした場合、既存のSinter SSH認証動作に
  従い、デフォルトのidentity解決を使うことがあります。認証を無効化する
  ものではありません。
- host plan出力はfileやtemplateのbodyを返しません: content diffは
  manifestの`sensitive`フラグに関係なくMCP境界で常にredactされます。

これはドキュメントサイトのWebMCP（ブラウザ側、ドキュメント検索のみ）と
は無関係です。Core MCPはSinter自身の操作を公開します。

## ChatGPT Plugin（プレビュー）

Sinter ChatGPT Plugin を使うと、ChatGPT から **ご自身の** Sinter 環境にある
read-only の `sinter mcp` tool を呼び出せます:

```text
ChatGPT → Sinter Plugin → 公開 Gateway (https://gateway.fulltrust.co.jp/mcp)
        → あなたのアカウントの controller → あなたの sinter-bridge → ローカルの `sinter mcp`
```

- 公開 Gateway（`gateway/` crate）は ChatGPT を OAuth で認証し、MCP リクエストを
  中継します。あなたの Sinter ホストではなく、あなたのサーバーへ接続することも
  ありません。
- `sinter-bridge` はあなたのマシンで動作し（外向き HTTPS のみ）、各リクエストを
  ローカルの `sinter mcp` 子プロセスへ渡します。すべての tool は read-only で、
  `readOnlyHint: true`、`destructiveHint: false`、`openWorldHint: false` の
  annotation が付いています。
- Sinter for ChatGPT は現在招待制です。利用を希望する場合は
  [Fulltrust お問い合わせフォーム](https://fulltrust.co.jp/contact/index.html) から、お問い合わせ内容に
  「Sinter利用希望」と記載してご連絡ください（サーバー情報・認証情報・トークンは
  記載しないでください）。Gateway 運用者がサインインアカウントを用意し、bridge 用の
  1 回限りの registration token を発行します。

セットアップ、トラブルシューティング、セキュリティ / プライバシーの詳細:
[ChatGPT Plugin ガイド](https://sinter.fulltrust.co.jp/ja/guides/chatgpt-plugin/)

## ライセンス

Sinterは以下のいずれかを選択できるデュアルライセンスです。

- Apache License, Version 2.0 (`LICENSE-APACHE`)
- MIT License (`LICENSE-MIT`)
