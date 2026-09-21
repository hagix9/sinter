# Sinter

[English](README.md) | **日本語**

**ドキュメント:** <https://hagix9.github.io/sinter/ja/> ([English](https://hagix9.github.io/sinter/))

**Small enough to understand, strong enough to trust.**

Sinterは、Itamaeに着想を得た軽量なエージェントレス構成管理ツールです。
単一のRustバイナリからOSの構成を記述・適用し、管理対象ホストには
SinterエージェントやSinterランタイム、Ruby、Pythonを必要としません。

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

Sinter **v0.4.1** は、対応するすべての Linux x86_64 プラットフォーム
ラインを1つの `sinter-v0.4.1-linux-x86_64.tar.gz` アーティファクトで
配布します。UbuntuとRockyのラインに加え、受入検証済みの
RHEL 9 / 10、AlmaLinux 9 / 10 対応が追加されました。

```sh
curl -fsSL https://hagix9.github.io/sinter/install.sh | sh
$HOME/.local/bin/sinter --version
```

受入検証したpoint release（v0.4.1）は Ubuntu 24.04.5 LTS、
Ubuntu 26.04.1 LTS、Rocky Linux 9.8、Rocky Linux 10.2、RHEL 9.8、
RHEL 10.2、AlmaLinux 9.8、AlmaLinux 10.2（すべてx86_64）です。
他の各point releaseを個別に受入検証したという意味ではありません。

インストーラは公式GitHubの最新安定版を選び、展開前にSHA256SUMSを検証し、
sudoを使わず `$HOME/.local/bin` に配置します。必要なら自分でPATHへ追加して
ください。シェル設定は変更しません。実行前の内容確認と手動ダウンロードは
[インストール](https://hagix9.github.io/sinter/ja/getting-started/installation/)を参照してください。

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
  main.rs          CLI
tests/             acceptance and integration test suites
```

## ライセンス

Sinterは以下のいずれかを選択できるデュアルライセンスです。

- Apache License, Version 2.0 (`LICENSE-APACHE`)
- MIT License (`LICENSE-MIT`)
