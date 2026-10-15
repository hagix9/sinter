# Sinter v1.5 N-1〜N-4 実装・検証レポート

日付: 2026-10-15
ブランチ: `v1.5-improvements`（基点 `origin/main` = `d207509`、v1.4.0 系）
作業ディレクトリ: `Projects/Sinter/worktrees/v1.5-improvements`

本レポートは N-1（`file`/`template` の `validate`）、N-2（DNF モジュールストリーム）、
N-3（パッケージ由来アカウント）、N-4（レシピ単位プロキシ）の実装・検証の集約記録である。
既存の DNF メタデータ自動取得改善（前段の `REPORT.md`）は完了済みとして扱い、再実装して
いない。独立監査は別ファイル `N1_N4_INDEPENDENT_AUDIT.md`。

## 1. 開始時の状態

- worktree `v1.5-improvements`、HEAD `d207509`、`origin/main` = `d207509`。
- 本 worktree の未コミット変更: 前段 DNF 改善（`src/resources.rs` ほか）＋今回の N-1/N-2/N-4。
- 正本 main clone `Projects/Sinter` の無関係な未コミット差分（FS2/FS3 旧版）は変更・破棄・
  stage していない。

## 2. N-1: file / template の validate

### 2.1 契約（確定した最小仕様）

`file` / `template` の任意フィールド `validate`（マップ）:

| キー | 必須 | 型 | 説明 |
|---|---|---|---|
| `program` | はい | 文字列（絶対パス） | 検証プログラム。 |
| `args` | いいえ | 文字列のリスト | 引数。 |
| `timeout_seconds` | いいえ | 整数 1..86400 | 既定 300。 |

実行: `program args... <staging ファイル>` を、シェルの介在なしの argv のみで、
操作自身の権限で、**staging 済みで未公開**のファイルに対して実行する。本番パスは
検証コマンドに渡らない。

結果:
- 終了コード 0 → 公開を許可（従来の atomic publication をそのまま実行）。
- 非ゼロ終了・signal・dispatch 失敗 → 内容を拒否。staging を破棄し、本番は**未変更**
  （Failed / change none）。staging の検証に到達した時点で未公開なので、本番ファイルが
  変更されることはない。
- timeout・応答不明（indeterminate） → 公開を試行せず（未公開は確定）、staging は
  証拠として残す（Indeterminate / change none）。
- `validate` 未指定 → 従来どおり（挙動不変）。

### 2.2 実装（変更ファイルと理由）

| ファイル | 変更 |
|---|---|
| `src/model.rs` | `FILE_FIELDS`/`TEMPLATE_FIELDS` に `validate` を追加。`validate_validate_spec()` で形状検査（宣言時・freeze 時）。 |
| `src/resources.rs` | `ValidateSpec` と `ev_validate()`、`ValidateOutcome`、`run_validate()` を追加。`run_file`/`run_template`→`file_present`→`publish_file` に `validate` を通し、staging 成功後・公開前に検証する。`PublishOutcome::ValidationIndeterminate` を追加（未公開を確定）。 |
| `src/targetfs.rs` | `StagedObject::payload_path()`（`<staging dir>/payload`）を追加。固定 staging script が payload を常に `payload` と命名する事実に基づく。 |
| `tests/validate_file.rs` | 新規9テスト。 |
| `tests/frontends.rs` | フィールド表テストに `validate` のサンプル値を追加。 |
| docs（en/ja `file.md`・`template.md`）、`DESIGN.md` §24.4、`CHANGELOG.md`、`examples/quick/validate-sshd-config.yaml` | 利用者向け・設計の記述。 |

### 2.3 既存の安全性保証の維持

検証は staging と publication の間の一手順として追加し、既存の atomic publication、
trust boundary、ACL、sticky directory、setpriv の各保証は変更していない。検証コマンドは
操作の mutation permit で実行され、sensitive なリソースでは検証の stdout/stderr を理由に
含めない。`validate` 未指定時はパスが変わらない。

### 2.4 ローカルテスト

`tests/validate_file.rs`（10件、すべて PASS。件数は NV-1 の `template` テスト追加後）:
公開前検証の成功で公開／失敗で本番不変（既存ファイル）／失敗で未作成（新規）／
timeout で未公開・change none／`validate` 未指定は従来どおり公開／sensitive で検証出力と
パスを漏らさない／冪等（収束後は検証しない）／`template` の validate も拒否時に本番不変／
モデル形状検証／正常形の受理。

## 3. N-2: DNF モジュールストリーム

### 3.1 実機証拠（Rocky 8.10 / dnf 4.14 で採取済み）

`dnf install --assumeno nodejs` のトランザクション表は次を含む（前段 Phase 3 の
`evidence/verify2-rocky8.out.log`）:

```
Installing:
 nodejs ...
Installing dependencies:
 npm ...
Installing weak dependencies:
 nodejs-full-i18n ...
Enabling module streams:
 nodejs                     10
```

`Enabling module streams:` はトランザクション表内のセクションで、その行は
`<module> <stream>` の 2 列であり、パッケージ payload ではない。

### 3.2 修正（実測した形式のみ受理）

- `DNF_MODULE_STREAM_SECTIONS = ["Enabling module streams:"]` を追加（**実測した形式のみ**）。
- モジュールセクションの行は `is_module_stream_row()`（厳密に `<module> <stream>`、
  トークンはモジュール名/ストリームの文字集合）で検証して**読み飛ばす**。パッケージ row に
  積まない。
- 未知のモジュール系セクション（例 `Installing module profiles:`）は従来どおり fail-closed。
- パッケージ集合・バージョン・arch・RPM identity・集合等価検査は一切緩めていない。
- 非既定ストリームの自動選択や暗黙の module enable は**追加していない**。dnf 自身が既定
  ストリームを有効化するのを Sinter は「出力を理解する」だけである。副作用は dnf の
  トランザクションの一部（`/etc/dnf/modules.d/<module>.yaml` の更新）で、`package` の
  既存契約（メンテナスクリプトの副作用、DESIGN §27）の範囲内。

### 3.3 ローカルテスト

`src/resources.rs` 単体（3件、PASS）:
実測表（nodejs）を受理し package row のみを payload とする／不正なモジュール row は
fail-closed／未実測セクションは fail-closed。

## 4. N-3: パッケージ由来アカウント（設計判断完了・実装なし）

- パッケージが作成するユーザー・グループ・サービスを名前から推測しない方針を維持。
- 既存の回帰テスト
  `tests/dependency_semantics.rs::a_package_created_account_is_not_known_to_plan_before_the_package_exists`
  が当該方針（package は account の producer ではない）を固定していることを確認した。
  追加テストは不要。
- `DESIGN.md` §14 に「Accounts and services created by a package are not inferred」を追記。
  明示的な `user`/`group`/`command`＋`depends_on` の安全な運用例は
  `examples/quick/accounts-and-paths.yaml` に記載。

## 5. N-4: レシピ単位のプロキシ（レシピ env）

### 5.1 契約

- トップレベル `env`（文字列のマップ）は、レシピ内のすべての `package` / `command`
  リソースに与える既定環境。
- 優先順位は**変数名ごと**に、リソース自身の `env` がレシピ `env` を上書き。既定が
  明示値を置き換えることはない。
- 適用範囲は `package` と `command` のみ。接続処理・パッケージ/サービスの問い合わせ・
  ファイル操作・service には渡さない。
- 名前は大文字小文字を区別（Linux と同様）。Sinter は変換しない（`HTTP_PROXY` と
  `http_proxy` は別物、両方をそのまま渡す）。予約名 `PATH`/`LANG`/`LC_ALL`/`HOME` は拒否。
- 値は `vars`/`facts` を補間可能。`sensitive` 変数由来の値を使うと継承リソースが
  sensitive になり、値はすべての出力で伏せられる。
- `env` は実行するレシピ本体にのみ書ける（include されたファイルでは拒否）。
- ホスト単位の `env` は設けない（インベントリはホスト変数を持たない＝DESIGN §19.2/§36 の
  既存の制約）。ホストごとの差は別レシピ/include で表現。

### 5.2 実装

| ファイル | 変更 |
|---|---|
| `src/ir.rs` | `TOP_LEVEL_FIELDS` に `env`。 |
| `src/document.rs` | `Document.env` と `validate_recipe_env()`（名前・予約名・値型）。 |
| `src/model.rs` | `LoadState.recipe_env`、entry-only（include で拒否）、`merge_recipe_env()`（package/command のみ、リソース env が優先）、`RESERVED_ENV` を `pub(crate)`。 |
| `tests/recipe_env.rs` | 新規8テスト。 |
| docs（en/ja `recipe-format.md`）、`DESIGN.md` §27.1、`CHANGELOG.md`、`examples/quick/package-proxy.yaml` | 記述。 |

### 5.3 ローカルテスト

`tests/recipe_env.rs`（10件、PASS。件数は NB-1／NV-2 のテスト追加後）:
command へ伝播／リソース env が優先／package の dnf transport へ伝播し `rpm -q` には
渡らない／無関係コマンドへ渡らない／名前は大文字小文字を区別し変換しない／sensitive 由来の
既定 env が静的な sensitive を立てる／sensitive 値が記録に漏れない／形状検証（4 不正形）／
include で拒否／`env` なしは従来どおり。

## 6. 回帰（ローカル）

| コマンド | 結果 |
|---|---|
| `cargo fmt --all -- --check` | 0 |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | 0 |
| `cargo test --locked --all-targets` | 57 ハーネス / passed 1629 / failed 0 / ignored 0 |

既存の DNF 自動取得テスト（`tests/dnf_metadata_refresh.rs` ほか）と FS2/FS3 系を含め回帰
なし。

## 7. GCE 実機検証（実施済み）

新規 VM 2台（Rocky 8.10 / Rocky 9.8、e2-small、asia-northeast1-a）で検証した。承認の上で
作成し、検証後に削除する。既存の TERMINATED インスタンスは変更していない。

- ビルド: 各 OS 上で `cargo build --locked -j1`（Rocky 8 は glibc 2.28 のため個別ビルド）。
  比較用の**修正前**バイナリは `origin/main`（`d207509`）から同じ手順で各 OS 上にビルドした
  （`sinter-pre`）。
- v1.5b バイナリ sha256: Rocky 8 `8a0e65722716025c…`、Rocky 9 `d79f2401b54c2548…`。
- sinter-pre バイナリ sha256: Rocky 8 `7541d987f856d3cb…`、Rocky 9 `8f0d73af7d4172b8…`。

### 7.1 結果

| 検証 | Rocky 8.10 | Rocky 9.8 |
|---|---|---|
| B: 冷たい dnf キャッシュ→`package` 導入（DNF 回帰） | 成功（tree 導入） | 成功（tree 導入） |
| C1: `validate` 正常（有効な sshd drop-in） | 成功・公開（`sshd -t` OK）※ | 成功・公開（`sshd -t` OK） |
| C2: `validate` 失敗（不正な sshd 内容） | **拒否・本番ファイル不変**（sha256 前後一致・`sshd -t` OK） | 同左 |
| D: レシピ `env` 伝播＋リソース上書き | `proxy=...` / 上書き値とも期待どおり | 同左 |
| E-pre: モジュールパッケージ（nodejs、修正前） | **FAILED** `cannot establish the install transaction set`・未導入 | （Rocky 9 はモジュール非使用のため対象外） |
| E-post: 同（v1.5） | **成功** nodejs 導入・`nodejs 10` ストリーム有効化 | 対象外 |
| E-idempotent: 再 apply | 0 changed | 対象外 |
| E-fail-closed: 存在しないパッケージ | **FAILED**・未導入 | **FAILED**・未導入 |

- **N-2 は決定的**: 同一 VM・暖かいキャッシュで、修正前は `Enabling module streams:` を
  含むトランザクション表を解釈できず fail-closed、v1.5 は同じ操作を成功させ、dnf が
  既定ストリーム `nodejs 10` を有効化した（`dnf module list --enabled` で確認）。
- **N-1 は実機で成立**: 不正な内容は公開されず、既存の本番ファイルは**バイト単位で不変**
  （sha256 前後一致）、公開済みファイルは `sshd -t` を通過。
- **N-4 は実機で成立**: レシピ `env` が command に渡り、リソース `env` が該当名を上書き。

※ Rocky 8 の N-1（C1/C2）は、最初の `verify3-rocky8.out.log` では最小イメージに `attr`
（`/usr/bin/getfattr`）が無いため**環境要因で**パス信頼境界検査に拒否された。`attr` 導入後に
`verify3-rocky8-N1.log` で再確認し、C1 成功・C2 拒否＋本番不変（sha256 `50714428…` 前後
一致）を確認した。表の Rocky 8 C1/C2 はこの再確認の結果である。

### 7.4 バイナリの来歴

- v1.5b: 本 worktree の未コミット作業（`origin/main` = `d207509` に対する差分）を各 OS 上で
  ビルド。sha256 は §7 のとおり。
- sinter-pre（比較用の修正前）: `git archive origin/main`（= `d207509`、v1.4.0 系）を各 OS 上で
  同じ手順（`cargo build --locked -j1`→`strip`）でビルド。`build-pre.sh` と
  `v15b-rocky{8,9}-install.log` に残る。両バイナリが `sinter 1.4.0` と表示するため、ログの
  識別は修正前の失敗文言（`refusing to fetch metadata` / `cannot establish the install
  transaction set`）と修正後の成功で行っている。

### 7.2 実機で確認した環境所見（記録）

- 最小の Rocky 8 イメージには `attr`（`/usr/bin/getfattr`）が無く、Sinter のパス信頼境界
  検査が安全側に拒否する（`dnf install attr` を案内）。`attr` を導入後、N-1 は Rocky 8 でも
  成立した。これは Sinter の欠陥ではなく、明示的で実行可能なエラーである。

### 7.3 証拠ファイル

`evidence/verify3-rocky{8,9}.out.log`、`evidence/verify3-rocky8-N1.log`、
`evidence/v15b-rocky{8,9}-{build,install}.log`、`evidence/build-pre.sh`、`evidence/verify3.sh`、
`evidence/SHA256SUMS`。索引は `N1_N4_EVIDENCE_INDEX.md`。

## 8. 未解決・別課題

- N-2: 実測したのは `Enabling module streams:` のみ。`dnf module install`（profile/group）
  系のセクションは未対応（fail-closed のまま）。実測したら追加検討。
- N-4: ホスト単位の `env` と CLI フラグは対象外（インベントリのホスト変数禁止と整合）。
- N-1: 検証コマンドが config を中間ファイルに分割する等、複数ファイルを要する検証は
  単一 staged ファイルの契約では表現できない（将来課題）。
- N-1: timeout/応答不明で検証が未確定のとき、staging ディレクトリは証拠として残す
  （公開は確定して行わない）。運用者向けの注意として `file.md` に記載。

## 9. 独立監査と最終判定

独立監査（実装担当とは別エージェント）を1回実施した。詳細は
`N1_N4_INDEPENDENT_AUDIT.md`。**BLOCKER 0、全項目 GO**。

監査の NON-BLOCKER（本ラウンドで対応）:
- NB-1（N-4）: レシピ `env` の sensitive 由来が静的な `derived_sensitive` に反映されない
  → **修正**（freeze 後の `with` から算出）＋テスト。
- NB-4/NB-5（証拠の来歴）: Rocky 8 の C1/C2 が `attr` 導入後の再確認であること、pre
  バイナリが `origin/main`（`d207509`）由来であることを §7.3/§7.4 に明記。
- NOT VERIFIED（template の validate 実機挙動／大文字小文字）→ **テスト追加**。

監査の残 NON-BLOCKER（記録のみ）:
- NB-2: 未確定検証で staging を残す（設計どおり、公開は行わない）。
- NB-3: `run_validate` の絶対パス再確認は防御的二重化（現状到達不能）。

### 最終判定

| 項目 | 判定 |
|---|---|
| N-1（`file`/`template` の `validate`） | **GO**（ローカル＋Rocky 8/9 実機＋独立監査） |
| N-2（DNF モジュールストリーム） | **GO**（Rocky 8 で before/after 実測＋独立監査） |
| N-3（パッケージ由来アカウント） | **仕様判断完了**（設計・文書化・既存回帰テストで固定） |
| N-4（レシピ単位 `env`） | **GO**（ローカル＋Rocky 8/9 実機＋独立監査） |
| v1.5 改善候補全体（既存 DNF 改善含む） | **GO**（commit 準備へ進める状態） |

commit / push / tag / release は未実施（別途承認）。既存 v1.4.0 資産は変更していない。
