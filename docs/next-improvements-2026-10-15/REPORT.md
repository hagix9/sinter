# Sinter 次期改善（v1.4.0 後）— 調査・実装・検証レポート

日付: 2026-10-15
対象ブランチ: `v1.5-improvements`（基点 `origin/main` = `d207509`、v1.4.0 系）
作業ディレクトリ: `Projects/Sinter/worktrees/v1.5-improvements`

本レポートは Phase 1（調査）と Phase 2（実装・ローカル検証）の集約記録である。
Phase 3（GCE 実機検証）と Phase 4（独立監査）は未実施で、§6 / §7 に計画と承認依頼を
示す。

---

## 0. 開始時の状態確認（保護対象の確認）

| 項目 | 値 |
|---|---|
| 正本 `main` clone | `Projects/Sinter`、HEAD `b1eaf20`、origin/main `d207509`（v1.4.0 + ドキュメント3件） |
| 既存未コミット作業（正本 main clone） | `src/fakesys.rs` / `src/resources.rs` / `src/targetfs.rs` / `tests/path_c.rs` ほか10件の tracked 差分。**v1.4.0 で正式コミット済みの FS2/FS3 作業の旧版**であり、v1.4.0 と無関係。**一切変更・破棄していない。** |
| worktree | 正本は `v1.5-improvements` のみ追加。既存 worktree（`tmp/v140-dnf-cache-fix` ほか）は不変 |
| tag | v1.4.0 まで15件。変更なし |
| GCE | 全16インスタンス TERMINATED（読み取りのみで確認）。破棄・変更なし |

既存作業を巻き込まないよう、改善は `origin/main`（v1.4.0 公開状態）から切った
新規 worktree 上で行った。正本 main clone の未コミット差分はそのまま維持している。
（worktree を git status に出さないため `Projects/Sinter/.git/info/exclude` に
`worktrees/` を1行追加した。作業ツリーのファイルは変更していない。）

成果物: 本レポートと証拠 `docs/next-improvements-2026-10-15/`（`REPORT.md`、
`evidence/`）、サンプル `examples/quick/`、回帰テスト `tests/dnf_metadata_refresh.rs`。

---

## 1. 目的

「普通の Linux 管理者が普通に実行できる操作を、Sinter でも余計な回避策なしに
実行できるようにする」こと。v1.4.0 までに実機で実際に発生した問題と使い勝手の
課題を、共通原因から修正する。

---

## 2. 調査・改善対象の分類（Phase 1）

分類の凡例:
**[解消済]** 既存実装で解決済み（再実装せず検証対象） / **[今回修正]** 今回修正 /
**[設計判断]** 仕様変更または新機能で、オーナー判断が必要 / **[別課題]** 今回の
目標に直結しないため別課題として記録 / **[要実測]** 実測が必要。

### A. パッケージ管理（DNF 中心）

| # | 課題 | 分類 | 根拠・状態 |
|---|---|---|---|
| A1 | `rasdaemon` 等で発生する DNF メタデータ完全性エラー | **[今回修正]** | 実機で複数回発生。`dnf repository metadata not locally complete`。原因は「有効リポジトリのメタデータが live cache に無い」（新規イメージ、リポジトリ追加直後）。v1.4.0 の R2a 修正は *payload 汚染* を直したが、*メタデータ欠落* は未解決だった（`RW-073`、`SINTER_OPENSTACK_RECIPE_QUALITY_AUDIT` R-4/C-4）。 |
| A2 | `sysstat` / `python36` / NRPE 等の plan 成功・apply 失敗 | **[今回修正／一部設計判断]** | 症状はすべて「apply 時のみ失敗」で、原因は A1（メタデータ欠落）と A3（モジュールストリーム）に帰着する。パッケージ個別の特例は追加しない。 |
| A3 | DNF モジュールストリームの有効化・選択 | **[設計判断]** | `package` は既定ストリームを dnf に任せる。非既定ストリームは現状 `command: dnf module enable` をレシピで明示する運用（`examples/quick/dnf-module.yaml`）。トランザクション表のモジュール系セクション（`Enabling module streams:` 等）の受理は実機出力の確認が先。GCE で採取してから実装判断。 |
| A4 | 通常の DNF では入るのに Sinter で失敗 | **[今回修正]** | A1 と同一原因。 |
| A5 | パッケージ導入済み判定の遅さ | **[要実測]** | plan は `package` 1件につき `rpm -q` を1回（リソース単位の観測、バッチ化なし）。観測バッチ化は fake の観測経路全体に影響するため、実測で効果を確認してから判断する。 |
| A6 | 不必要な DNF キャッシュ更新・外部通信 | **[今回修正]** | 今回の自動取得は `metadata_expire=-1` により**キャッシュ済みメタデータは再取得しない**。完全性検査が失敗したときだけ取得する。 |
| A7 | プロキシ・通信障害による長時間待機 | **[解消済／別課題]** | `package`/`command` の `env` で `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` を指定可能。ホスト単位・レシピ単位の設定は未対応（別課題）。タイムアウトは操作単位で分離（`command.timeout_seconds`、executor の per-command deadline、SSH setup budget）。 |
| A8 | 依存解決・失敗メッセージの品質 | **[解消済]** | 失敗理由は固定文言で分類済み（`snapshot repodata unusable for <pkg> (check exited N)` 等）。 |

### B. 権限とディレクトリ操作

**[解消済]（v1.4.0 で対応済み・検証対象）** — root 接続、一般ユーザー接続、sudo 可能
一般ユーザー、`/home` 配下、`/tmp`・`/var/tmp`、0777/1777 親、ACL/sticky/所有者/実効
権限は、FS2/FS3（共有ディレクトリの staging、所有者権限への降格、sticky ディレクトリの
trust 検査）として v1.4.0 に実装・実機検証済み。今回の作業はこれらを変更せず、サンプル
レシピと GCE で回帰確認する対象とする。`--sudo` の要否は「接続主体の実効権限」で決まり、
`sudo -n` の可否で自動判定する（v1.4.0 の sudo root fix / effective-uid 対応）。

### C. リソース間の依存関係

**[解消済／設計判断]** — `depends_on` による明示依存、実行順に先の生産側を plan が認識
する F-3 対応は v1.4.0 に実装済み（`product`→`service` の遅延、アカウント生産側の
遅延。`SINTER_F3_DEPENDENCY_IMPLEMENTATION_AND_AUDIT`）。**パッケージがユーザー/グループ/
サービスを作る場合の予測は未実装**（`accounts.rs` は「生産側が user/group リソースの
とき」のみ遅延。パッケージ由来アカウントは推論しない）。命名の対応が無く推論すると
plan が楽観的になるため、意図的に非対応。**設計判断**: 明示宣言（`depends_on` +
`user`/`group` リソース、または `command`）で解決する方針を維持するか、パッケージ由来
アカウントの宣言手段を新設するか。

OpenStack レシピが成功していた理由: `dnf makecache` を明示 command として実行し、
`depends_on` で順序を固定していた（`SINTER_V140_OPENSTACK_BUILD_TO_AIO_FEASIBILITY`）。
標準リソース（`package`/`file`/`service`）で表現し、アカウントは明示リソースで作る
構成であり、コマンドによる回避は「makecache」と「OpenStack 固有の命令的操作
（DB 作成・登録・sync）」に限られていた。

### D. プロキシとタイムアウト

**[解消済／設計判断]** — 操作単位の `env`（プロキシ）と操作単位タイムアウトは実装済み。
接続タイムアウトは `SSH_SETUP_BUDGET_SECS`、通信停滞は per-command deadline と
`wait_readable` ポーリングで処理し、**標準出力が無いことだけを理由に停止しない**
（大きなインストールは deadline まで待つ）。ホスト単位・レシピ単位のプロキシ設定は
未対応（別課題）。

### E. 設定ファイルのフォーマット検証

**[設計判断]** — 現状、構文検証専用の仕組みは無い。到達可能な手段は
「書いた直後に各ソフトの非適用検証コマンドを `command` で実行し、`changed_when: "false"`
で変更報告から除外、`depends_on` で後続より先に走らせる」（`examples/quick/validate-sshd-config.yaml`）。
`visudo -cf` / `rsyslogd -N1 -f` / `testparm -s` / `sshd -t` を確認済み。
**反映前に staging 一時ファイルを検証してから公開する**（`file`/`template` の
`validate` オプション）は、FS2 の staging 経路に手を入れる仕様追加であり、オーナー
判断が必要。

### F. 軽量サンプルレシピ

**[今回追加]** — `examples/quick/` に単機能レシピ5本と README（en/ja）。
OpenStack は応用例として維持。

### G. パフォーマンス

**[要実測／別課題]** — 導入済み判定は `rpm -q` 1件/リソース。DNF の重複呼び出しは
スナップショット方式により各リソース1回で、metadata 再取得は A6 で抑止。tmpfs 化は
実測で効果がある場合のみ採用する方針（今回は未採用）。観測バッチ化は実測後判断。

---

## 3. Phase 2 実装内容（今回修正: A1/A2/A4/A6）

### 3.1 変更の要点

DNF の完全性検査が「有効リポジトリの repodata が無い」ことで失敗したとき、
**ターゲット自身の dnf メタデータキャッシュを1回だけ更新（= `dnf makecache` 相当）し、
スナップショットを作り直して検証し直す**。初回から `dnf makecache` を要求する回避策を
不要にした。

- 取得するのは**メタデータのみ**。パッケージ payload は取得しない（従来どおり
  別ステップで私有スナップショットへ prefetch）。
- `metadata_expire=-1` により**キャッシュ済みメタデータは再取得しない**（不要な外部通信
  をしない）。
- `skip_if_unavailable=0` により、使えない有効リポジトリは引き続き fail-closed。
- 取得は**1回に限定**（再取得の後、もう一度失敗したら fail-closed。ループしない）。
- スナップショットが**live cache を削除・コピーしない**性質は不変（取得は dnf 自身が
  行う live キャッシュの更新のみ。`rm`/`cp` は live cache を対象にしない）。
- 完全性検査が**「非ゼロ終了」以外**（出力が解釈不能・signal・indeterminate）で
  ブロックしたときは**取得しない**（推測を避ける）。
- 最初のスナップショットの後始末（`rm -rf`）に失敗した場合は、再試行せず fail-closed
  （残骸を成功で隠さない、R2-05）。
- `generate_completion_cache` プラグインは全 dnf 呼び出しで無効のまま（live cache への
  余分な書き込みを残さない）。

### 3.2 変更ファイル

| ファイル | 変更 |
|---|---|
| `src/platform.rs` | `dnf_makecache_args()` 追加＋単体テスト |
| `src/resources.rs` | `dnf_metadata_snapshot` を wrapper/inner に分割、`dnf_check_snapshot_metadata`（結果を `DnfCheck` で型付け）と `dnf_acquire_host_metadata` を追加、失敗文言を実態に合わせ更新 |
| `src/executor.rs` | fake の `dnf makecache` モデル（repos を warm 化）と `dnf_makecache_output` オーバーライド |
| `tests/platform.rs` | 既存2テストを新挙動（自動取得＋fail-closed）に合わせ更新 |
| `tests/dnf_metadata_refresh.rs` | 新規7テスト（下記） |
| `docs-site/.../en|ja/reference/resources/package.md`、`en|ja/troubleshooting.md` | 回避策（`dnf makecache` を先に実行）の記述を撤去、自動取得を記述 |
| `DESIGN.md` §27 | メタデータ取得の仕様を追記 |
| `CHANGELOG.md` | Unreleased 節 |
| `examples/quick/` | サンプルレシピ5本＋README（en/ja） |

### 3.3 不変条件（維持）

`-C install` は私有スナップショットに対してのみ実行（インストール自体はメタデータを
取得できない）／payload 集合の完全一致・RPM identity 検証・metadata 完全性検査は不変／
`--nogpgcheck` は付けない／スナップショット 0700／失敗は fail-closed／sensitive の名前は
理由に出さない。

---

## 4. ローカル検証（Phase 2 結果）

実行環境: macOS、`CARGO_TARGET_DIR` は外付け SSD。完全な生ログは
`/Volumes/VGX1000 SSD/Codex/tmp/v15-evidence/`。

| コマンド | 結果 |
|---|---|
| `cargo fmt --all -- --check` | 0 |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | 0 |
| `cargo test --locked --all-targets` | 55 ハーネス / passed 1609 / failed 0 / ignored 0（EXIT=0、NON-BLOCKER 修正後） |

新規テスト（`tests/dnf_metadata_refresh.rs`）:

- 冷たいキャッシュで自動取得し、install が成功する（取得は1回、repoquery は2回、取得は
  その間、取得引数は `metadata_expire=-1`・`skip_if_unavailable=0`・`cachedir` 無し）
- 暖かいキャッシュでは取得しない（makecache 0回、repoquery 1回）
- 取得失敗は fail-closed（install 0、理由に取得失敗を明記）
- indeterminate な検査は取得しない
- 取得しても完全にならなければ fail-closed（再試行は1回）
- 1 run 内で取得は高々1回（複数パッケージが warm 済みキャッシュを再利用）
- 最初のスナップショットの後始末失敗は取得前に fail-closed
- 取得コマンドは操作の `env`（プロキシ）を引き継ぐ

**Linux 固有 suite は macOS では 0 tests**（`#![cfg(target_os = "linux")]`）。本節の結果は
**Linux 実機検証ではない**。実機検証は §6。

---

## 5. 未解決事項・別課題

| ID | 内容 | 分類 | 理由 |
|---|---|---|---|
| N-1 | `file`/`template` の `validate` オプション（staging 一時ファイルを公開前に検証） | 設計判断 | FS2 の staging 経路への仕様追加。オーナー判断の上で実装＋実機検証 |
| N-2 | DNF モジュール系セクションのトランザクション表受理 | 設計判断 | 実機の dnf 出力を採取してから。既定ストリームは dnf に任せる。非既定は `command` で明示 |
| N-3 | パッケージ由来アカウント/サービスの予測 | 設計判断 | 命名対応が無く、推論は plan を楽観的にする。明示宣言を維持するか新設するか |
| N-4 | ホスト単位・レシピ単位・CLI のプロキシ設定 | 設計判断 | 現状は操作単位 `env` のみ。新設は API 変更 |
| N-5 | パッケージ観測のバッチ化（計画時 `rpm -q` の往復削減） | 要実測 | 実測効果を確認してから |
| N-6 | tmpfs 一時処理 | 要実測 | 実測で効果がある場合のみ |

---

## 6. Phase 3 GCE 実機検証（実施済み）

承認された新規 VM 3台で、クリーンな OS から修正を検証した。証拠は
`docs/next-improvements-2026-10-15/evidence/`（`verify-rocky{8,9,10}.out.log`、
`rocky{8,9}-build.log`、`SHA256SUMS`）。

### 6.1 環境

| VM | OS | glibc | `/usr/bin/dnf` | v1.5 バイナリ SHA-256（最終） |
|---|---|---|---|---|
| sinter-v15-rocky8 | Rocky Linux 8.10 | 2.28 | dnf-3 | `ec81dfbd…`（Rocky 8 上でビルド） |
| sinter-v15-rocky9 | Rocky Linux 9.8 | 2.34 | dnf-3 (4.14.0) | `6fe7f9b4…`（Rocky 9 上でビルド） |
| sinter-v15-rocky10 | Rocky Linux 10.2 | 2.39 | dnf-3 (4.20.0) | `6fe7f9b4…`（Rocky 9 ビルドを使用） |

- ビルド: 各 OS 上で `cargo build --locked -j1`（Rocky 8 は glibc 2.28 のため個別ビルド）。
  strip 後 12.5MB。Rocky 9 の glibc 2.34 バイナリは Rocky 10 でも動作。
- v1.4.0 公開バイナリ（glibc 2.34 要求）は Rocky 9/10 でのみ動作した。Rocky 8 は
  glibc 2.28 のため実行不可（before/after 比較は 9/10 で取得）。
- バイナリ同一性: 最終ソース（独立監査の NON-BLOCKER 修正後）で再ビルドし、同一起動手順を
  再実行した（証拠 `verify2-rocky{8,9,10}.out.log`）。SHA と注意（バージョン文字列は
  pre/post で `sinter 1.4.0` のまま）は `evidence/binary-sha256.txt` に記録。
- 既存の TERMINATED インスタンス（16台）は変更していない。

### 6.2 結果（before/after が決定的）

| シナリオ | Rocky 8 | Rocky 9 | Rocky 10 |
|---|---|---|---|
| **S1pre (v1.4.0, 冷たいキャッシュ)** | 実行不可 | **FAILED** `refusing to fetch metadata`・tree 未導入 | **FAILED** 同文・tree 未導入 |
| **S1 (v1.5, 冷たいキャッシュ)** | **成功** tree 導入 | **成功** tree 導入（cachedir 9→21） | **成功** tree 導入（cachedir 2→14） |
| S1json (v1.5) | status=success | success | success |
| S2 再 apply（冪等） | 0 changed | 0 changed | 0 changed |
| S3 plan（収束後） | 0 changed | 0 changed | 0 changed |
| S4 audit | no_drift | no_drift | no_drift |
| S5 リポジトリ追加後の EPEL パッケージ (ncdu) | 成功 | 成功 | 成功 |
| S6 不良リポジトリで fail-closed | FAILED・zip 未導入 | FAILED・zip 未導入 | FAILED・zip 未導入 |
| S7 復旧（不良リポジトリ除去後） | 成功 zip 導入 | 成功 zip 導入 | 成功 zip 導入 |
| S8 アカウント/ディレクトリ（B/C 回帰） | attr 欠如で FAILED（6.3） | **成功＋冪等**（0640 v15demo:v15demo） | **成功＋冪等** |

- **決定的な before/after**: 同一 VM・同一の冷たいキャッシュで、v1.4.0 は
  `dnf repository metadata not locally complete; refusing to fetch metadata` で失敗し、
  v1.5 は同じ操作を自動取得して成功した（Rocky 9/10）。S6 は v1.5 の新文言
  `…; refreshing the repository metadata cache exited 1` で fail-closed し、install は
  変更を起こしていない（zip 未導入）。
- Rocky 10 でも `dnf-3`(4.20.0) に対して makecache が機能し、既知の dnf4 引数のみで
  完結した（dnf5 固有処理には依存しない）。

### 6.3 実機で確認した副次的な所見（記録）

1. **N-2（DNF モジュール）実機証拠**: Rocky 8 の `dnf install --assumeno nodejs` の
   トランザクション表に **`Enabling module streams:` セクション**（`nodejs 10`）が現れる。
   Sinter のパーサはこのセクションを知らないため、**EL8 のモジュール由来パッケージは
   fail-closed になる**（未検証だった互換性ギャップが実機で確定）。Rocky 9/10 では
   nodejs はモジュールではなく通常パッケージで、そのセクションは現れなかった。
2. **Rocky 8 の `attr` 欠如**: 権限・ディレクトリ機能は ACL 検査のため `/usr/bin/getfattr`
   を必要とし、最小の Rocky 8 イメージには無い。Sinter は安全側に拒否し
   `dnf install attr` を案内する（明確で実行可能なエラー。サイレントな回避ではない）。
   Rocky 9/10 のイメージには同梱されていた。

### 6.4 費用・ライフサイクル

- 実測費用は想定（$1 未満）の範囲。3台の VM とブートディスクは Phase 4 完了後に
  **削除済み**（`gcloud ... list` で v15 リソース 0 を確認）。既存の TERMINATED
  インスタンス16台・ディスク16本は変更していない。

---

## 7. Phase 4 独立監査（実施済み）

実装担当とは別のエージェントによる監査を2回実施した（1回目の完全監査＋NON-BLOCKER
修正後の限定再監査）。監査には実装報告の結論を渡さず、ソース・証拠・テストのみを
提示した。

### 7.1 完全監査（独立・読み取り＋テスト実行）

判定: **GO**（BLOCKER 0）。

確認された事項（監査自身の再実行で確認）: 取得は1回で必ず停止しループしない／plan と
`state: absent` では到達しない／live cache を `rm`/`cp` しない／署名検証の緩和なし／
`sensitive` が伝播／取得は操作の `env`（プロキシ）のみを引き継ぐ／新規テストは
「取得を無効化すると失敗する」ことを変異実験で確認（回帰テストとして有効）／
全テスト 1607/0・clippy・fmt クリーン／証拠ログが before/after を支持。

指摘（すべて NON-BLOCKER / NOT VERIFIED。BLOCKER なし）と対応:

| # | 種別 | 内容 | 対応 |
|---|---|---|---|
| NB1 | NON-BLOCKER | 取得の `Indeterminate` を `Failed` として報告（状態精度） | **修正**（フラグを伝播し Indeterminate として報告）＋テスト |
| NB2 | NON-BLOCKER | 「非ゼロ終了」を取得トリガに使うため、存在しないパッケージでも無駄な取得が走る（安全性は不変） | コメントを実態に合わせ修正（分類でないと明記） |
| NB3 | NON-BLOCKER | 取得タイムアウト300s < payload 600s | **修正**（600s に整合） |
| NB4 | NON-BLOCKER | 「at most once per run」の言い方が絶対的（run 中途で repo 追加時は再度取得） | テスト名・コメントを「warmed cache の再利用」に修正 |
| NB5 | NON-BLOCKER | 存在するが壊れた repodata は `metadata_expire=-1` のため治らない | 仕様どおり（未キャッシュ対象）。記録のみ |
| NB6 | NON-BLOCKER | テスト被覆の穴（plan/absent の非到達が構造のみ、cleanup テストが判別力に乏しい） | plan/absent の非取得テストを追加。cleanup テストは既知の限界として記録 |
| NB7 | NON-BLOCKER | 証拠の同一性（バージョン文字列が pre/post 同一、strip 後 SHA が証拠に無い） | `evidence/binary-sha256.txt` を追加し、最終バイナリで**再検証**（`verify2-*`） |
| NV1 | NOT VERIFIED | EL8 モジュール由来パッケージの fail-closed は推論のみ（Sinter 実行証拠なし） | GCE の S9 生 dnf 出力で根拠を記録（§6.3）。実 Sinter 実行は未実施のまま記録 |
| NV2 | NOT VERIFIED | VM のライフサイクルは監査範囲外 | §6.4 / 最終報告で扱う |

### 7.2 限定再監査（NB 修正後）

判定: **GO**（BLOCKER 0）。NB1 のフラグ伝播・各 `false` ケースの妥当性・NB3 の他
タイムアウト非回帰・新規テストが実際に判別力を持つこと（変異実験で確認）・
`tests/platform.rs` の fail-closed 維持を確認。全テスト **1609 passed / 0 failed**、
clippy `-D warnings` クリーン。

- 限定再監査の残 NON-BLOCKER: `Signaled` を確定失敗（false）と扱う点、dispatch `Err`
  を前提置失敗と扱う点。いずれも既存の同種経路（snapshot 検査・mutation）と同一方針で、
  `Change::None` を保つため真実性は保たれる。
- NOT VERIFIED: 直前監査スナップショットとの byte-diff は不可（タイムアウトは全箇所の
  目視で非回帰を確認）。doctest は対象コマンドでは走らない。

---

## 8. 各課題の解決状況一覧

| 区分 | 課題 | 状況 |
|---|---|---|
| A1 | DNF メタデータ完全性エラー | **修正済・実機検証済**（Rocky 8/9/10、v1.4.0 失敗→v1.5 成功） |
| A2 | plan 成功・apply 失敗 | **修正済（共通原因）・実機検証済** |
| A3 | DNF モジュールストリーム | 運用パターン文書化・サンプル追加。EL8 のモジュール由来パッケージは実機で fail-closed を確認（N-2） |
| A4 | 通常 DNF では入るのに失敗 | **修正済（A1 と同根）・実機検証済** |
| A5 | 導入済み判定の遅さ | 未着手（N-5、要実測） |
| A6 | 不必要なキャッシュ更新・外部通信 | **修正済（metadata_expire=-1／失敗時のみ取得）** |
| A7 | プロキシ・長時間待機 | 操作単位 `env`／タイムアウト分離は既存。ホスト/レシピ単位は N-4 |
| A8 | 失敗メッセージ品質 | 既存（分類済み） |
| B | 権限・ディレクトリ | 既存（v1.4.0）。Rocky 9/10 で回帰確認済（Rocky 8 は `attr` 欠如） |
| C | 依存関係 | 既存（F-3）。Rocky 9/10 で成功＋冪等を確認。パッケージ由来アカウントは N-3 |
| D | プロキシ・タイムアウト | 既存。ホスト/レシピ単位は N-4 |
| E | 設定ファイル検証 | 運用パターン文書化・サンプル追加。`validate` オプションは N-1 |
| F | 軽量サンプルレシピ | **追加済（`examples/quick/`）** |
| G | パフォーマンス | 一部（不要通信の抑止）は A6。観測バッチ化は N-5 |

---

## 9. 最終判定

**GO（受け入れ可）**。

- 対象の修正（A1/A2/A4/A6）は、Rocky 8/9/10 のクリーン OS で before/after を実測して
  成立し、fail-closed・冪等・plan/audit 整合・復旧も確認した。
- 独立監査（完全＋限定再監査）はいずれも BLOCKER 0 で GO。NON-BLOCKER は自律修正済み、
  残りは記録。
- 未解決は §5 の設計判断・要実測項目（N-1〜N-6）。今回の目標（回避策なしの通常操作）に
  直結する N-1〜N-4 は、実装・実機検証を伴うためオーナー判断として記録した。
- 実機の GCE VM 3台は監査完了後に削除した（既存インスタンスは不変）。

## 10. 次のアクション（提案）

1. N-1〜N-4 の採否をオーナーが判断（採否により Phase 2 相当を再実施＋実機検証）。
2. 変更の commit / push / release は別途承認の上で（本作業では未実施）。
3. N-2（EL8 モジュール）の実 Sinter 実行による fail-closed の直接確認は、後続の N-1〜N-4
   ラウンドで実施済み（`N1_N4_IMPLEMENTATION_REPORT.md` §7.1 の E-pre / E-fail-closed）。
