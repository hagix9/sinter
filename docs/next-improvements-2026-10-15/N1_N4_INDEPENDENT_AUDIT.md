# Sinter v1.5 N-1〜N-4 独立監査

日付: 2026-10-15
対象: `Projects/Sinter/worktrees/v1.5-improvements`（基点 `origin/main` = `d207509`、差分は未コミット）
実施: 実装担当とは別のエージェント（ソース・テスト・証拠のみを提示。実装報告の結論は渡していない）
監査成果物: 本ファイル。実装報告は `N1_N4_IMPLEMENTATION_REPORT.md`、証拠は `evidence/`。

## 1. 監査の方法

- ソースの再読（`src/model.rs`、`src/document.rs`、`src/ir.rs`、`src/resources.rs`、
  `src/targetfs.rs`）と差分の確認。
- 変異実験（worktree のコピーを `Codex/tmp` に作り、生産コードを変異させて新規テストが
  失敗することを確認）:
  - `run_validate` を無効化 → `tests/validate_file.rs` の 9 件中 5 件が失敗。
  - `DNF_MODULE_STREAM_SECTIONS` の処理を除去 → N-2 の受理テストが失敗。
  - `merge_recipe_env` の優先順位を反転 → 上書きテストが失敗。
- 検証の再実行: `cargo fmt --all -- --check` 0、`cargo clippy --locked --all-targets
  --all-features -- -D warnings` 0、`cargo test --locked --all-targets`
  57 ハーネス / 1629 passed / 0 failed（監査実行時点。その後 NON-BLOCKER 対応で 1632）。
  証拠ディレクトリの `SHA256SUMS` を検証（全て OK）。`examples/quick/*.yaml` の
  `sinter validate` はすべて成功。

## 2. 対象別の所見

### N-1（`file`/`template` の `validate`）

- 検証は **staging 済みファイル**に対して実行される（`run_validate` が
  `StagedObject::payload_path()` = `<staging dir>/payload` を最後の引数に付す。固定
  staging script の `cat > payload` と一致）。本番パスは渡らない。
- 検証は staging の後・公開の前に位置し、`Rejected` は `discard_staged` してから
  `FailedBeforePublish`、`Unresolved` は `ValidationIndeterminate` で**公開しない**。
  公開は検証より後の 1 箇所でしかディスパッチされない。→ **失敗時に本番ファイルが
  変更される経路は無い**。
- argv のみ（シェルなし）、`program` はロード時・実行時に絶対パス、`validate` 未指定時は
  従来経路。
- sensitive ではパスを `[redacted]`、検証の stdout/stderr を理由に含めない。
- FS2/FS3: `src/targetfs.rs`/`fsstage.*` の差分は追加の `payload_path()` のみ。trust/ACL/
  sticky/setpriv の保証は不変。
- 所見: NB-2（未確定時に staging を残す＝設計どおり）、NB-3（絶対パス再確認は防御的
  二重化）。BLOCKER なし。**GO**。

### N-2（DNF モジュールストリーム）

- 受理するのは実測した `Enabling module streams:` のみ。行は厳密な `<module> <stream>`
  （専用の文字集合）で、payload に積まず、Transaction Summary の数にも数えない。
- 未実測のモジュール系セクションは従来どおり fail-closed。
- パッケージ集合等価・RPM identity・metadata 完全性検査は不変。`Sinter` 自身が
  ストリームを選んだり module enable を発行する箇所は `src/` に無い。
- BLOCKER なし。**GO**。

### N-3（パッケージ由来アカウント・文書化）

- 自動推論をしない方針が `DESIGN.md` §14 に明記され、既存テスト
  `tests/dependency_semantics.rs::a_package_created_account_is_not_known_to_plan_before_the_package_exists`
  で固定されている。`examples/quick/accounts-and-paths.yaml`・`dnf-module.yaml` は検証を
  通過し、方針と整合。**GO（仕様判断完了）**。

### N-4（レシピ単位 `env`）

- 優先順位は変数名ごとにレシピ既定 < リソース上書き。既定は `package`/`command` のみに
  到達し（`rpm -q`・接続処理には渡らないことをテストで確認）、予約名・include での宣言・
  非文字列値は拒否。名前は変換しない。
- sensitive: 実行時は評価後の env から `command_sensitive`/`env_sensitive` が立ち、値は
  伏せられる（記録に漏れないテストあり）。
- 所見: NB-1（静的な `derived_sensitive` がマージ前の `with` から算出されていた）
  → 本ラウンドで修正（freeze 後の `with` から算出）＋テスト。BLOCKER なし。**GO**。

### 既存 DNF 自動取得の非回帰

- 実機 `verify3-rocky{8,9}.out.log` の B 節で、冷たいキャッシュからの `package` 導入が
  成功することを確認。ローカルの `tests/dnf_metadata_refresh.rs` も全 PASS。

## 3. NON-BLOCKER / NOT VERIFIED の整理

| # | 種別 | 内容 | 対応 |
|---|---|---|---|
| NB-1 | N-4 | 静的 sensitive にレシピ env が反映されない | **修正**＋テスト |
| NB-2 | N-1 | 未確定検証で staging を残す | 設計どおり。記録 |
| NB-3 | N-1 | 絶対パス再確認が到達不能（防御的二重化） | 記録 |
| NB-4 | 証拠 | Rocky 8 の C1/C2 が `attr` 導入後の再確認である点が表で不明瞭 | 実装報告 §7 を明確化 |
| NB-5 | 証拠 | pre バイナリの commit が証拠に無い | 実装報告 §7.4 に明記 |
| NV-1 | N-1 | template の validate 実機挙動が未確認 | **テスト追加** |
| NV-2 | N-4 | 大文字小文字の専用テストが無い | **テスト追加** |

## 4. 判定

**BLOCKER 0。N-1 / N-2 / N-3 / N-4 いずれも GO。** NON-BLOCKER は上記のとおり対応または
記録。監査が再実行できなかった項目（GCE の VM ライフサイクル、実機環境の再実行）は
範囲外として明記する。
