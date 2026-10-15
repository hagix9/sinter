# Sinter v1.5 N-1〜N-4 証拠索引

日付: 2026-10-15
場所: `docs/next-improvements-2026-10-15/evidence/`
完全性: 同ディレクトリの `SHA256SUMS`（`shasum -a 256 -c SHA256SUMS` で検証可能）。

## GCE 実機（新規・使い捨て・検証後に削除）

| ファイル | 内容 |
|---|---|
| `verify3-rocky8.out.log` | Rocky 8.10: B（冷キャッシュ→package 成功）、N-1（`attr` 欠如で環境要因拒否）、N-4（env 伝播）、N-2（pre 失敗→v1.5 成功・冪等・fail-closed） |
| `verify3-rocky9.out.log` | Rocky 9.8: B、N-1（公開→拒否＋本番不変）、N-4、存在しないパッケージの fail-closed |
| `verify3-rocky8-N1.log` | Rocky 8.10: `attr` 導入後の N-1 再確認（公開→拒否＋本番不変） |
| `v15b-rocky8-build.log`, `v15b-rocky9-build.log` | v1.5b のビルド（`cargo build --locked -j1`、argv 記録付き、ビルド手順・依存導入） |
| `v15b-rocky8-install.log`, `v15b-rocky9-install.log` | v1.5b のインストールと、pre（`origin/main`）ビルド・インストール |
| `build-pre.sh` | pre バイナリのビルド手順（`origin/main` のソースを `cargo build --locked -j1`→`strip`） |
| `verify3.sh` | 実機検証スクリプト（再実行可能・冒頭で baseline にリセット） |

VM（`sinter-v15b-rocky8` / `sinter-v15b-rocky9`、e2-small、`asia-northeast1-a`）は検証後に
削除する。既存の TERMINATED インスタンスは変更していない。

## ローカル（macOS）

| ファイル | 内容 |
|---|---|
| `full-test.log` | 前段 DNF 改善の全テスト（v1.5b の前段時点） |
| `full-test-post-nonblocker.log` | 前段の NON-BLOCKER 修正後の全テスト |
| `n14-final-full-test.log` | N-1/N-2/N-4 実装後の最終全テスト（57 ハーネス / 1632 passed / 0 failed） |
| `audit2-test-full.log`, `audit2-clippy.log` | 前段の限定再監査の実行ログ |
| `binary-sha256.txt` | 前段（DNF 改善）実機検証に使ったバイナリの SHA と注意 |

実機検証時点のバイナリ（今回）:
- v1.5b: Rocky 8 `8a0e65722716025c…`、Rocky 9 `d79f2401b54c2548…`
- sinter-pre（`origin/main` = `d207509` 由来）: Rocky 8 `7541d987f856d3cb…`、Rocky 9 `8f0d73af7d4172b8…`

## ローカルの追加テスト（証拠は Cargo 実行ログ／各テストファイル）

- `tests/validate_file.rs`（10 件）: 公開前検証、失敗時の本番不変、timeout、sensitive、冪等、
  template の validate、モデル形状検証。
- `tests/recipe_env.rs`（10 件）: command/package への伝播、優先順位、スコープ、sensitive、
  大文字小文字、静的な sensitive 反映、モデル形状検証、include 拒否。
- `src/resources.rs` 単体（3 件）: N-2 の実測表受理・不正 row 拒否・未実測セクション拒否。
