---
title: コントリビューション
description: Sinter のビルド、テスト、コントリビューションのワークフロー。
---

## バグの報告

バグは
[GitHub の Issue トラッカー](https://github.com/hagix9/sinter/issues)
に報告してください。Sinter のバージョン（`sinter --version`）、
コントローラとターゲットの OS、問題を再現する最小の recipe とコマンドライン、
出力（`--verbose` や `--format json` が役立ちます）を含めてください。
実際のホスト名、認証情報、鍵、トークンはプレースホルダに置き換えてください。

## セキュリティ脆弱性の報告

脆弱性の疑いがある問題を公開 Issue に書かないでください。
[GitHub のプライベート脆弱性報告](https://github.com/hagix9/sinter/security/advisories/new)
から非公開で報告してください。詳細は
[SECURITY.md](https://github.com/hagix9/sinter/blob/main/SECURITY.md)
を参照してください。

## 変更の提案

小さな修正を超える変更は、実装する前に Issue を開いて方針を合意して
ください。変更は `main` に対する pull request として提出してください。
提出する前に:

- [品質ゲート](#品質ゲート)を実行し、動作を変える変更にはテストを
  含めてください。
- ドキュメントを変更した場合は、`docs-site/` で `npm run check`、
  `npm run webmcp:check`、`npm run build` を実行してください
  （[ドキュメント](#ドキュメント)を参照）。

## ビルド

```sh
cargo build --release
# binary: target/release/sinter
```

## 品質ゲート

リリースで使われるローカルのゲート一式:

```sh
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked
git diff --check
```

## テスト構成

| スイート | 範囲 |
|----------|------|
| lib ユニットテスト | 値モデル、フロントエンド、式、パス、argv クォート |
| `frontends` | YAML/TOML 等価性、スキーマ拒否、include |
| `engine` | file/dir/link/template、plan の安全性、冪等性、fail-fast |
| `commands` | ガード、register、changed_when、環境ベースライン、終了コード |
| `handlers` | 遅延ハンドラ、重複排除、検証ゲート |
| `package_service` | apt/dnf インストール/削除/冪等性、systemd の状態 |
| `file_safety` | 信頼境界、シンボリックリンク拒否、アトミック公開 |
| `truthfulness` | 結果次元のマトリクス |
| `cli` | 終了コード、JSON 出力、sensitive マスク |
| `ssh` | 実際の SSH 統合テスト（環境変数でゲート） |

SSH 統合テストには使い捨ての Ubuntu ターゲットが必要です:

```sh
export SINTER_TEST_SSH_HOST=127.0.0.1
export SINTER_TEST_SSH_PORT=22
export SINTER_TEST_SSH_USER=ubuntu
export SINTER_TEST_SSH_KNOWN_HOSTS=/path/to/known_hosts
export SINTER_TEST_SSH_IDENTITY=/path/to/test_key
cargo test --test ssh
```

## ドキュメント

このサイトは `docs-site/`（Astro + Starlight）にあります:

```sh
cd docs-site
npm ci
npm run dev      # ローカル開発サーバ
npm run build    # dist/ への静的ビルド
```

ドキュメントと WebMCP ツールで共有されるリソースメタデータは
`src/data/resources.json` にあります。リソースパラメータを変更した
ときは更新してください。日本語の説明文は `src/data/resources.ja.json`
で、同じリソースタイプとパラメータ名をキーにオーバーレイされます。

## リリース

リリース手順: リポジトリの
[RELEASE.md](https://github.com/hagix9/sinter/blob/main/RELEASE.md)を
参照してください。
