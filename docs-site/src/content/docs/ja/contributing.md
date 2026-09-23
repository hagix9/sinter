---
title: コントリビューション
description: Sinter のビルド、テスト、コントリビューションのワークフロー。
---

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
[RELEASE.md](https://github.com/hagix9/blob/main/RELEASE.md)を
参照してください。
