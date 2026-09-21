---
title: リソースリファレンス
description: v0.5.0 に実装されているすべての Sinter リソースタイプ。
---

Sinter v0.5.0 は 7 つのリソースタイプを実装しています。以下の
パラメータはサポートされる完全なセットであり、未知の `with`
フィールドはスキーマエラーです。

| タイプ | 用途 | 主要パラメータ |
|--------|------|----------------|
| [file](/sinter/ja/reference/resources/file/) | 通常ファイルの内容とメタデータ | `path`、`state`、`content`/`source`、`owner`、`group`、`mode` |
| [directory](/sinter/ja/reference/resources/directory/) | ディレクトリの存在とメタデータ | `path`、`state`、`owner`、`group`、`mode` |
| [link](/sinter/ja/reference/resources/link/) | シンボリックリンク | `path`、`target`、`state` |
| [template](/sinter/ja/reference/resources/template/) | コントローラ側テンプレートのレンダリング | `path`、`source`、`vars`、`mode` |
| [command](/sinter/ja/reference/resources/command/) | 正確な argv によるプログラム実行 | `program`、`args`、`creates`/`removes`、`changed_when`、`register` |
| [package](/sinter/ja/reference/resources/package/) | パッケージのインストール/削除（apt/dnf） | `name`、`state` |
| [service](/sinter/ja/reference/resources/service/) | systemd の状態と有効化 | `name`、`state`、`enabled` |

## 共通の規約

- `path` 系パラメータは絶対パスです。親パスはあらかじめ存在し、
  信頼境界チェック（予期しないシンボリックリンクがないこと）を
  通過する必要があります。
- `mode` は常に引用符付きの 4 桁 8 進数文字列（`"0644"`）です。
- `state` はファイルシステム系リソースでは `present` がデフォルト
  です。`package` では明示的に必須です。
- 内容の公開はアトミック（rename）です。省略された既存のメタデータは
  保持されます。
- すべてのタイプは冪等です。収束済みのリソースは再適用しても
  何も変更しません。
