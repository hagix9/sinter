---
title: クイックスタート
description: レシピをターゲットホストに対して validate・plan・apply・audit する。
---

このチュートリアルでは管理対象ホストに `tree` パッケージをインストール
します。同じレシピが Ubuntu（apt）と、Rocky Linux、RHEL、AlmaLinux
などの RHEL 系ターゲット（dnf）の両方で動作します。Sinter が検出した
プラットフォームからバックエンドを選択します。

## 1. レシピを書く

```yaml title="recipe.yaml"
version: 1

resources:
  - id: tree
    type: package
    with:
      name: tree
      state: present
```

## 2. Validate

```sh
sinter validate recipe.yaml
# ok: 1 resource(s), 0 handler(s), 0 var(s)
```

`validate` は何にも接続せず、構造と意味をチェックします。

## 3. Plan

```sh
sinter plan --host web01.example.com recipe.yaml
```

`plan` は観測のみを行います。`tree` が存在しない場合、plan はその
パッケージを未適用の変更として報告しますが、インストールは行いません。

## 4. Apply

```sh
sinter apply --host web01.example.com --sudo recipe.yaml
```

`apply` はパッケージの状態を再観測し、`tree` がなければインストール
してから結果を検証します。

## 5. もう一度 apply する

```sh
sinter apply --host web01.example.com --sudo recipe.yaml
```

2 回目の実行では変更はゼロです。目的の状態はすでに満たされています。

## 6. Audit

```sh
sinter audit --host web01.example.com --sudo recipe.yaml
```

`audit` は `plan` と同じく読み取り専用ですが、問いが異なります：
ターゲットがすでにレシピと一致しているかを確認します。apply 成功後、
監査可能で適合したリソースを `PASS` と報告して終了コード `0` で
終了します。drift なら `7`、観測エラーなら `6` です。`command`
リソースは常に `NOT_AUDITABLE` で実行されず、`when` でスキップされた
リソースは `NOT_APPLICABLE` になるため、終了コード 0 でも未検証の
リソースが含まれ得ます。`summary:` 行で全体を確認してください。

## SSH オプション

```sh
sinter plan \
  --host web01.example.com \
  --port 2222 \
  --user ops \
  --identity ~/.ssh/ops_key \
  --known-hosts ~/.ssh/known_hosts \
  recipe.yaml
```

| フラグ | 意味 |
|--------|------|
| `--host` | SSH ターゲット。省略すると localhost。 |
| `--port` | SSH ポート（デフォルト 22）。デフォルト以外のポートには `known_hosts` に `[host]:port` エントリが必要。 |
| `--user` | SSH ユーザ（デフォルト: `$USER`）。 |
| `--identity` | 秘密鍵ファイル。複数回指定可能。 |
| `--known-hosts` | `known_hosts` ファイル（デフォルト `~/.ssh/known_hosts`）。 |
| `--sudo` | ターゲット側のすべての操作を `sudo -n` 経由で実行。 |
| `--format` | `text`（デフォルト）または `json`。 |
| `--verbose` | 詳細な出力。 |

次は [はじめてのレシピ](/sinter/ja/getting-started/first-recipe/) で
ファイル、ディレクトリ、リンク、サービスを追加します。
