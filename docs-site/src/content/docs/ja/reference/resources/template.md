---
title: template
description: コントローラ側のテンプレートファイルをレンダリングして管理対象パスに配置する。
---

**目的:** レシピの隣に置かれたテンプレートファイルをレンダリングし、
結果をターゲットの `path` に公開する。

## 書式

```yaml
- id: app_conf
  type: template
  with:
    path: /etc/myapp/config.ini
    source: templates/config.ini
    mode: "0640"
    vars:
      listen_port: 8080
```

```text title="templates/config.ini"
[server]
listen = {{ template.listen_port }}
hostname = {{ facts.hostname }}
```

## パラメータ

| パラメータ | 必須 | 型 | デフォルト | 説明 |
|-----------|------|-----|-----------|------|
| `path` | はい | string（絶対パス） | — | ターゲット上の配置先。 |
| `source` | はい | string | — | コントローラ側テンプレート。レシピファイルからの相対パスで解決。 |
| `state` | いいえ | string | `present` | `present` または `absent`。 |
| `vars` | いいえ | map | — | テンプレートローカルな値。`template.<name>` として参照可能。 |
| `owner` | いいえ | string | — | 所有者名。 |
| `group` | いいえ | string | — | グループ名。 |
| `mode` | いいえ | string | — | 引用符付きの 4 桁 8 進数。 |

## 期待される動作

- テンプレートはコントローラ上でレンダリングされ、
  [`file`](/ja/reference/resources/file/) と同様にアトミックに
  公開されます。
- テンプレート式は `vars.*`、`facts.*`、`registers.*`、`template.*` を
  読み取れます。`template.*` の名前が他の名前空間をシャドウすることは
  ありません。
- `content` は**サポートされません** — template リソースは常に
  `source` を使います。

## 冪等性

完全に冪等です — レンダリング結果に変更がなければ変更もハンドラ通知も
発生しません。

## 失敗時の動作

- `source` ファイルの欠落やテンプレート評価エラー（未定義変数など）は
  validate/apply 時に説明的なエラーで失敗します。メッセージから
  sensitive な値はマスクされます。
- `file` と同じファイルシステム安全ルール（信頼境界、シンボリック
  リンクの拒否、アトミックな公開）。

## プラットフォームに関する補足

すべての対応ターゲットに適用されます。

## 関連

[file](/ja/reference/resources/file/) ·
[レシピ — 式](/ja/concepts/recipes/)
