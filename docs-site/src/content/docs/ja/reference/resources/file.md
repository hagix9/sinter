---
title: file
description: 通常ファイルの内容とメタデータを管理する。
---

**目的:** 通常ファイルが目的の内容・所有者・モードで存在すること、
または存在しないことを保証する。

## 書式

```yaml
- id: motd
  type: file
  with:
    path: /etc/motd
    content: "managed by sinter\n"
    mode: "0644"
    owner: root
    group: root
```

## パラメータ

| パラメータ | 必須 | 型 | デフォルト | 説明 |
|-----------|------|-----|-----------|------|
| `path` | はい | string（絶対パス） | — | 管理対象ファイルのパス。 |
| `state` | いいえ | string | `present` | `present` または `absent`。 |
| `content` | いいえ | string | — | リテラルな内容。`source` とは排他。 |
| `source` | いいえ | string | — | `path` にコピーするコントローラ側ファイル。`content` とは排他。 |
| `owner` | いいえ | string | — | 所有者名。 |
| `group` | いいえ | string | — | グループ名。 |
| `mode` | いいえ | string | — | 引用符付きの 4 桁 8 進数。例: `"0644"`。 |

## 期待される動作

- `present`: ファイルを作成または更新します。内容は rename によって
  アトミックに公開されます。`owner`/`group`/`mode` が省略された
  場合、既存のメタデータは保持されます。
- `absent`: 対象が通常ファイルであれば削除します。他のオブジェクト種別
  （ディレクトリ、シンボリックリンク、デバイス）をファイルとして
  削除することは拒否されます。
- 親ディレクトリはあらかじめ存在し、信頼境界チェックを通過する必要が
  あります。パス中の予期しないシンボリックリンクは拒否されます。

## 冪等性

完全に冪等です — すでに一致している content、mode、所有者に対して
変更は行われません。

## 失敗時の動作

- 安全でない親パスや予期しないシンボリックリンク → 変更前に失敗。
- Sinter が保持できない非対応のセキュリティメタデータ（ACL/xattr/
  SELinux コンテキスト）は、暗黙の喪失ではなく拒否となります。
- diff 出力は内容の変更を表示しますが、リソースまたは内容が
  sensitive の場合は `redacted` と表示されます。

## プラットフォームに関する補足

すべての対応ターゲットに適用されます。`/tmp` のような誰でも書き込める
ディレクトリ配下のパスは信頼境界チェックで失敗します。

## 関連

[template](/sinter/ja/reference/resources/template/) ·
[directory](/sinter/ja/reference/resources/directory/) ·
[link](/sinter/ja/reference/resources/link/)
