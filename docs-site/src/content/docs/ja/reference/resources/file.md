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
| `content` | いいえ | string、または `{ secret: <path> }` | — | リテラルな内容、または暗号化されたシークレット（[sinter secrets](/ja/reference/secrets/#レシピでシークレットを使う) を参照）。`source` とは排他。 |
| `source` | いいえ | string | — | `path` にコピーするコントローラ側ファイル。相対パスはレシピファイルのディレクトリから解決されます。`content` とは排他。 |
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
- ファイルが systemd マネージャの入力（ユニットファイル、drop-in、
  alias/mask/`.wants`/`.requires` リンク、`system.conf`）を実際に変更すると、
  それを必要とする次のサービスまたはハンドラの前、および成功した apply の
  最後に、Sinter が `systemctl daemon-reload` を自動的に実行します。
  [service](/ja/reference/resources/service/#マネージャの自動同期)を参照して
  ください。

## シークレットの内容

```yaml
- id: api_key
  type: file
  with:
    path: /etc/app/api.key
    content: { secret: secrets/api.key.age }
    owner: root
    group: root
```

ファイルのバイト列は、レシピのテキストではなく、リポジトリ内の暗号化された
[age](https://age-encryption.org/v1) ファイルから取られます。ファイルは
[`sinter secrets encrypt`](/ja/reference/secrets/) で作ります。要点は次のとおりです。
完全な契約（identity の探索、パスフレーズ、制限）は
[sinter secrets](/ja/reference/secrets/#レシピでシークレットを使う) にあります。

- **参照。** その参照を含むレシピファイルのディレクトリ（include されたレシピならそのレシピ
  自身のディレクトリ）を基準とする、静的な**相対**パスで、作業ディレクトリは基準に
  なりません。拒否されるもの: 絶対パス、`.`・`..`・空の要素、バックスラッシュ、制御文字、
  `{{ }}` 補間、そのディレクトリ以下のシンボリックリンク、通常ファイルではない対象、厳密に
  `{ secret: <path> }` ではない値。`content` と `source` は引き続き排他です。参照を
  受け付けるのは `file.content` と `user.password_hash` だけです。
- **`validate`** は、参照と、ファイルが正しい age ファイルであることだけを確認します。
  復号はせず、鍵も要りません。
- **`plan`、`apply`、`audit`** はシークレットをメモリ上で復号し、ターゲットと SHA-256 で
  比較し、**正確なバイト列**として公開します（バイナリ、NUL バイト、末尾改行がない
  状態も保たれます。最大 16 MiB）。コントローラ上に平文の一時ファイルは作られず、
  内容はコマンドラインではなく標準入力でターゲットに届きます。
- **常に sensitive** です（`sensitive:` の指定に関わらず）。内容の diff は伏せられ、診断も
  伏せられ、**新規**ファイルの既定モードは `0600` です（既存ファイルは、宣言しない限り
  メタデータを保持します）。
- **鍵がなければ変更しない（フェイルクローズ）。** identity が使えない（または
  パスフレーズを入力できない）場合、`plan` は失敗し（終了コード 4）、`apply` はそのリソースを
  失敗させて実行を止め、apply が部分的なファイルを書くことはありません。`audit` は
  ターゲットにファイルが存在すれば `ERROR`、なければ `DRIFT` を報告します。`state: absent` は鍵を必要としません。原因は
  標準エラーに 1 度だけ出力され、レポート自体は伏せられたままです。何かが変わる前に
  鍵の不在を知るため、先に `plan` を実行してください。
- **制限。** 1 つのシークレットは 16 MiB まで。書き込みは 300 秒のコマンド期限内に完了する
  必要があります（[制限](/ja/reference/secrets/#制限)を参照）。MCP のマニフェスト系ツールは
  シークレット参照を拒否します（[Core MCP](/ja/reference/mcp/) を参照）。

## 冪等性

完全に冪等です — すでに一致している content、mode、所有者に対して
変更は行われません。

## 失敗時の動作

- 安全でない親パスや予期しないシンボリックリンク → 変更前に失敗。
- Sinter が保持できない非対応のセキュリティメタデータ（ACL/xattr/
  SELinux コンテキスト）は、暗黙の喪失ではなく拒否となります。
- diff 出力は内容の変更を表示しますが、リソースまたは内容が
  sensitive の場合は `redacted` と表示されます。
- 鍵が使えない `content: { secret: … }` は、変更前に失敗します
  （[シークレットの内容](#シークレットの内容)を参照）。

## プラットフォームに関する補足

すべての対応ターゲットに適用されます。`/tmp` のような誰でも書き込める
ディレクトリ配下のパスは信頼境界チェックで失敗します。

## 関連

[template](/ja/reference/resources/template/) ·
[directory](/ja/reference/resources/directory/) ·
[link](/ja/reference/resources/link/)
