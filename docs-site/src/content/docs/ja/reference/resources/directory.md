---
title: directory
description: ディレクトリを目的のメタデータで存在させる。
---

**目的:** ディレクトリが目的の所有者・グループ・モードで存在する
（または存在しない）ことを保証する。

## 書式

```yaml
- id: appdir
  type: directory
  with:
    path: /opt/myapp
    mode: "0755"
    owner: root
    group: root
```

## パラメータ

| パラメータ | 必須 | 型 | デフォルト | 説明 |
|-----------|------|-----|-----------|------|
| `path` | はい | string（絶対パス） | — | 管理対象ディレクトリのパス。 |
| `state` | いいえ | string | `present` | `present` または `absent`。 |
| `owner` | いいえ | string | — | 所有者名。 |
| `group` | いいえ | string | — | グループ名。 |
| `mode` | いいえ | string | — | 引用符付きの 4 桁 8 進数。例: `"0755"`。 |
| `parents` | いいえ | boolean（リテラル） | `false` | 存在しない親ディレクトリも作成します。[親ディレクトリがない場合](#親ディレクトリがない場合)を参照してください。 |

## 期待される動作

- `present`: そのディレクトリだけを作成します — `parents: true` を指定
  しない限り、親はあらかじめ存在している必要があります。
- `absent`: ディレクトリを削除します。空でないディレクトリや
  ディレクトリ以外のオブジェクトは拒否されます。
- `owner`/`group`/`mode` が省略された場合、メタデータは保持されます。

## 親ディレクトリがない場合

既定では、親ディレクトリがなければエラーになります。指定していない
ディレクトリを Sinter が勝手に作ることはありません。`parents: true` を
指定すると、そのディレクトリと、その上にある存在しないディレクトリを
すべて作成します。

```yaml
- id: data
  type: directory
  with:
    path: /srv/app/var/data
    owner: app
    group: app
    mode: "0750"
    parents: true
```

```toml
[[resources]]
id = "data"
type = "directory"
with = { path = "/srv/app/var/data", owner = "app", group = "app", mode = "0750", parents = true }
```

- `owner`、`group`、`mode` は、指定したディレクトリ（`/srv/app/var/data`）
  だけに適用されます。
- 存在しない親（`/srv/app`、`/srv/app/var`）は、モード `0755`、変更を実行する
  アカウント（`--sudo` なら root）の所有で作成されます。親に別の所有者や
  モードが必要なら、その親を `directory` リソースとして別に宣言してください。
- すでに存在する親は変更しません。モードも所有者も変えません。
- 親は上から順に 1 つずつ作成します。各段階で、その上のパスが Sinter の
  [親パスの検査](/ja/reference/resources/file/)を通ることを確認します。
  途中にファイルやシンボリックリンクがある場合や、他のアカウントが書き込める
  親がある場合は拒否し、その下には何も作りません。
- `plan` は何も作成せず、`apply` が作成するディレクトリを表示します。
- 親を作成した後の処理が失敗した場合、リソースは失敗になり、結果に作成済みの
  ディレクトリが示されます。
- `parents` は `true` か `false` で書きます（式は使えません）。`state: absent`
  では効果がなく、削除されるのは指定したディレクトリだけです。
- `file`、`template`、`link` は親ディレクトリを作成しません。その前に
  `directory` リソースを置いてください。

## 冪等性

完全に冪等です。

## 失敗時の動作

- 親ディレクトリが存在しない → 失敗（`parents: true` を指定した場合を除く）。
- パス中の予期しないシンボリックリンク → 変更前に拒否。

## プラットフォームに関する補足

すべての対応ターゲットに適用されます。ディレクトリ作成は
[`file`](/ja/reference/resources/file/#信頼境界) と同じ親パスの信頼境界を使います。

## 関連

[file](/ja/reference/resources/file/) ·
[link](/ja/reference/resources/link/)
