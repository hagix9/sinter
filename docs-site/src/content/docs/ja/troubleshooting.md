---
title: トラブルシューティング
description: よくある Sinter の失敗とその意味。
---

## 終了コード

| コード | 意味 | 典型的な原因 |
|--------|------|--------------|
| 0 | 成功 | audit: DRIFT も ERROR もなし — `NOT_AUDITABLE`/`NOT_APPLICABLE` のリソースが存在してもよい |
| 2 | バリデーション/スキーマエラー | レシピの構文誤り、未知のフィールド、不正な値 |
| 3 | 接続/capability/セキュリティエラー | SSH、ホスト鍵、非対応プラットフォーム |
| 4 | plan 未完了 | plan を安全に生成できない |
| 5 | apply 失敗 | リソースが失敗した |
| 6 | apply indeterminate / audit の ERROR | apply: ディスパッチ後のタイムアウト、応答の喪失、シグナルの不確実性。audit: 1 件以上の ERROR — エラーは DRIFT より優先 |
| 7 | audit の DRIFT | 1 件以上の DRIFT、ERROR なし |

## SSH / known_hosts

**`unknown host key` / `host key changed`**

Sinter は自動登録しません。対処: 選択された `known_hosts` ファイル
（デフォルト `~/.ssh/known_hosts`）に正しい鍵を追加するか、
`--known-hosts <path>` を渡してください。

**デフォルト以外のポートが拒否される**

ポート 22 はポートなしの `host` エントリを使います。それ以外のすべての
ポートには `[host]:port` が必要です。ポートなしのエントリは
デフォルト以外のポートを認可しません。

**ハッシュ化された known_hosts**

ハッシュ化されたエントリはサポートされません。ハッシュ化されていない
エントリを使ってください。

**`SSH authentication failed for user@host`**

ホスト鍵の検証には成功しましたが、鍵が受け付けられませんでした。鍵が
利用可能か確認してください: 鍵を保持する ssh-agent、明示的な `--identity
<path>`、またはデフォルトの `~/.ssh/id_ed25519` / `~/.ssh/id_rsa`。対応する
公開鍵がターゲットユーザーとしてあらかじめ許可されている必要があります。
Sinter が鍵をプロビジョニングすることはありません。（これは上記のホスト鍵
チェックとは別のものです。）

## 権限昇格

**`sudo` の失敗**

`--sudo` は非対話の `sudo -n` を使います。ターゲットユーザが
パスワードなしの sudo を持つことを確認してください（`sudo -n true`）。
Sinter はパーミッション失敗を昇格してリトライすることはありません。
失敗は失敗のままです。

## プラットフォーム検出

**`package resources require a supported target platform`**

ターゲットの `/etc/os-release` が対応プラットフォームとして識別
されませんでした。対応: Ubuntu 24.04 / 26.04 LTS amd64（apt）、
Rocky Linux 9 / 10、RHEL 9 / 10、AlmaLinux 9 / 10 x86_64（dnf）。
Oracle LinuxはRHEL系として認識されます（dnf）が、受入検証は未実施です。

## リソースの失敗

**`parent path` / シンボリックリンクのエラー**

ファイルシステムの変更には信頼できる親パスが必要です。予期しない
シンボリックリンクや安全でない親（`/tmp` 直下など）は拒否されます。
`path` を信頼できる場所に向けてください。

**`service unit ... was not found`**

ユニットがターゲット上に存在しません。先にパッケージをインストール
してください（`depends_on`）。またはユニット名を確認してください。

**Indeterminate な apply（終了コード 6）**

Sinter が変更が完了したか確認できませんでした。闇雲にリトライしないで
ください。まずターゲットの状態を調べ、安全であれば再適用してください。

## dnf 固有

**RHEL 系ターゲットでのメタデータ/キャッシュの失敗**

インストールは `/var/tmp/sinter-dnf.*` 配下のプライベートメタデータ
スナップショット（モード 0700）を使います。スナップショットの残骸は
実行後に残らないはずです。残っている場合はバグとして報告してください。

## 詳細を得るには

- `--verbose` でリソースごとの詳細
- `--format json` で機械可読な結果
