---
title: postgresql_role
description: ローカルの PostgreSQL サーバーのロールを 1 つ管理する。パスワードは暗号化したシークレットの SCRAM-SHA-256 verifier で渡す。
---

**目的:** ターゲットで動いている PostgreSQL サーバーの**ロール**を 1 つ宣言します。
存在するか（present / absent）、指定した属性、そして必要ならパスワードを、暗号化
したシークレットに入れた **SCRAM-SHA-256 の verifier** として管理します。ほかの
リソースと同じく plan、apply、audit の対象です。v1.5.1 で追加されました。

## 書式

```yaml
- id: app_role
  type: postgresql_role
  depends_on: [pg_service]
  with:
    name: app
    login: true
    connection_limit: 20
    password_verifier: { secret: secrets/app-verifier.age }
```

## パラメーター

| パラメーター | 必須 | 型 | 既定値 | 説明 |
|--------------|------|----|--------|------|
| `name` | はい | 文字列 | — | ロール名。静的な値。`[a-z_][a-z0-9_]*`、最大 63 バイト、`pg_*` は不可。 |
| `state` | いいえ | 文字列 | `present` | `present` または `absent`。 |
| `login`、`superuser`、`createdb`、`createrole`、`inherit`、`replication`、`bypassrls` | いいえ | 真偽値 | 管理しない | 宣言した属性だけを管理します。宣言しない属性は変更しません（新しいロールでは PostgreSQL の既定値になります）。 |
| `connection_limit` | いいえ | 整数 | 管理しない | `-1`（無制限）以上。 |
| `password_verifier` | いいえ | `{ secret: <path> }` | 管理しない | SCRAM-SHA-256 の verifier を 1 つだけ入れた暗号化シークレット。レシピに直接は書けません。 |
| `os_user` | いいえ | 文字列 | `postgres` | クラスタを所有する OS のアカウント。`psql` はこのアカウントで実行します（peer 認証）。 |
| `psql` | いいえ | 文字列 | `/usr/bin/psql` | `psql` の絶対パス（PGDG は `/usr/pgsql-17/bin/psql`）。 |
| `port` | いいえ | 整数 | サーバーの既定 | 既定と異なるポートで動くクラスタのポート。 |
| `database` | いいえ | 文字列 | `postgres` | 接続するデータベース。 |

未知のフィールドはスキーマのエラーです。平文の `password` フィールドはありません。

## 期待される動作

- **ローカルのサーバー、peer 認証。** Sinter はターゲットで `setpriv` を使って
  `os_user` として `psql` を実行します（接続にパスワードは使いません）。そのため
  root が必要です。root で接続するか、`--sudo` を使ってください。
- **観測**は、ロール名だけを含む読み取り専用の `SELECT`（`pg_catalog.pg_authid`）を
  コマンドラインで 1 回実行します。verifier を宣言している場合は、保存されている
  パスワードの値を読み、**メモリの中で**（定数時間で）比べます。値は表示しません。
- `present` でロールが無い → `CREATE ROLE "name" WITH <宣言した属性>
  [PASSWORD '<verifier>']`。宣言しない属性は PostgreSQL の既定値（`NOSUPERUSER`、
  `NOLOGIN`、`INHERIT` など）になります。暗黙に権限を付与することはありません。
- `present` でロールがある → 宣言した属性のうち異なるものだけを `ALTER ROLE` し、
  保存されている verifier が異なるとき（`md5` のハッシュやパスワード無しも「異なる」
  とみなします）だけ `ALTER ROLE ... PASSWORD` を実行します。
- `absent` → `CASCADE` を付けずに `DROP ROLE "name"`。オブジェクトを所有している、
  または権限を持っているロールは PostgreSQL が削除を拒否し、それが結果になります。
- Sinter が接続に使うロール（`os_user`）は削除せず、`superuser` と `login` を外す
  こともありません。
- **plan** は観測から予告します。前のリソースがまだサーバーを導入または起動して
  いないため観測できないときは、plan ではロールを **Unknown** と報告します。apply が
  推測で進むことはありません。
- **audit** は次元ごと（`login`、`connection_limit`、`password_verifier` など）に
  drift を報告します。パスワードの次元に値が含まれることはありません。

## verifier は秘密として扱う

SCRAM の verifier はパスワードそのものではありませんが、オフラインでの推測を
許すので、パスワードのハッシュと同じく秘密として扱います。

- 暗号化したシークレット（`password_verifier: { secret: ... }`、
  [sinter secrets](/ja/reference/secrets/) を参照）からだけ受け付け、厳密に
  `SCRAM-SHA-256$<iterations>:<salt>$<StoredKey>:<ServerKey>`（4096 回以上、末尾の
  改行 1 つは可）でなければなりません。平文のパスワードや `md5…` のハッシュは、
  何かを実行する前に固定の文言で拒否します。
- サーバーには `psql` の**標準入力**だけで渡し、argv、環境変数、一時ファイルには
  載せません。plan、apply、audit の出力にも出しません。
- **サーバー側のログ。** 変更の前に、セッションで `log_min_messages`、
  `log_min_error_statement`、`log_statement`、実行時間・サンプリング・デバッグの
  ログ（`log_min_duration_statement`、`log_duration`、`log_*_sample*`、
  `debug_print_*`）、`track_activities`、`pg_stat_statements.track` /
  `track_utility`、`pgaudit.log` を記録しない値に設定し、`current_setting` で
  **すべて読み返します**。全部を確認できたときだけ、変更を 1 つのトランザクションで
  実行します。確認できなければ verifier を含むものは何も送らず、リソースは失敗
  します。そのため、失敗した文もその内容ごとログに残らず、変更に対する `psql` の
  出力も結果には含めません。
- verifier そのものは、PostgreSQL が `pg_authid`（とその WAL）に、指定したとおりに
  保存します（`password_encryption` の設定にかかわらず）。

verifier は、信頼できるマシンで、標準入力から入力したパスワードから作ってください
（Python の標準ライブラリだけを使い、どこにも送信しません）。

```sh
python3 -c 'import base64,hashlib,hmac,os,sys
pw=sys.stdin.buffer.read().rstrip(b"\n"); s=os.urandom(16); i=4096
k=hashlib.pbkdf2_hmac("sha256",pw,s,i); c=hmac.new(k,b"Client Key","sha256").digest()
v=hmac.new(k,b"Server Key","sha256").digest(); b=lambda x: base64.b64encode(x).decode()
print("SCRAM-SHA-256$%d:%s$%s:%s"%(i,b(s),b(hashlib.sha256(c).digest()),b(v)))' > app.verifier
sinter secrets encrypt app.verifier -o secrets/app-verifier.age
```

文をログに記録するサーバーでは、`psql` の `\password` でパスワードを設定しないで
ください。`\password` はほかの文と同じように `ALTER ROLE ... PASSWORD` を送ります。

## 冪等性

完全に冪等です。宣言したすべての次元が一致するロールに対しては、文を実行せず、
変更も報告しません。

## 失敗時の動作

- root でない、`psql` が無い、サーバーが動いていない、`os_user` が接続できない →
  リソースは失敗します（plan ではエラー、または前の計画された変更があれば
  Unknown）。`psql` の出力は表示しません。
- ログの抑止を確認できない → 失敗し、何も送りません。
- 変更が拒否された（PostgreSQL のエラー） → 失敗します。ロールを観測し直し、
  変わっていなければ「変更なし」と報告します。
- superuser でない `os_user` は `pg_authid` を読めず、ログの設定も変えられない →
  変更の前に失敗します。

## プラットフォームに関する補足

v1.5.1 の開発中に、PostgreSQL 10.23（Rocky Linux 8 の既定の stream）、13.23
（Rocky Linux 9 の既定）、16.15（Rocky Linux 8 / 9 の stream 16、Rocky Linux 10）、
17.11（Rocky Linux 9 の PGDG）で実測しました。PostgreSQL 10 以降が必要です。
`pg_hba.conf` はこのリソースでは管理しません。ファイルとして管理してください
（[PostgreSQL のレシピ](/ja/recipes/overview/) を参照）。

## 関連

[user](/ja/reference/resources/user/) ·
[sinter secrets](/ja/reference/secrets/) ·
[file](/ja/reference/resources/file/)
