# RHEL 系のレシピ（v1.5.1）

Rocky Linux / RHEL 8、9、10 向けの完成したレシピです。各ファイルの冒頭のコメントに、
何をするのかと、その理由を書いています。リリースごとの手順は
`facts.os.version_major` で選びます。EL8 は SSH の**接続先**としてだけ扱います
（Sinter は EL9 / EL10 か Ubuntu で実行します）。ファイル系のリソースには、ターゲットに
`attr` パッケージが必要です。

| ファイル | 内容 |
|----------|------|
| `python-el8.yaml` | EL8 の Python 3.6、3.11（+ pip）、3.12 を実際のパッケージ名で導入 |
| `postgresql-os.yaml` | OS の PostgreSQL 16、検証付きの設定、SCRAM の `pg_hba.conf`、ロール |
| `postgresql-pgdg17.yaml` | 固定した鍵とリポジトリのファイルで、PGDG の PostgreSQL 17 |
| `epel-crb.yaml` | EPEL と CRB / PowerTools、それぞれのパッケージ |
| `signed-repo.yaml` | 任意の署名付き RPM リポジトリ（先に鍵と URL を置き換える） |
| `apache-htpasswd.yaml` | シークレットの htpasswd による Basic 認証付きの httpd |

シークレットは同梱していません。apply の前に作ってください。

- `secrets/app-verifier.age` — PostgreSQL のロール `app` の SCRAM-SHA-256 の
  verifier（生成のための 1 行のコマンドは `postgresql_role` のリファレンスに
  あります）を `sinter secrets encrypt` で暗号化したもの。
- `secrets/htpasswd.age` — htpasswd のファイル（`htpasswd -niB <user>`）を同じ方法で
  暗号化したもの。

```sh
sinter validate examples/recipes/postgresql-os.yaml
sinter apply examples/recipes/postgresql-os.yaml --host <host> --sudo
sinter apply examples/recipes/postgresql-os.yaml --host <host> --sudo   # 変更なし
sinter audit examples/recipes/postgresql-os.yaml --host <host> --sudo
```
