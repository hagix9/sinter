# クイックレシピ

一度にひとつの振る舞いだけを確認できる、小さく速いレシピ集です。どれも短い
1 ファイルなので、失敗したときの原因が分かりやすい構成です。使い捨ての
RHEL 系または Debian/Ubuntu ホストを対象にします（一部は root / `--sudo` が
必要です）。

| ファイル | 確認できること |
|----------|----------------|
| `packages.yaml` | `package` の `state: present` と、dnf メタデータの自動取得（手動の `dnf makecache` 不要） |
| `package-proxy.yaml` | レシピ単位の `env` で全 `package`/`command` にプロキシを一度だけ設定（`NO_PROXY`、リソース単位の上書き） |
| `dnf-module.yaml` | DNF モジュールストリームからのパッケージ導入（`command` + `depends_on`） |
| `accounts-and-paths.yaml` | group → user → directory → file を明示的な `depends_on` で構成（パッケージ由来アカウントは推測しない） |
| `httpd-service.yaml` | package → 専用 user → service を明示的な `depends_on` で構成（依存元が失敗すると依存先は実行されない） |
| `validate-sshd-config.yaml` | `validate`: 公開前に staging ファイルを検証する |

`depends_on` は順序付けとゲートであり、依存の自動推論ではありません。資源は
列挙した id がすべて成功した後にだけ実行され、依存元が失敗すると依存先は
**ブロックされて実行されません**（`httpd-service.yaml`、`dnf-module.yaml`、
`accounts-and-paths.yaml` を参照）。Sinter が依存を勝手に追加することはなく、
パッケージがアカウントやユニットを作ることも想定しません。

ターゲットに接続せずに構文だけを検証できます。

```sh
sinter validate examples/quick/packages.yaml
```

ターゲットへ適用します（2 回目は変更なしになるはずです）。

```sh
sinter apply examples/quick/packages.yaml --ssh user@host
sinter apply examples/quick/packages.yaml --ssh user@host   # 冪等
```

複数ロールの例は `examples/multihost/` にあります。OpenStack の応用レシピは
エンドツーエンドの例として別途維持します。
