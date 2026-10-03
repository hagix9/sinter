# Codespace で Sinter を試す

[English](README.md) | **日本語**

この codespace は、あなたの GitHub アカウント上に作られる使い捨ての
Ubuntu 24.04 x86_64 コンテナです。作成時に、公開済みの Sinter v1.1.3
リリースを repository の `install.sh` で `~/.local/bin` にインストール
しています。`install.sh` はダウンロードしたファイルをリリースの
`SHA256SUMS` で検証します。あわせて、Sinter が管理対象のマシンに必要とする
`attr` パッケージも入れています。他のマシンへの接続は一切行いません。

ターミナルを開いて次を実行してください。

```sh
sinter --version
sinter validate examples/start/hello.yaml
sinter plan examples/start/hello.yaml    # 観測のみ。何も変更しません
sinter apply examples/start/hello.yaml   # ~/sinter-start/hello.txt を作成
sinter plan examples/start/hello.yaml    # 変更すべきものはもうありません
sinter audit examples/start/hello.yaml
```

[`hello.yaml`](hello.yaml) が管理するのは、この codespace 内の
`~/sinter-start` だけです（Sinter は安全チェックの一つとして、`/tmp` の
ような誰でも書き込めるディレクトリの下には書き込みません）。`--host` を付けない場合、Sinter は自分が
動いているマシンを対象にします。recipe を編集して、コマンドを再実行して
試してみてください。

このコンテナには systemd がないため、`service` リソースは SSH 経由で
実際の対応ホストで試すのがおすすめです。詳しくは
[ドキュメント](https://sinter.fulltrust.co.jp/ja/)を参照してください。

Codespaces の利用は、あなたの GitHub アカウントの Codespaces 利用枠に
計上されます。使い終わったら codespace を停止または削除してください。
