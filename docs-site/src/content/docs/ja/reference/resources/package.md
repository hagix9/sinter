---
title: package
description: ターゲットのパッケージバックエンドでパッケージをインストール・削除する。
---

**目的:** ターゲットのネイティブなパッケージバックエンド — Ubuntu
では `apt`、RHEL 系ターゲットでは `dnf` — を使って、パッケージが
インストール済み（`present`）または削除済み（`absent`）であることを
保証する。

## 書式

```yaml
- id: tree
  type: package
  with:
    name: tree
    state: present
```

操作ごとに環境変数を明示できます。環境変数はこのパッケージ操作（権限
昇格した `apt` / `dnf` の実行を含む）にだけ渡され、ホスト全体の永続的な
設定にはなりません。

```yaml
- id: install-tools
  type: package
  with:
    name: curl
    state: present
    env:
      HTTP_PROXY: "http://proxy.example.com:3128"
      HTTPS_PROXY: "http://proxy.example.com:3128"
      NO_PROXY: "localhost,127.0.0.1,.example.internal"
```

## パラメータ

| パラメータ | 必須 | 型 | デフォルト | 説明 |
|-----------|------|-----|-----------|------|
| `name` | はい | string | — | パッケージ名（検証される）。 |
| `state` | はい | string | — | `present` または `absent`。必須。 |
| `env` | いいえ | string の map | 空 | このパッケージ操作に渡す環境変数。 |

## 期待される動作

- バックエンドはターゲットの `/etc/os-release` の識別情報から自動的に
  選択されます — レシピはプラットフォーム中立のままです。
- Ubuntu での `present` → `apt`。RHEL 系ターゲット（Rocky Linux、RHEL、
  AlmaLinux、Oracle Linux）→ `dnf`。
- バージョン固定はありません。
- dnf ターゲットでは、インストールはプライベートキャッシュ
  スナップショット経由で行われます —
  [実行モデル](/ja/concepts/execution-model/)と
  [Rocky ガイド](/ja/guides/rocky-linux/)を参照してください。
- apt ターゲットでは、Sinter は `apt-get update` を実行しません。パッケージ一覧が
  すでにある必要があります。一覧の無い新しいイメージでは導入が失敗します
  （`E: Unable to locate package`。apt の出力は信用しないので、変更の可能性ありと
  報告されます）。先に一覧を更新してください。例えば、`/usr/bin/apt-get update` を
  実行する `command` リソース（`changed_when: "false"`）をパッケージより前に宣言します。
- 壊れたパッケージ状態（設定途中など）は自動修復ではなく失敗と
  なります。

## 削除（`state: absent`）— apt / dnf ターゲット

> **未リリース。** この節は v1.7.0 より後に実装された削除（WP-PKG-CORE-REPAIR）を
> 説明します。v1.7.0 以前は、パッケージマネージャーに削除を任せていた
> （`apt-get remove`、`dnf remove`）ため、逆依存のパッケージまで削除される
> ことがありました。

Sinter は、**指定した導入済みパッケージだけ**を削除します。

| バックエンド | 削除 | 事前の dry-run |
|--------------|------|----------------|
| apt（Ubuntu） | `dpkg --remove NAME` | `dpkg --dry-run --remove NAME` |
| dnf（RHEL 系） | `rpm -e NEVRA`（dnf 自身のプロセスロックを保持して実行） | `rpm -e --test NEVRA` |

- パッケージマネージャーの resolver に削除対象の集合を決めさせることはありません。
  `apt-get remove`、`dnf remove`、autoremove、purge、`--force-depends` /
  `--nodeps` は使いません。
- **ほかの導入済みパッケージが依存していれば何も削除せず**、依存元の名前を示して
  失敗します（sensitive なリソースでは件数だけ）。先に依存元を削除または置き換えて
  ください。
- **そのパッケージが引き込んだ依存パッケージは残ります**（不要になっても削除されません）。
  削除したい場合は、それぞれに `state: absent` のリソースを宣言してください。
- 次の場合も、何も削除する前に拒否します: essential / protected（dpkg）、dnf の保護
  （`dnf` 自身、`/etc/dnf/protected.d`、`dnf.conf` の `protected_packages`）、
  実行中カーネルのイメージを所有するパッケージ、複数インスタンスの導入（別アーキテクチャ・
  別バージョン。別アーキテクチャが設定ファイルだけ残っている、または未導入の場合は数えません）、クリーンな導入状態ではない、DNF 設定やパッケージ DB を読めない・
  解釈できない。
- 削除後にパッケージ DB を読み戻して確認します: 対象が消えていること、**ほかの
  パッケージが消えていないこと**、削除前と比べて新しい依存問題や設定途中のパッケージが
  無いこと。満たさなければ失敗として報告します。Sinter がホストを修復することは
  ありません。計画（何を確認したか）と実績（何が見つかったか）は別々に報告します。
- `with.env` のうち削除コマンドに渡るのは `DEBIAN_FRONTEND`、`DEBIAN_PRIORITY`、
  `NEEDRESTART_MODE`、`NEEDRESTART_SUSPEND` だけです。ほかの名前は捨てられます
  （結果に個数が出ます）。

### 記録されるもの・残るもの

- この方式の削除は、パッケージマネージャー自身の履歴（`dnf history`、
  `/var/log/apt/history.log`）には**記録されません**。apt / dnf のフック（needrestart、
  etckeeper など）も動きません。dpkg は設定ファイルを残します（`apt-get remove` と同じ）。
- **dpkg は、依存の確認と pre-removal スクリプトの実行より前に、削除の要求を DB に
  書きます。** その後 dpkg が拒否したりスクリプトが失敗したりすると、パッケージは導入
  されたまま `deinstall ok installed`（post-removal スクリプトの失敗後は
  `half-installed`）という状態になります。Sinter はこの状態を読みません。リソースは
  「変更の可能性あり・検証は不明」と報告し、この状態を直すまで、そのパッケージを観測する
  後続のリソースは失敗します（例: `dpkg --set-selections` で `<name> install` を指定、
  `dpkg --configure -a`）。通常の逆依存による拒否では、先に DB に書き込まない dry-run が
  拒否するので、この状態は残りません。

### ロックと、ロックが及ばない範囲

| 同時に動くもの | apt ターゲット | dnf ターゲット |
|----------------|----------------|----------------|
| `apt`、`dpkg`、unattended-upgrades | 削除は即座に失敗（dpkg のロック）。何も変更しない | – |
| `dnf`、`dnf-automatic`、`yum` | – | 実行中のトランザクションがあると `rpm` の前に失敗。削除中に始まったものは `rpm` が終わるまで待つ（Sinter が dnf のプロセスロックを保持） |
| ほかの `rpm` トランザクション | – | 待たずに即失敗（端末が無いため） |
| PackageKit、`microdnf`、手で実行した `rpm -U` | – | **排他されません** |

dpkg はロックを保持したまま依存を確認します。rpm は、トランザクションロックを取る直前に
依存を確認するため、dnf のロックを使わないプロセスがその瞬間に導入した依存元を見逃す
ことがあります。その場合、**ほかのプロセスの commit が Sinter のパッケージ DB の読取りより
前に済んでいれば**、削除後の確認が依存破壊を失敗として報告します。commit がそれより後なら、
削除は成功として報告されます。Sinter が元に戻すことはできません。

dnf の `persistdir` が既定値でない場合（`dnf.conf` または `automatic.conf`）は、dnf の
ロックが別の場所にあるため、削除を拒否します。

そのほか、削除せずに拒否・失敗する場合:

- dnf ターゲットで `dnf` が未導入、または `/var/lib/dnf` が無い（ロックのラッパーを実行
  できない）: 変更なしで拒否します。
- `dpkg.cfg` の `ignore-depends=NAME` はコマンドラインから打ち消せません。dpkg は依存元が
  必要としていても削除し、削除後の確認（`apt-get -s check`）だけが依存破壊を報告します。
- 削除対象パッケージのメンテナスクリプトが `dnf` / `yum` を実行すると、`rpm` の実行中に
  Sinter が保持するロックを待ちます。300 秒後に Sinter がコマンド全体を kill し、rpm の
  トランザクションが中途半端に残ることがあります。
- 削除の実行中に Sinter 自体が kill（SIGTERM / SIGKILL）された場合、`dpkg` / `rpm` は止まらず
  最後まで実行され、パッケージ DB は整合したままですが、結果を報告する者がいません。
  あとで audit を実行してください（切断後に出力を書き続けるスクリプトは未検証です）。
- ほかのプロセスが先にパッケージを削除していた場合、変更なしで失敗として報告します
  （「the package was already gone」。apt / dnf 共通）。
  apt では dpkg 自身の警告（`ignoring request to remove NAME which isn't installed`、および
  設定ファイルだけが残っている旨の警告。名前の後ろに `:arch` が付く形も含む）が、このパッケージを名指しし、
  かつ dpkg が「Removing」行を出していない場合にこの判定を行います。削除後の検査はどの場合も実行されます。
- apt で `dpkg --remove` が失敗したとき「何も変更していない」と報告するのは、dpkg が「Removing」行を出して
  おらず、dpkg 自身の拒否が stderr の行全体として出ている場合だけです（このパッケージの依存問題、他プロセスの
  ロック、権限不足、曖昧な名前、essential パッケージ）。メンテナスクリプトが出力した言葉は根拠にしません。
  dpkg が削除を開始していた場合や、どこまで進んだか出力から分からない場合は、変更あり（または変更の可能性）と
  して報告し、「変更なし」にはしません。パッケージが消えているのに誰が削除したか分からない場合は
  変更の可能性として報告します。削除後の検査はどの場合も実行されます。
- apt で、別アーキテクチャのインスタンスが設定ファイルだけ残っている（または未導入）場合は、それが無い場合と
  同じに扱います。状態はアーキテクチャごとに読み取ります。複数のアーキテクチャが導入済み、または
  それ以外の状態のインスタンスがある場合は、従来どおり拒否します。

### 所要時間

dnf ターゲットでは、削除の前後にインストール済みパッケージの一覧と依存の検証
（`rpm -qa`、`rpm -Va --nofiles`）を行います。これは CPU 負荷が高く、パッケージ数と
ホストの速度に応じて増えます。負荷の低い 2 vCPU の Rocky Linux 9 VM（412 パッケージ）で
1 回あたり約 7 秒、小さな Rocky Linux 10 VM（450 パッケージ）で 1〜2 分です
（rpm 4.19 ではここがかなり遅くなります）。apt ターゲットは約 5 秒です。所要時間はインストール済みパッケージ数に比例して増え、
2 回の依存検証はそれぞれ 300 秒が上限です（削除前なら拒否、削除後なら
`verification: unknown`）。

### 実機での検証範囲

Ubuntu 24.04、Rocky Linux 9.8、Rocky Linux 10.2 では、使い捨てのパッケージを使って
実機で検証しました（削除、依存による拒否、ロック競合、スクリプト失敗、中断）。Ubuntu 26.04、
RHEL 9/10、AlmaLinux 9/10 は同じツールを使うため同様に動作する見込みですが、削除は
**検証していません**。Rocky Linux 8 と Oracle Linux も未検証です。Fedora は対象外です。

## 冪等性

完全に冪等です — すでにインストール済みの `present`、すでに削除済みの
`absent` は変更もパッケージトランザクションも発生させません。拒否された削除はホストを
元のままにします（例外は上記の dpkg の注意を参照）。

## 失敗時の動作

- 非対応プラットフォーム / バックエンドの欠落 → capability エラー。
- 解決できないパッケージ、リポジトリエラー、曖昧な観測 → 失敗または
  indeterminate。偽の変更報告にはなりません。
- 変更前の観測失敗が変更として報告されることはありません。
- 安全と確認できない削除（依存元あり、保護パッケージ、読めない設定、ほかのプロセスが
  保持するロック）は、`change: none` で、理由に `nothing was changed` を含めて失敗します。
  ほかのパッケージも消えた、または新しい依存破壊が残った削除は、
  `verification: failed` の失敗として報告します。

## メタデータスナップショット（dnf）

RHEL 系ターゲットでは、インストールはターゲットの dnf メタデータのプライベートな
スナップショットに対して cache-only で実行されます。スナップショットは有効な
すべてのリポジトリのメタデータキャッシュが完全である必要があります。有効な
リポジトリのメタデータが未キャッシュの場合（新しいイメージや、直前に追加した
リポジトリなど）、Sinter は `dnf makecache` と同じくターゲット自身の dnf
メタデータキャッシュを一度だけ更新し、スナップショットを再作成して検証し直します。
手動での準備は不要です。取得するのは未キャッシュのメタデータだけ
（`metadata_expire=-1`）なので、キャッシュ済みのホストでは余分な通信は発生しません。
またこの手順で取得するのはリポジトリのメタデータのみで、パッケージのペイロードは
ダウンロードしません。メタデータを確立できない場合は、パッケージを変更する前に
fail-closed になります。スナップショットは live cache にダウンロード済みの
パッケージをトランザクションのペイロードと誤認しなくなり、live cache を削除・
コピーすることもありません。
パッケージ同一性の問い合わせ（`rpm -qp`）は信頼されていない署名の警告を無視します。
署名が信頼されるかどうかは引き続き dnf とペイロードのダイジェストで決まります。

## パッケージ名と provides（dnf）

パッケージは**そのパッケージ自身の名前**で宣言してください。dnf は、別の
パッケージが *provides* しているだけの名前も受け付けます（RHEL 系 8 では
`python3` は `python36` が、`python311` は `python3.11` が provides しています）。
しかし Sinter は結果をその名前のまま検証するので、そのような導入は確認できません。
Sinter は導入の前に、dry-run の取引が要求した名前そのものを導入することを
確かめます。dnf が別のパッケージに解決した場合や、導入済みの別のパッケージが
provides しているので「何もすることがない」と dnf が答えた場合は、
**何も変更せずに**失敗し、実際のパッケージ名を案内します。

```text
python3 is not a package name: dnf resolves it through a provides match to
package python36; nothing was changed. Declare the package by its own name
(name: python36) so the result can be verified
```

`plan` は dnf の依存解決を実行しないので、このような名前も「導入する」と
予告します。`apply` はホストを変更せずに拒否します。

## dnf が拒否した理由（dnf）

dnf が導入を拒否したとき、理由には dnf が報告した原因が表示されます
（dnf 4.7（EL8）、4.14（EL9）、4.20（EL10）で実測した出力に基づきます）。
どの場合も何も導入されません。

| 原因 | 理由の書き出し |
|------|----------------|
| 有効なリポジトリにその名前のパッケージ（または provides するもの）が無い | `dnf found no package named …` |
| provides でしか一致しない名前 | `… is not a package name: dnf resolves it …` / `no package named … is installed, but dnf reports …` |
| 依存が不足している（CRB / PowerTools などのリポジトリが無効なことが多い） | `dnf cannot resolve the dependencies of …: nothing provides <capability>` |
| 署名が無い、またはリポジトリが信頼しない鍵で署名されたパッケージ | `dnf refused a package signature … (GPG check FAILED …)` |
| 有効なリポジトリに到達できない | `dnf could not download the metadata of repository <id> …` |
| その他の理由でパッケージのダウンロードに失敗した | `dnf could not download the packages required for …` |
| 1 回だけの更新の後も、リポジトリのメタデータをローカルのキャッシュから使えない | `dnf repository metadata not locally complete (…)` |

表示されるのは固定の文言と、検証したトークン（パッケージ名、リポジトリ id、
依存の capability）だけです。dnf の生の出力（リポジトリの URL を含むことが
あります）は表示しません。Sinter が認識できない出力はバイト数だけを報告し
（`… bytes of unrecognized dnf error output withheld`）、引き続き fail-closed に
なります。sensitive なリソースでは名前もすべて伏せられます。

## プラットフォームに関する補足

| プラットフォーム | バックエンド |
|------------------|--------------|
| Ubuntu 24.04 / 26.04 LTS | apt |
| Rocky Linux 8（SSH の接続先としてのみ） | dnf |
| Rocky Linux 9 / 10 | dnf |
| RHEL 9 / 10 | dnf |
| AlmaLinux 9 / 10 | dnf |
| Oracle Linux | dnf（互換性見込み — 受入検証は未実施） |

## 関連

[service](/ja/reference/resources/service/) ·
[実行モデル](/ja/concepts/execution-model/)
