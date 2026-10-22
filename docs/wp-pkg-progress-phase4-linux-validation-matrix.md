# WP-PKG-PROGRESS Phase 4 — Linux 実機検証マトリクス

- 作業: WP-PKG-PROGRESS Phase 4（進捗表示の Linux 実機検証計画）
- 日付: 2026-10-23
- 状態: **計画のみ。実機・VM・GCE は一切操作していない。**
- 実機試験の実施には Owner の別途承認を必要とする。

## 1. 目的と範囲

Phase 1〜3 で実装した APT / DNF のパッケージ進捗表示を、実際の Linux ホストで
検証するための再現可能な手順を定める。

対象:

- `package` リソースの `apply` における進捗詳細（`ProgressEvent::PackageDetail`）
- TTY（一時行）と plain（`SINTER_PROGRESS=plain`）の表示
- `status-fd` / 非 TTY 出力に基づく APT / DNF4 / DNF5 の文法
- 進捗の有無が実行結果・終了コード・JSON を変えないこと
- sudo / root / 一般ユーザー、SSH 切断、timeout、cancel

対象外:

- パッケージ管理機能そのものの変更
- Phase 5（リリース準備）
- 新規の進捗機能追加

## 2. 基本原則

1. **OS とバックエンドの対応を推測しない。** 各ホストで `/etc/os-release`、
   `command -v`、`--version` を実行し、Sinter が `target facts:` で検出した
   バックエンドを記録する。想定と異なれば、そのホストの試験を中止して記録する。
2. **1 ケース = 1 つの初期状態。** 破壊的操作の前にスナップショットを取得し、
   ケースごとに初期状態へ戻す。upgrade の「ダウングレードで戻す」は前提にしない。
3. **stdout と stderr を別々に保存する。** 進捗は stderr のみに出る。
4. **進捗あり / なしを同じ条件で比較する。** レシピ、対象ホスト、パッケージ、
   リポジトリ状態を揃える。
5. **未実行を PASS と書かない。** 実施していない項目は `NOT VERIFIED` のまま
   残す。

## 3. 環境

- 使い捨ての VM または GCE インスタンス（AGENTS の GCE ライフサイクル方針に従う）。
- 各ホストで root または `sudo -n` が使えること。一般ユーザー試験用に
  非特権ユーザーも 1 つ用意する。
- ネットワーク: 検証用リポジトリに到達できること。到達できない場合は
  キャッシュ済みパッケージで実施し、その旨を記録する。
- 記録: ホスト名、`/etc/os-release`、カーネル、アーキテクチャ、日時（JST）、
  実行したコマンド、終了コード。

## 4. 候補ホストと事前確認

候補は次の 7 つ。**バックエンドは「確認予定」であり、確定事実ではない。**

| ホスト | リリース | 確認するバックエンド（推測しない） | 事前確認コマンド |
|---|---|---|---|
| Rocky Linux 9 | 9.x | 要確認 | `cat /etc/os-release; command -v dnf rpm apt-get; dnf --version` |
| RHEL 9 | 9.x | 要確認 | 同上 |
| RHEL 10 | 10.x | 要確認（DNF5 の可能性を含む） | 同上。`dnf --version` の出力をそのまま記録 |
| Ubuntu 22.04 | 22.04 | 要確認 | `cat /etc/os-release; command -v apt-get dpkg; apt-get --version` |
| Ubuntu 24.04 | 24.04 | 要確認 | 同上 |
| Debian 12 | 12 | 要確認 | 同上 |
| Debian 13 | 13 | 要確認 | 同上 |

確認手順（読み取りのみ）:

```sh
cat /etc/os-release
uname -a
command -v apt-get dpkg dnf rpm || true
apt-get --version 2>/dev/null | head -1
dnf --version 2>/dev/null | head -3
rpm --version 2>/dev/null
```

Sinter 側の検出結果は `plan` の `target facts:` 行（ホスト名、OS、ファミリ、
バージョン、アーキテクチャ）から記録する。`target facts` と上記の手動確認が
食い違った場合は、そのホストを **BLOCKED** として記録し、推測で続行しない。

## 5. 期待する進捗（実装済みの契約）

実装（`src/package_progress/{apt,dnf}.rs`）が報告できるもの。実機で一致するかを
確認する対象であり、実機結果ではない。

| バックエンド | 局面 | 数値 | 表示例 |
|---|---|---|---|
| APT（status-fd） | `downloading`, `installing`, `configuring`, `triggering`, `removing` | ダウンロード集約 %、トランザクション操作 %、ファイル数、パッケージ名 | `download 42%`, `install 64%`, `remove 50%` |
| APT（status-fd なし） | 上記の局面語 | なし | `configuring nginx-1.24.0` |
| DNF4 | `resolving`, `downloading`, `installing`, `removing`, `verifying`, `triggering` | `file n/m`、`action n/m`、正確な `B`/`B/s` のみ | `installing nginx action 1/3` |
| DNF5 | `resolving`, `downloading`, `installing`, `removing`, `verifying`, `triggering` | `file n/m`（download バーのみ） | `installing nginx` |

不変条件（実機でも確認する）:

- パーセントは実測できたときだけ。ダウンロード % を install % として出さない。
- DNF5 のバー内 `100%` をトランザクション % として出さない。
- DNF4 の `action n/m` をパッケージ件数として出さない。
- 不明なパッケージ名を創作しない。
- `sensitive` の `package` リソースは詳細を出さない。

## 6. 試験ケース

各ケースを全ホストで実施する。`<pkg>` はそのホストのリポジトリに存在する
小さなパッケージ（例: `acl`、`nano`、`tree`）を、事前に `dnf/apt-cache` で
確認してから使う。

| ID | ケース | 目的 | 主な確認 |
|---|---|---|---|
| T-01 | install（依存なし） | 局面と件数の基本 | `downloading` → `installing`/`configuring`、終了コード 0 |
| T-02 | install（依存あり） | 複数パッケージの扱い | `action n/m` の増え方、downloading のファイル数 |
| T-03 | remove | 方向の正しさ | `removing` のみ。install と表示しない |
| T-04 | upgrade | upgrade の 2 アクション | `action n/m` が install + cleanup になること |
| T-05 | reinstall（対応バックエンドのみ） | 再導入 | 方向と件数 |
| T-06 | 存在しないパッケージ | 失敗時 | 進捗が失敗を成功に見せない。exit code と report |
| T-07 | GPG/署名エラーまたは依存解決失敗 | 失敗時 | 部分的な局面の後に失敗。詳細が結果を変えない |
| T-08 | キャッシュ済み install | download 局面が出ないこと | `downloading` を捏造しない |
| T-09 | `--downloadonly` 相当の prefetch（DNF） | DNF の download 局面 | prefetch でのみ `downloading` |
| T-10 | timeout（コマンド timeout） | 中断 | indeterminate、進捗の finish、後続コマンドなし |
| T-11 | SSH 切断 | 接続断 | 結果の分類、進捗の停止、再実行の扱い |
| T-12 | SIGINT（Ctrl-C 相当） | cancel | 終了コード、レポート、進捗の後始末 |
| T-13 | 一般ユーザー（sudo なし） | 権限 | 変更なし、明確な失敗、進捗が成功を示唆しない |
| T-14 | root 実行 | 権限差 | sudo 経由との表示・結果の一致 |
| T-15 | sensitive レシピ | 情報抑止 | パッケージ詳細が一切出ない |
| T-16 | 進捗なし（`SINTER_PROGRESS` 未設定・非 TTY） | 互換 | 出力が従来と同一 |
| T-17 | JSON | 機械可読 | stdout が JSON のみ、進捗ゼロ、byte 一致 |

## 7. 実行手順（1 ケースあたり）

### 7.1 準備

```sh
# 初期状態の記録
date -Is; cat /etc/os-release; uname -a
rpm -q <pkg> 2>/dev/null || dpkg-query -W -f='${Status} ${Version}\n' <pkg> 2>/dev/null || true
sudo -n true && echo sudo-ok || echo sudo-unavailable
```

スナップショットを取得する（VM: snapshot、GCE: 既存の承認済み手順に従う）。
GCE を使う場合は、作業前にインスタンスの元の状態を記録する。

### 7.2 進捗あり（plain）

```sh
SINTER_PROGRESS=plain sinter apply -f recipe.yaml >out.txt 2>err.txt
echo $?
```

記録: `out.txt`、`err.txt`、終了コード、`target facts`、`progress:` 行の抜粋。

### 7.3 進捗あり（TTY）

PTY 上で実行する（`script` など、環境にある手段を使う）。

```sh
script -q tty.txt sinter apply -f recipe.yaml
```

記録: 端末出力（最終行が消去されていること）、stderr の内容、終了コード。

### 7.4 進捗なし（比較）

```sh
env -u SINTER_PROGRESS sinter apply -f recipe.yaml >out0.txt 2>err0.txt
```

比較: `out.txt` と `out0.txt` が同一、`err.txt` から `progress:` 行を除いたものが
`err0.txt` と同一、終了コードが同一。

### 7.5 JSON

```sh
sinter apply -f recipe.yaml --format json >json.txt 2>json.err
```

比較: 進捗を出さない同一条件の JSON と byte 一致。`json.err` に進捗がないこと。

### 7.6 破壊的操作の後始末

ケースごとにスナップショットへ戻す。`remove` の逆は install で戻せるが、
`upgrade` は downgrade を前提にしない。GCE の一時リソースは方針に従って停止し、
削除は明示承認がある場合だけ行う。

## 8. バックエンド別の観測ポイント

### APT

- `status-fd` が実際に記録を出すか:
  `apt-get install -y <pkg> -o APT::Status-Fd=1 >apt.out 2>apt.err` を
  使い捨てホストで実行し、`apt.out` に `dlstatus:` / `pmstatus:` があるか確認する。
- `pmstatus` の percent がトランザクション全体の値か（`PackagesDone/PackagesTotal`）。
- `Setting up` / `Processing triggers` が `configuring` / `triggering` に対応すること。
- `remove` で `install` と表示しないこと（C1 の再発防止）。
- TTY では APT が色・進捗バーを出すが、Sinter の PTY なし実行では
  非対話出力になること。

### DNF4

- 非 TTY の stdout に `Installing/Erasing/Verifying` 行が出ること。
- 最終行のみ（`ti_done == ti_total`）が印字されること。
- `action n/m` が rpm トランザクションのアクション順であること。
- upgrade で install 行と `Cleanup` 行が出て、`action` が 2 アクションに
  なること。
- `Running scriptlet` が `%pre` でも出ること（件数を持たないことの確認）。
- download は prefetch（`--downloadonly`）でのみ発生すること。

### DNF5

- 非対話では完了したバーのみが出ること。
- バーの `[n/m]` が prepare を含むこと（パッケージ件数として扱わない）。
- バーの `100%` が項目単位であること（トランザクション % にしない）。
- `Prepare transaction` を局面として扱わないこと。

## 9. 合否基準

各ケースで以下をすべて満たすこと。

- 終了コードとレポートが、進捗の有無で同一。
- stdout が進捗で汚れない。JSON は byte 一致。
- 表示された数値が、取得元の出力と説明可能な形で一致する。
- 取得できない値が `0` や推測値で埋まらない。
- 失敗・timeout・切断で、進捗が成功を示唆しない。
- sensitive リソースで詳細が出ない。
- DNF4 の action 数をパッケージ数として表示しない。
- 狭い端末（例: 20 桁）でも失敗・成功の語が読める。

いずれかが満たされない場合は、そのケースを **FAIL** とし、差分・ログ・再現手順を
記録して停止する。勝手に修復しない。

## 10. 証跡

ケースごとに次を保存する。

```text
<case-id>/
  recipe.yaml
  cmd.txt
  out.txt / out0.txt
  err.txt / err0.txt
  json.txt / json.err
  tty.txt
  versions.txt        # /etc/os-release, uname, backend --version
  target-facts.txt    # Sinter の target facts
  result.txt          # exit code, PASS/FAIL, 判定理由
  sha256.txt
```

## 11. NOT VERIFIED（現時点）

- 上記 7 ホストのいずれでの実行も未実施。
- 各ホストのバックエンドとバージョンは未確認。
- APT `status-fd` の実出力、DNF4/DNF5 の実出力、sudo/SSH 経由の進捗は未確認。
- TTY の実表示（消去・幅・失敗語）は未確認。
- 切断・timeout・cancel 時の実挙動は未確認。
- 進捗の有無による結果一致性は、macOS 上の fake target 試験でのみ確認済み。

## 12. 承認

実機試験の開始には Owner の明示承認を必要とする。承認時に対象ホスト、期間、
GCE リソースの扱い、破壊的ケースの範囲を確定する。
