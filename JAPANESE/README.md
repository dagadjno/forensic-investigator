# forensic-investigator

**侵害された Windows マシンを自動で調査し、レポートを書き出す** ツールです。

Windows ホストから収集された証拠フォルダ（インシデント対応でアナリストが取得するようなもの — イベントログ、
レジストリハイブ、PowerShell 履歴など）を指定すると、まずその証拠を解析し、続いて AI エージェントが調査します
（データを読み、手がかりを追い、設問に答える）。そして **すべての記述が、正確な元レコードへの引用で裏付けられた**
Markdown レポートを生成します。答えが見つからないときはその旨を述べるか、手作業で確認すべきファイルを指し示します。
決してでっち上げません。

インシデント対応の初動調査（トリアージ）と、フォレンジックの **CTF** 課題（証拠イメージに関する設問リストに
答えるもの）の両方に役立ちます。

---

## Quick start

初めてですか？ うまくいく流れの全体を 4 ステップで（各ステップは後で詳しく説明します）:

```bash
# 1. 一度きりのセットアップ — Python 環境と、API キー用の .env ファイルを作る
python install.py
#    ...その後、作られた .env を開いて貼り付ける:  ANTHROPIC_API_KEY=sk-ant-...

# 2. 環境を有効化する（新しいターミナルごとに毎回）
.venv\Scripts\Activate.ps1            # Windows PowerShell
#    macOS / Linux:  source .venv/bin/activate

# 3. 安い最初の調査を実行する（--only Psh = PowerShell 履歴だけ）
python main.py investigate "PATH/TO/ACQ-IR-<host>" --case-id test --only Psh

# 4. 結果を読む
#    output/test/report.md   (任意のエディタで開く)
#    output/test/report.html (ブラウザで開く: 検索・並べ替え可能)
```

3 番目のコマンドは、あえて安くしてあります。準備ができたら: `--only Psh` を外して **本格的な** 調査を行う、
`--questions questions.txt` を足して **特定の設問** に答える、あるいは複数ホストの CTF 全体なら
**[CTF_PLAYBOOK.md](CTF_PLAYBOOK.md)** へ進んでください。詳細は以下を読み進めてください。

---

## 目次

1. [必要なもの](#1-必要なもの)
2. [インストール（順を追って）](#2-インストール順を追って)
3. [最初の調査を実行する](#3-最初の調査を実行する)
4. [特定の設問を尋ねる](#4-特定の設問を尋ねる)
5. [出力を理解する](#5-出力を理解する)
6. [データベースを自分で調べる](#6-データベースを自分で調べる)
7. [実行モード（コストと範囲の制御）](#7-実行モードコストと範囲の制御)
8. [実行を再開する](#8-実行を再開する)
9. [別の AI プロバイダを選ぶ](#9-別の-ai-プロバイダを選ぶ)
10. [メモリイメージの解析（任意）](#10-メモリイメージの解析任意)
11. [設定ファイル](#11-設定ファイル)
12. [仕組み（内部の動き）](#12-仕組み内部の動き)
13. [状況と今後の予定](#13-状況と今後の予定)

---

## 1. 必要なもの

- **Python 3.10 以降** がインストールされていること。`python --version` で確認。
- **AI の API キー。** 既定では Anthropic（Claude）を使います。`ANTHROPIC_API_KEY` が必要です
  （または OpenAI / Gemini のキー — [第 9 章](#9-別の-ai-プロバイダを選ぶ) 参照）。調査の実行は
  課金される API 呼び出しを行うので、いくらかクレジットのあるキーが必須です。
- 調査対象となる **Windows の証拠フォルダ。** 本ツールは **AChoirX 形式のトリアージ収集データ** 向けに
  作られています: `Evt`（イベントログ）、`Reg`（レジストリ）、`Psh`（PowerShell 履歴）のような短い code の
  サブフォルダを持つフォルダです。典型的なフォルダ名は `ACQ-IR-<hostname>-<date>` のようになります。
  フォルダは常に **読み取り** のみ — ツールが証拠を書き換えることはありません。

> 手元にコレクションがない？ 本ツールは DC33「OBSIDIAN」CTF のデータセット向けに作られましたが、同じ dir-code
> 構成を使うフォルダなら何にでも動きます（認識する code の一覧は `config/artifact_map.yaml` 参照）。

---

## 2. インストール（順を追って）

### 手早い方法（1 コマンド）

プロジェクトフォルダから、セットアップスクリプトを実行します — 仮想環境を作り、依存パッケージを入れ、`.env` を
用意します:

```bash
python install.py              # フル: 本体 + Volatility メモリ解析 (第 10 章)
python install.py --no-memory  # 本体のみ (Volatility を省略)
```

その後、作られた `.env` に API キーを足せば準備完了です（[第 3 章](#3-最初の調査を実行する)）。
どの OS でも動き、標準ライブラリだけを使い、再実行しても安全です。手作業でやりたいときの手順は以下です。

### 手作業でのセットアップ

**プロジェクトフォルダ**（`main.py` があるフォルダ）でターミナルを開いて実行:

```bash
# 1. 隔離された Python 環境を作る（推奨。環境を散らかさずに済む）
python -m venv .venv

# 2. 有効化する
#    Windows (PowerShell):
.venv\Scripts\Activate.ps1
#    macOS / Linux:
source .venv/bin/activate

# 3. ツール本体と依存パッケージを入れる
pip install -r requirements.txt
```

### API キーを足す

プロジェクトフォルダに `.env` という名前のファイルを作る（テンプレートをコピー）:

```bash
cp .env.example .env
```

`.env` をテキストエディタで開き、キーを記入する:

```
ANTHROPIC_API_KEY=sk-ant-...your key here...
```

これで完了です — ツールは `.env` を自動で読み込みます。（`.env` は git の管理対象外なので、キーが
コミットされることはありません。）お好みで、シェルで環境変数を設定してもかまいません:
`export ANTHROPIC_API_KEY=...`（PowerShell: `$env:ANTHROPIC_API_KEY="..."`）。

---

## 3. 最初の調査を実行する

基本のコマンドはこちら:

```bash
python main.py investigate "PATH/TO/EVIDENCE/FOLDER" --case-id myfirstcase
```

- `PATH/TO/EVIDENCE/FOLDER` を証拠フォルダ（中に `Evt`、`Reg`、`Psh` … があるもの）のパスに置き換える。
  **クォートは付けたまま** に — パスにはよくスペースが含まれます。
- `--case-id` は、この調査に自分で付けるラベルにすぎません。結果は `output/myfirstcase/` の下に保存されます。

例（Windows のパス）:

```bash
python main.py investigate "C:/Users/me/Downloads/ACQ-IR-namtws001-20250702-0113" --case-id ws001
```

処理中は進捗が表示されます:

```
🔍 Ingesting namtws001-20250702-0113 ...
    📂 parsing Evt (event_logs) ...
    ✅ [evtx] parsed 20 high-value channels, emitted 24630 events (backend: evtx)
    📊 cataloged 686 files, 26657 timeline events
🧠 Investigating (run to completion) ...
  🔎 lead #1 [coverage] Explore the Psh (powershell_history) artifacts
       step 1: kb_read(...)
       ...
📝 Writing report ...
✅ Done. Report: .../output/ws001/report.md
```

終わったら **`output/ws001/report.md`** を開いてください — これが調査レポートです。

> ⚠️ 本格実行は **すべての** 証拠カテゴリを調べ、多数の AI 呼び出しを行うことがあります。最初の実行を安く
> するには [実行モード](#7-実行モードコストと範囲の制御) を参照 — 例えば `--only Psh` を付けて 1 カテゴリだけを
> 調べます。

> **出力についての補足:** ターミナルでは出力に色が付き、解析中はその場で書き換わる進捗行が出ます。ファイルへ
> リダイレクトすると素のテキスト（色コードなし）になります。長時間の実行はマシンの **自動スリープ** を自動で
> 防ぎます（Windows — ただしノート PC は **蓋を開けたまま** に。蓋の制御は電源プランが別に行います）。
> 素の出力にするには `NO_COLOR=1` または `NO_EMOJI=1` を設定します。

---

## 4. 特定の設問を尋ねる

CTF 形式の作業では、答えてほしい設問そのものをツールに渡します。プレーンテキストのファイル（例
`questions.txt`）に **1 行 1 問** で入れます:

```
攻撃者はどのリモートアクセスツールを、どうやってインストールしたか?
command-and-control サーバーの IP アドレスは何か?
攻撃者はどのユーザーアカウントを Administrators グループに追加したか?
```

そしてツールに指定する:

```bash
python main.py investigate "PATH/TO/EVIDENCE" --case-id ws001 --questions questions.txt
```

一度きりの簡単な質問ならファイルは不要 — **`--question`** で直接渡します（繰り返し可、`--questions` との併用も可）:

```bash
python main.py investigate "PATH/TO/EVIDENCE" --case-id ws001 --question "C2 の IP は?"
python main.py investigate "PATH/TO/EVIDENCE" --case-id ws001 \
    --question "C2 の IP は?" --question "どの RAT がインストールされたか?"
```

> **`--question` は case の設問一覧に *追加* し、`--questions FILE` は *置き換え* ます。** つまり同じ
> `--case-id` に対して後から直接別の設問を尋ねると、以前のものは *残ります*（積み上がります） — 一方
> `--questions` ファイルで再実行すると、そのファイルが新しい一覧になります（消した行は落ちます）。ファイルを
> 「正」としたいときはファイルを使ってください。

レポートには、各設問に対応する **回答シート** が入ります。設問を与えると、AI はどの証拠カテゴリが最も関連するかも
自動で判断し、それらを先に調べます。

> **CTF 用の補助（自動）:** エージェントは仕込まれたフラグのマーカー — `btv{...}`、`flag{...}`、`FL4G={...}` — を
> すべての証拠から探し、回答として表に出します。また、ファイル名 / コマンド / パスを **そのまま** 返します
> （例: `AdFind` ではなく `AdFind.exe`）。完全一致で採点する仕組みに合わせるためです。設定するフラグはありません。

複数ホストの解析、設問のホストへの振り分け、準備チェックリスト、トラブルシューティングを含む **ライブ CTF の
手順書** は **[CTF_PLAYBOOK.md](CTF_PLAYBOOK.md)** を参照してください。

---

## 5. 出力を理解する

各実行は `output/<case-id>/` フォルダを作り、次を含みます:

| ファイル | 内容 |
|------|------------|
| `report.md` | 人が読むためのレポート（これを開く）。 |
| `report.html` | 自己完結・オフラインの **対話的** 版レポート — ブラウザで開いて回答 / 検出結果 / カバレッジを検索・絞り込み・並べ替えできる（行をクリックすると引用付きの裏付けを表示）。複数ホスト版の `report.html` と同じダッシュボードを、このホストに絞ったもの。 |
| `case.db` | 解析済みの証拠と検出結果をすべて格納した SQLite データベース（自分で調べられる — [第 6 章](#6-データベースを自分で調べる) 参照）。 |

毎回自動で作られます。既存の `case.db` から **`report.html` を作り直す** には（Markdown ではなくデータベースを
読みます）: `python scripts/report_html.py output/<case-id>`（`--open` で開く）。パスを省くと、代わりに
ホスト横断の統合ダッシュボードを作り直します。

**レポート** には次の節があります:

- **回答シート**（設問を与えた場合） — 各設問は次のいずれかとして解決されます:
  - **ANSWERED** — 直接の答え。正確な元レコードへの引用付き。よく裏付けられた答えが複数見つかったときは、
    選べるように全候補が表示されます。
  - **POINTER** — ツール自身では答えを読めない（例: 画像の中や、解析しないバイナリの中）ため、手作業で
    調べるべきファイルを指し示します。*推測はしません。*
  - **UNRESOLVED** — 探したが何も見つからなかった。**何を調べたか** を記録します（手がかりがステップ数の上限を
    使い切った場合でも、抜けが黙って空欄になることはありません）。
- **検出結果 (Findings)** — 見つけた注目すべき事項（深刻度、関連する場合は ATT&CK テクニック、引用付き）。
- **カバレッジと抜け** — すべての証拠カテゴリについて、解析されたか、調べられたかを示す表。何が調べられ、何が
  調べられなかったかが分かります。

**引用 (locator)** は `` `event_logs:Evt/.../Security.evtx:269584` `` のように見えます — これは正確なレコードへの
安定した指し示しです。すべての主張に 1 つ付いており、ツールが検証できなかったものは印が付きます。
（自分で引用をたどる方法は次の節。）

---

## 6. データベースを自分で調べる

ツールが解析し、結論づけたものはすべて `output/<case-id>/case.db`（標準の **SQLite** データベース）にあります。
直接たどれます — レポートより深く掘りたいとき、引用を検証したいときに便利です。

### 最も簡単: 同梱の `query.py`

repo には **`scripts/query.py`** が同梱されています — データベースのパスを引数に取り（どのホストの `case.db`
でも動く）、**読み取り専用** で開きます（うっかり書き込みが証拠に触れることはありません）。SQL なしで実行すると、
テーブルと行数を一覧します:

```bash
python scripts/query.py output/ws001/case.db                                  # テーブル一覧
python scripts/query.py output/ws001/case.db "SELECT severity, title FROM findings"
python scripts/query.py output/ws001/case.db "SELECT * FROM answers" --limit 5
```

または、ファイルなしで Python の 1 行（SQLite は Python 組み込み）:

```bash
python -c "import sqlite3; c=sqlite3.connect('output/ws001/case.db'); [print(r) for r in c.execute('SELECT severity, title FROM findings')]"
```

### `scripts/` の補助ツール

repo には小さな **読み取り専用** の補助ツール（AI なし、コストなし）がいくつか同梱されています。一覧:

| スクリプト | 何をするか |
|--------|--------------|
| `python scripts/query.py <case.db> ["SQL"]` | 1 つの case に SQL を実行（読み取り専用）。SQL なし → テーブル + 行数を一覧。 |
| `python scripts/search.py <term> [more…]` | 設問がどのホストのものかを見つける。複数語 = 既定で **AND** — **1 つの行** がすべての語を含む項目だけ。ホストごとの件数 + バケット別内訳を表示。一致した行 + locator は `--show`、OR は `--any`。 |
| `python scripts/whoanswered.py` | どのホストがどの設問に答えたかを一覧。 |
| `python scripts/aggregate.py` | ホスト横断の **統合回答シート**（`output/_combined/answer_sheet.md`）を作る。 |
| `python scripts/report_html.py [output/<case-id>]` | **対話的な HTML ダッシュボード** を(作り直)す — 1 ホスト、または引数なしで全ホスト統合。`--open` で開く。 |

複数ホスト向けのもの（`search`、`whoanswered`、`aggregate`、`report_html`）は [CTF_PLAYBOOK.md](CTF_PLAYBOOK.md)
§4 で、設問をホストへ振り分け、結果を読むために使います。

### あるいは sqlite3 コマンドラインツールを使う

`sqlite3` CLI が入っている場合:

```bash
sqlite3 output/ws001/case.db
```

`sqlite>` プロンプトで読みやすい出力を有効にし、クエリを実行:

```sql
.mode box
.headers on
SELECT severity, title FROM findings;
```

### あるいは無料の GUI を使う

[DB Browser for SQLite](https://sqlitebrowser.org/) を使えば `case.db` を開き、クリック操作でテーブルを
閲覧・検索できます — SQL に不慣れなら便利です。

### 気になるテーブル

| テーブル | 中身 |
|-------|--------------|
| `events` | 正規化されたタイムライン — 解析したレコードごとに 1 行（PowerShell コマンド、イベントログの項目、レジストリの値…）。列: `ts`、`source_artifact`、`user`、`event_type`、`summary`、`locator`。 |
| `findings` | AI が結論づけたこと。列: `severity`、`confidence`、`attack_technique`、`title`、`description`。 |
| `finding_evidence` | 各検出結果の引用（`finding_id`、`locator`、`excerpt`）。 |
| `answers` | 設問への解決（`question_id`、`status`、`answer`、`confidence`）。 |
| `answer_evidence` / `answer_candidates` | 各回答の引用 / 指し示されたファイル。 |
| `questions` | 与えた設問（`id`、`text`）。 |
| `coverage` | 各証拠カテゴリと、それが調べられたか（`artifact`、`parser`、`status`）。 |
| `files` | コレクション内の **すべて** のファイルのメタデータ（解析されないものも含む） — `path`、`owner`、`size`、時刻。ツールが読めないファイルを指し示せるのは、これのおかげです。 |
| `leads` | 調査の待ち行列（何が、どの順で調べられたか）。 |

> `events.source_artifact` の列は、その行をどの解析器 (parser) が作ったかを示します。値:
> `powershell_history`、`event_logs`、`registry`、`amcache`、`browser`、`lnk`、`usn`、
> `srum`、加えて必要時に呼ばれる `mft`（`mft_lookup` から）と `memory`（Volatility から）。

### 便利なクエリ例

```sql
-- 全検出結果、深刻度の高い順
SELECT severity, attack_technique, title FROM findings;

-- 検出結果 #4 の裏付け（引用）を表示
SELECT locator, excerpt FROM finding_evidence WHERE finding_id = 4;

-- タイムライン全体で IP / キーワードを検索
SELECT source_artifact, user, summary, locator
FROM events WHERE summary LIKE '%13.58.222.12%';

-- 各ソースから来たタイムラインのイベント数は?
SELECT source_artifact, COUNT(*) FROM events GROUP BY source_artifact;

-- タイムライン内のすべての PowerShell コマンドを見る
SELECT user, summary FROM events WHERE source_artifact = 'powershell_history';

-- 設問への回答を確信度付きで
SELECT q.text, a.status, a.answer, a.confidence
FROM answers a JOIN questions q ON q.id = a.question_id;

-- どの証拠カテゴリが調べられ、どれが飛ばされたか?
SELECT artifact, parser, status FROM coverage WHERE present = 1;

-- レポート内の引用が何を指しているかを調べる
SELECT summary FROM events WHERE locator = 'event_logs:Evt/Sys32/Windows/System32/winevt/Logs/Security.evtx:269584';

-- 名前で候補ファイルを探す (例: 答えを持つかもしれない画像)
SELECT path, owner, size, mtime FROM files WHERE path LIKE '%.png';
```

---

## 7. 実行モード（コストと範囲の制御）

本格実行はすべての証拠カテゴリを調べるので、遅く / 高コストになり得ます。次のフラグで作業量を制御します:

| コマンド | 何をするか | いつ使うか |
|---------|--------------|-------------|
| *(フラグなし)* | **すべての** カテゴリを調べる。設問があると、AI がカテゴリを関連度で並べ、関連の高いものから調べる。 | 徹底的な調査; 何も見落としたくない。 |
| `--only Psh,Evt` | 挙げたカテゴリ **だけ** を調べる。他へ手がかりを追わない。 | 最も安い / 速い。最初の試しや、絞った確認に最適。 |
| `--only Psh,Evt --expand` | 同上だが、必要なら AI が他のカテゴリへ手がかりを追える。 | 絞りつつ、証拠をまたいだ相関を許す。 |
| `--relevant-only` | AI が設問に関連するカテゴリを選び、それだけを調べる。 | 絞った設問向け。（注: *広い* 設問ではほぼ全部を選ぶことがある — 本当に絞るには `--only`。） |
| `--ingest-only` | 証拠を `case.db` に **解析** して止まる — AI なし、コストなし。 | 解析済みの土台を一度作り、（遅い）証拠を解析し直さずに、多数の安い実行で再利用する。 |
| `--reingest` | この case が取り込み済みでも、新規に解析し直す。 | 解析器を変えた後、またはコレクションが変わった場合。 |

例:

```bash
# できるだけ安い最初の実行 — PowerShell 履歴だけ:
python main.py investigate "PATH" --case-id test --only Psh

# 設問に絞り、範囲は AI に任せる:
python main.py investigate "PATH" --case-id ws001 --questions questions.txt --relevant-only

# AI なしで一度解析し、その解析済み case.db を繰り返し実行で再利用する:
python main.py investigate "PATH" --case-id base --ingest-only
#   ...後で、output/base/case.db を output/run1/case.db にコピーして run1 を調べる
#   (解析済みだと気づき、そのまま調査に進む — 解析し直さない)。
```

カテゴリの code（`Psh`、`Evt`、`Reg` …）は `config/artifact_map.yaml` に一覧があります。

### 多数のホストを一度に（並列）

複数ホストの case（例えば CTF 全体）では、`run_hosts.py` が複数のホストを **並列** で実行します — それぞれが
自分のプロセスと `case.db` を持ち、`--jobs` で上限を設けます。`investigate` と同じフラグを受け取ります
（各ホストのコンソール出力は `output/<host>/run.log` へ）:

```bash
# 全ホストを一度解析、4 並列 (AI なし):
python run_hosts.py "PATH/TO/FORENSICS/ACQ-IR-*" --ingest-only --jobs 4

# その後、1 つの設問一覧に対して全ホストを調べる、3 並列:
python run_hosts.py "PATH/TO/FORENSICS/ACQ-IR-*" --questions questions.txt --relevant-only --jobs 3
```

**特定のホストだけがよい？** glob / パスを複数渡す — 和集合になるので、望むホストを正確に指定できます
（命名は自由、共通のパターンは不要）:

```bash
# この 2 ホストだけ:
python run_hosts.py "PATH/.../ACQ-IR-dc01-*" "PATH/.../ACQ-IR-ws003-*" --questions questions.txt --jobs 2
# パターンを共有するなら文字クラスの glob:  ".../ACQ-IR-ws00[34]-*"
```

各ホストのステップごとの出力は **`[host]` タグ付きでコンソールにその場で流れる** ので、進んでいるのが分かります —
各ホスト完了時の 1 行だけにするには `--quiet` を渡します。すべての実行（単一ホストでも並列でも）は、完全で
**時刻付き** の `output/<host>/run.log` も書き出します。

**どの設問がどのホストか分からない？** 全設問を全ホストで実行するだけ（上記） — *どれか* のホストが答えれば
設問は解決です。調査の一括実行が終わると、`run_hosts.py` は **2 つの統合ビューを自動生成** します
（どちらもいつでも作り直せる、読み取り専用 / コストなし）:

- **`output/_combined/answer_sheet.md`** — 対応表（設問 → どのホストが答えたか）に加え、全ホスト横断で
  照らし合わせた設問ごとの最良回答。（`python scripts/aggregate.py`）
- **`output/_combined/report.html`** — **自己完結・オフラインの対話的ダッシュボード**: ブラウザで開き、全ホストの
  回答 / 検出結果 / カバレッジを横断して **検索・絞り込み・並べ替え** できる（行をクリックすると引用付きの裏付けを
  展開）。ネットワークも依存もなし — データは埋め込み済み。（`python scripts/report_html.py --open`）

---

## 8. 実行を再開する

**同じ `--case-id`** で再実行すると、最初からやり直すのではなく、止まったところから続きます:

- 解析は **繰り返されません**（保存済み）。新規に解析し直すには `--reingest` を足す。
- 実行が落ちたか止めた場合、未完の作業がやり直されます。
- **設問はその本文で照合されます。** 変えていない設問で再実行すると、その回答は残ります（やり直しません）。
  設問を **変えた**（または新しく足した）場合は、それが新規に調べられます — すでに解析済みの証拠を使うので、
  追加の設問のために解析し直す料金は発生しません。今の設問一覧を設定するには `--questions` を渡します。

```bash
# 最初の実行でいくつかの設問に答え、その後 questions.txt に新しい設問を足す:
python main.py investigate "PATH" --case-id ws001 --questions questions.txt
# (questions.txt を編集し、1 行足す)
python main.py investigate "PATH" --case-id ws001 --questions questions.txt   # 新しい設問だけが調べられる
```

---

## 9. 別の AI プロバイダを選ぶ

本ツールは **Anthropic（Claude）**、**OpenAI**、**Gemini** に対応します。Anthropic が既定で、最もよく
テストされています。切り替えるには `config/config.yaml` を編集し、そのプロバイダの SDK を入れます。

```yaml
# config/config.yaml — 調査を行うのは "subagent" の役割
models:
  subagent: { provider: anthropic, model: claude-sonnet-4-6 }  # 既定 (最高精度は claude-opus-4-8)
  # subagent: { provider: openai,  model: gpt-5 }
  # subagent: { provider: gemini,  model: gemini-2.5-pro }
```

対応する SDK を入れ、対応するキーを設定します:

| プロバイダ | Install | 環境変数 |
|----------|---------|---------|
| Anthropic | (同梱) | `ANTHROPIC_API_KEY` |
| OpenAI | `pip install -e ".[openai]"` | `OPENAI_API_KEY` |
| Gemini | `pip install -e ".[gemini]"` | `GEMINI_API_KEY` (または `GOOGLE_API_KEY`) |

実際に使うプロバイダの SDK だけが必要です。**OpenAI と Gemini のバックエンドは各 SDK の公式仕様に従いますが、
Anthropic ほど実戦で鍛えられていません — 最初の実行で確認してください。**

---

## 10. メモリイメージの解析（任意）

コレクションに RAM のキャプチャ（`.raw` / `.mem` / `.dmp` イメージを含む `MemDump/` フォルダ）が含まれる場合、
エージェントは **Volatility3** でそれを解析し、メモリにしか存在しない答え — 実行中のプロセス、動いている
ネットワーク接続、注入されたコード、コンソールで打たれたコマンド — に答えられます。

**`python install.py` はこれを既定でセットアップします**（下記の `.venv-vol` 環境を作ります）。この章はそれが
何かを説明します — 手作業のセットアップ、2 台目のマシン、Docker、または `--no-memory` で入れた場合に役立ちます。

Volatility は、依存関係が本体と衝突しないよう **専用の仮想環境** に置かれます。ツールは単にそこを呼び出します。
メモリが未設定でも、ツールはうまく機能低下します（メモリ系の設問は POINTER になる） — ただし `config.yaml` は
`enabled: true` で配布されるため、設定するか `memory.enabled: false` にするまで Volatility のエラーが出ます。

### 手作業で設定する（マシンごとに一度）

```bash
# repo の直下から
python -m venv .venv-vol

# その中に Volatility を入れる
.venv-vol/Scripts/pip install -r requirements-memory.txt   # Windows
.venv-vol/bin/pip install -r requirements-memory.txt       # macOS / Linux
```

動作を確認する:

```bash
.venv-vol/Scripts/vol --help     # Windows
.venv-vol/bin/vol --help         # macOS / Linux
```

> 初めてイメージを解析するとき、Microsoft から Windows の **シンボルテーブル** をダウンロードします（一度だけ
> インターネットが必要）。その後はキャッシュされます。Volatility3 の中核は pure-Python なので、最新の Python でも
> きれいに入ります。

### 有効にする

`config/config.yaml` で有効にし、`vol_cmd` をそのマシンの実行ファイルに向けます:

```yaml
memory:
  enabled: true
  vol_cmd: [".venv-vol/Scripts/vol.exe"]    # Windows
  # vol_cmd: [".venv-vol/bin/vol"]          # macOS / Linux
  cache_dir: output/_memcache               # イメージごとのプラグインキャッシュ (再実行は無料)
```

リストの最初の要素は repo の直下から解決されます。リストなので、代わりに Docker 経由で Volatility を実行する
こともできます: `vol_cmd: ["docker","run","--rm","-v","...","volatility3"]`。

> **なぜ `.venv-vol/` はコミットされない？** 仮想環境はマシン・OS・Python バージョンに固有です（絶対パスと
> プラットフォーム依存のバイナリを埋め込みます）。コミットしても別のマシンではどのみち動きません。持ち運べる
> 成果物は **手順** — `requirements-memory.txt` と上の 2 コマンド — であり、これがどこでも作り直します。

### 実行中に何をするか

設問が揮発性の証拠を必要とするとき、エージェントは特定の Volatility プラグイン（例: `windows.netscan`、
`windows.pslist`、`windows.malfind`、`windows.cmdline` / `consoles`）に対して `vol_run` ツールを呼び、各結果の
行は通常どおり **引用可能な** タイムラインのレコード（`source="memory"`）になります。メモリは遅いので、
エージェントは的を絞って使い — ディスク上の証拠で答えられないときだけ — 結果はプラグインごとにキャッシュされます。

> 1 つの制限: この Volatility ビルドには **資格情報のダンププラグインがありません**（hashdump / lsadump なし）。
> *打鍵された* 秘密については、エージェントは `consoles` / `cmdline` を試します。それ以外はイメージを POINTER します。

---

## 11. 設定ファイル

| ファイル | 目的 |
|------|---------|
| `config/config.yaml` | 各役割がどの AI モデルを使うか、effort の水準、安全のための予算（最大ステップ / リード数、加えて設問ごとのリード上限と、ホストごとの実行時間の上限）、そして `memory:` ブロック（Volatility の設定 — [第 10 章](#10-メモリイメージの解析任意) 参照）。 |
| `config/artifact_map.yaml` | 証拠フォルダの code（`Evt`、`Reg` …）を種類と解析器に対応づける — **コレクション構成のための橋渡し**。別構成のコレクションに対応するには編集する（または `--artifact-map` を渡す）。 |
| `config/artifact_map.stock.yaml` | **stock AChoirX** の出力（DC33 の独自構成とは別）向けの既製の対応表。`--artifact-map` で使う。 |
| `knowledge_base/` | AI が調査中に読む、素の Markdown の「プレイブック」と参考資料。**これらを編集すれば、コーディングなしでツールの動きを改善できます。** |
| `.env`（`.env.example` から） | API キー。自動で読み込まれ、git の管理対象外。 |
| `requirements.txt` / `requirements-memory.txt` | 本体の依存 / メモリ解析用の任意の Volatility 依存。 |

### 別のコレクションや新しい収集ツールで使う

本ツールは **AChoirX** 形式のトリアージ収集データを中心に作られています（DC33 のデータセットは *独自の* AChoirX
収集ツールを使用）。ただし 1 つの構成に固定されてはいません: `artifact_map.yaml` が各最上位の **フォルダ code** を
種類 + 解析器に対応づけるので、別構成への適応はたいてい **YAML の編集で済み、コードではありません**。

**本格実行の前にコレクションを確認する**（決まった手順どおり、AI なし、コストなし）:

```bash
python main.py check "PATH/TO/COLLECTION"
```

どのフォルダ code が認識されるか、各解析器が期待する入力を見つけられるか（CSV 解析器については列が合うか）、
そして判定 — **COMPATIBLE / PARTIAL / UNRECOGNIZED** を報告します。新しい出所のコレクションには、まずこれを
実行してください: 解析器は不慣れな構成では *静かに* 機能低下します（足りないファイルを飛ばし、0 を出す）。
そのため、ほぼ空の結果が「うまくいった」ように見えてしまうことがあります。`check` はそれを明示します。

**別の対応表を使う** には `--artifact-map`（`check` と `investigate` の両方で使えます）:

```bash
python main.py check      --artifact-map config/artifact_map.stock.yaml "PATH/TO/COLLECTION"
python main.py investigate --artifact-map config/artifact_map.stock.yaml "PATH" --case-id x
```

**stock AChoirX** の出力向けの既製の **`config/artifact_map.stock.yaml`** が同梱されており、**実際の stock
コレクション（AChoirX 2026）に対して検証済み** です — すべての解析器が動き、`check` は COMPATIBLE を報告します。
stock は DC33 構成とおよそ 95% 同じで（同梱のエクスポートツールが同じなので browser / USN の CSV 形式は合い、
バイナリ形式は標準）、違うのは一部のフォルダ code だけです: autoruns `Arn`→`ASEP`（CSV）、sysinfo `Sys`→`SYS`、
本物の prefetch は `Prf`（run-program のコピーは引き続き `RanProg`）、そして新しい `PCA` バケット（Program
Compatibility Assistant — 実行の証拠）。他の収集ツールについては、`artifact_map.yaml` をコピーし、`check` が
報告する内容に合わせて code の名前を変える / 足すだけで完了です。

---

## 12. 仕組み（内部の動き）

```
証拠フォルダ (読み取り専用)
  │
  ▼  [A] 解析 (決まった手順、AI なし)   → 正規化したレコードを case.db に保存
  │       定評あるフォレンジック解析器が、バイナリの証拠を構造化した行に変える。
  │
  ▼  [B] 手がかり(lead)を用意する (あなたの設問 + 証拠カテゴリごとに 1 つ)
  │
  ▼  [C] エージェントのループ
  │       オーケストレーターが各手がかりをサブエージェントに渡す。サブエージェントはツールでデータを読み、
  │       検出結果 / 回答を書き（それぞれ引用付き）、新しい手がかりを立てられる。すべてが調べ尽くされ、
  │       待ち行列が空になるまで実行する。
  │
  ▼  [D] レポート: 検出結果から Markdown を書き、続いてすべての引用が解決することを検証する。
```

一部の証拠は、ステップ [A] で一括解析する代わりに **必要時に** 解析されます: フル `$MFT`（`mft_lookup` ツール
経由）とメモリイメージ（`vol_run` / Volatility 経由）は丸ごと解析するには大きすぎるので、[C] の間、手がかりが
必要とするときだけ遅れて調べられます — そしてその結果は同じ引用付きタイムラインに加わります（`source="mft"` /
`"memory"`）。

**重要な設計ルール:** AI は生のバイナリ（イベントログ、レジストリハイブ、メモリダンプ）を決して解析しません。
信頼できるフォレンジック解析器がまず構造化レコードを取り出し、AI はその正規化データの上でのみ考え、すべての
主張に実在のレコードを引用しなければなりません。これが、でっち上げを防ぎます。

> **エンジニア向け:** AI アーキテクチャの全体 — エージェント構成、オーケストレーターとサブエージェントが Case
> File を通じてどう協調するか、ツールの層、引用の強制、LLM まわりの実装 — は **[ARCHITECTURE.md](ARCHITECTURE.md)** を
> 参照してください。

---

## 13. 状況と今後の予定

「済」と付いた解析器と機能は、実際の証拠で動作・テスト済みです。

- [x] 中核エンジン: 解析 → タイムライン（`case.db`）→ エージェントのループ → 引用付き Markdown レポート
- [x] 引用の強制 + 検証（引用のない主張なし）
- [x] `Psh`（PowerShell 履歴）解析器
- [x] `Evt`（Windows イベントログ / EVTX）解析器 — Rust ベース（`evtx`）で高速; 厳選した重要チャンネル & ID
      （Kerberos/NTLM、AD グループ管理、ファイル共有アクセス、サービスのインストール/終了、アプリのクラッシュ +
      MSI インストール（Application ログ）、WMI/BITS/AppLocker/RDP-client/SMB/Directory-Service を含む）
- [x] `Reg`（レジストリ）解析器 — 永続化、アカウント、ソフトウェア、デバイス、ユーザー操作
- [x] Amcache 解析器（`source="amcache"`）— プログラム実行の証拠 + SHA1 ハッシュ
- [x] `Brw`（ブラウザ）解析器 — 履歴 & ダウンロード（`source="browser"`）
- [x] `Lnk`（ショートカット/LNK）解析器 — 最近開いたファイル: 対象パス、MAC 時刻、ボリューム
- [x] USN ジャーナル解析器（`source="usn"`）— 厳選したファイルの作成/削除/名前変更のタイムライン
- [x] 必要時の `$MFT` 照会ツール — 名前からファイルのフルパス + `$SI`/`$FN` 時刻を解決する
      （フル `$MFT` は意図的に一括解析しない; これは的を絞った遅延処理）
- [x] `Sys` SRUM 解析器（`source="srum"`）— アプリの活動時間帯 + ネットワーク接続
- [x] 複数プロバイダの AI（Anthropic / OpenAI / Gemini）、再開、設問に応じた範囲の絞り込み
- [x] エージェントは専用の解析器がなくても、テキスト / CSV の証拠（例: `Conn/CPorts.csv`、
      `Sys/LastActivity.csv`）を直接読める
      （注: このデータセットでは `Ranprog` は `.pf` の prefetch ではなく、実行ファイルの *コピー* を持つ）
- [x] メモリイメージの解析（Volatility3）— 隔離された仮想環境の上で、必要時に `vol_run` ツール
      （任意; [第 10 章](#10-メモリイメージの解析任意) 参照）
- [x] コレクション互換性の `check` コマンド + `--artifact-map` の構成橋渡し — **実際の stock AChoirX (2026)
      コレクションで検証済み** の既製対応表を含む（すべての解析器が動く; 新しいバケット `ASEP`/`PCA`/`Prf` を
      目録化 + プレイブックの案内付きで、必要時に読む）
- [x] 複数ホストの並列実行（`run_hosts.py`、その場で出力）+ CTF 用の補助（`find_flags` による決まった手順での
      仕込みフラグ探索、そのままのトークン回答、直接指定の `--question`）
- [x] ホスト横断の統合 **回答シート** + 対話的 **HTML ダッシュボード**（全ホストを検索 / 絞り込み / 並べ替え;
      ホストごとの `report.html` も）— `aggregate.py` / `report_html.py`
- [ ] ホスト横断の相関 — 単一のエージェントがドメイン全体を *まとめて* 調べる（現在は各ホストを個別に調べ、
      結果を後から統合している）
```
