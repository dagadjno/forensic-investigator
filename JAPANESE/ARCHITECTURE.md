# アーキテクチャ

**forensic-investigator** に取り組むエンジニア向けの参考資料です。エージェント構成、エージェント同士の協調の
仕方、ツールの層、すべてが Case File（SQLite）をどう読み書きするか、そして LLM まわりの実装を説明します。
*使い方* は `README.md`、当日の CTF 手順書は `CTF_PLAYBOOK.md` を参照してください。

---

## 1. 設計の主張（まずこれを読む）

このシステム全体は、LLM に **でっち上げなしで** フォレンジックを行わせるために存在します。すべての設計判断を
決めるルール:

> **LLM は生のバイト列を決して解析せず、実在の解析済みレコードに引用できないことは一切断言できない。**

これは、プロンプトだけでなく構造として、3 つの方法で強制されます:

1. **考える前に解析する。** 決まった手順で動く信頼できる解析器が、バイナリの証拠（EVTX、レジストリハイブ、
   `$MFT`、SRUDB.dat …）を *先に* SQLite の正規化した行に変える。エージェントはその構造化データしか見ない。
2. **書き込み時の引用検査。** すべての読み取りツールは、返した locator を *登録* する。検出結果 / 回答は、
   どのツールも返していない locator を引用していると、書き込み時に **拒否** される。
3. **独立した検証。** 最終工程で、すべての引用 locator をデータベースに対して再解決し、存在しないものに印を付ける。

以下のすべては、この 3 つの保証のために存在します。

---

## 2. 3 つの層

```
            ┌──────────────────────────────────────────────────────────────┐
            │  A. 解析 (決まった手順、LLM なし)                              │
 証拠     ─▶│     src/extraction/*  ─▶  case.db 内の正規化した行            │
  フォルダ   └──────────────────────────────────────────────────────────────┘
                                  │
            ┌─────────────────────▼────────────────────────────────────────┐
            │  B. 調査 (エージェントのループ、唯一の LLM 駆動の層)           │
            │     オーケストレーター ⇄ Case File ⇄ サブエージェント ⇄ ツール │
            └─────────────────────┬────────────────────────────────────────┘
                                  │
            ┌─────────────────────▼────────────────────────────────────────┐
            │  C. レポート (決まった手順、LLM なし)                          │
            │     台帳から Markdown/HTML を生成 + 引用を検証                 │
            └──────────────────────────────────────────────────────────────┘
```

LLM を呼ぶのは **層 B** だけです。層 A と C は普通の Python で、毎回まったく同じ出力を生みます。
`main.py :: cmd_investigate` が、ホストごとにこの 3 つを順に実行します。

---

## 3. Case File が中心の伝達路（`output/<case-id>/case.db`）

エージェント間の **直接のやり取りは存在しません。** オーケストレーターとすべてのサブエージェントは、1 つの
SQLite データベースだけを通じて通信します — 古典的な **ブラックボード方式** です。これがこのシステムについて
最も重要な構造上の事実です。すべての状態が SQLite に残るため、実行は **再開可能**（同じ `--case-id` で再実行）で、
かつ **べき等**（`meta.ingested=1` なら解析を飛ばす）です。

スキーマは `src/store/schema.sql` にあり、`src/store/case_db.py :: CaseDB` が包んでいます。以下の各テーブルと列を、
DC33 ホストの調査からの **実際の例の行** 付きで示します。

### locator（引用のためのハンドル）

**locator** は、読み取りツールが返し、検出結果 / 回答が引用する安定した文字列です。形式は
`"<source>:<relpath>:<record-key>"` で、`<source>` の接頭辞はその行の `source_artifact` に等しく、record-key は
source に依存します:

| source | record-key | locator の例 |
|--------|-----------|-----------------|
| `event_logs` | EVTX のレコード id | `event_logs:Evt/.../Security.evtx:269584` |
| `powershell_history` | 行番号 | `powershell_history:Psh/Users/<u>/.../ConsoleHost_history.txt:1` |
| `registry` | キーのパス | `registry:Reg/Config/SAM:SAM\Domains\Account\Users\Names\Administrator` |
| `amcache` | エントリ id | `amcache:Reg/.../Amcache.hve:1234` |
| `browser` | csv の行 | `browser:Brw/History.csv:42` |
| `usn` | USN 番号 | `usn:RawData/.../USNJrnl.csv:5916816` |
| `srum` | 行 id | `srum:Sys/.../SRUDB.dat:88` |
| `mft` *(必要時)* | `$MFT` のレコード番号 | `mft:RawData/C/$MFT:248126` |
| `memory` *(必要時)* | 結果の番号 | `memory:netscan:7` |
| `file` *(目録)* | — または `:<line>` | `file:Conn/CPorts.csv` · `file:Logs/run.log:88` |

### `events` — 正規化タイムライン（データベースの大部分）

解析したレコードごとに 1 行。`query_timeline` / `grep_artifact` が検索する対象です。

| 列 | 保持する内容 | 例 |
|--------|-------|---------|
| `id` | 自動採番の主キー | `34019` |
| `ts` | ISO-8601 のイベント時刻、証拠に時刻がなければ `""` | `2025-06-29T00:45:51.439092Z` |
| `source_artifact` | どの解析器が作ったか（= locator の接頭辞） | `powershell_history` |
| `host` | レコードが持つ場合はホスト名 | `namtws004.mtfin.local` |
| `user` | イベントに関わるユーザー/SID | `administrator.MTFIN`、`S-1-5-18` |
| `event_type` | 解析器の下位種別タグ | `ps_command`、`BITS:306`、`mft:file` |
| `summary` | 人 / エージェントが読める行（約 600 文字で頭打ち、`[+N more fields — get_raw_event]` で終わることがある） | `get-content 'C:\Program Files (x86)\ossec-agent\ossec.conf'` |
| `locator` | 安定した引用ハンドル（上記参照） | `powershell_history:Psh/Users/administrator.MTFIN/.../ConsoleHost_history.txt:1` |
| `raw` | JSON としての全項目（イベントログ/レジストリ）または生の行; `get_raw_event` を支える | `{"EventID":4720,"TargetSid":"S-1-5-...",...}` |

`idx_events_source` が `source_artifact`（最もよく使う絞り込み）に索引を張ります。

### `files` — **すべての** ファイルのメタデータ（解析できないバイナリも含む）

POINTER 回答と、`mft_lookup` / `read_file` のパス解決を支えます。

| 列 | 保持する内容 | 例 |
|--------|-------|---------|
| `path` (主キー) | 証拠の起点からの相対パス | `RawData/$UsnJrnl_$J.bin` |
| `artifact` | 所属する dir-code | `RawData` |
| `name` | ファイル名 | `$UsnJrnl_$J.bin` |
| `owner` | パス（`Users/<x>/`）から推定した所有者 | `gloria.bradley` |
| `size` | バイト数 | `39071552` |
| `mtime`/`ctime`/`atime` | ファイルシステムの MAC 時刻（ISO-8601） | `2025-07-02T01:17:35+00:00` |
| `is_text` | テキストとして読めるなら 1（内容を判定）→ `read_file` が動く; さもなければ POINTER のみ | `0` |

### `coverage` — バケット一覧（終了を決める）

| 列 | 保持する内容 | 例 |
|--------|-------|---------|
| `artifact` (主キー) | dir-code | `Arn` |
| `type` | 対応表からの証拠の種類 | `amcache_autoruns` |
| `parser` | 解析器モジュール名、または NULL（目録のみ） | `NULL` |
| `present` | このコレクションにフォルダがあれば 1 | `1` |
| `status` | `unexamined → triaged → analyzed`; どれも `unexamined` でなくなったら実行終了 | `analyzed` |

### `leads` — 作業の待ち行列（エンジン）

「リード」は、調査すべき 1 単位の作業を表します。

| 列 | 保持する内容 | 例 |
|--------|-------|---------|
| `id` (主キー) | 並び順の決め手 | `1` |
| `title` | 作業内容 | `Answer: A user on NAMTWS04 created a file they wanted to keep under wraps. …` |
| `reason` | 理由（エージェントが立てたリード用） | `""` |
| `source` | `question` \| `coverage` \| `agent` | `question` |
| `question_id` | `source=question` のとき設定 | `q870b206e` |
| `artifact` | `source=coverage` のときの対象バケット | `NULL` |
| `priority` | 大きいほど先（設問 70; カバレッジは各バケットの表 / ルーターから） | `70` |
| `depth` | エージェントが立てたリードの連鎖の深さ（`max_lead_depth` で頭打ち） | `0` |
| `status` | `open → in_progress → closed` | `closed` |
| `dedup_key` | `UNIQUE` — `source\|qid\|artifact\|title` — 同じリードの重複登録を防ぐ | `question\|q870b206e\|\|answer: a user on namtws04 …` |

### `findings` + `finding_evidence` — 台帳

| `findings` の列 | 保持する内容 | 例 |
|-------------------|-------|---------|
| `id` (主キー) | 検出結果の id | `1` |
| `title` | 短い見出し | `User hid file in deeply obfuscated directory structure` |
| `severity` | `info\|low\|medium\|high\|critical` | `medium` |
| `confidence` | `low\|medium\|high` | `high` |
| `attack_technique` | ATT&CK id（共有 locator との重複判定キー） | `T1564` |
| `description` | 自由記述 | `gloria.bradley created a deeply nested folder tree …` |
| `status` | 台帳上の状態 | `corroborated` |
| `created_at` | ISO-8601 | `2026-06-26T15:08:09.6…` |

`finding_evidence`: `finding_id` → (`locator`, `excerpt`)。例:
`(1, "mft:RawData/C/$MFT:248126", "\Users\gloria.bradley\…\DO NOT LOOK\…")`。

### `questions` / `answers` / `answer_evidence` / `answer_candidates`

`questions`: `id` = 正規化した本文の内容ハッシュ `q<sha1[:8]>` · `text` = 設問。
例: `("q79044b52", "What SID of the first account created by the compromised account…?")`。

| `answers` の列 | 保持する内容 | 例 |
|------------------|-------|---------|
| `id` (主キー) | 回答の id | `1` |
| `question_id` | `questions.id` への外部キー | `q870b206e` |
| `status` | `answered \| pointer \| unresolved` | `answered` |
| `answer` | 回答本文（該当時はそのままのトークン） | `C:\Users\gloria.bradley\…\DO NOT LOOK` |
| `confidence` | `low\|medium\|high` | `high` |
| `reasoning` | 根拠; unresolved の場合は **何を検索したか** | `User gloria.bradley created a deeply nested folder …` |
| `created_at` | ISO-8601 | `2026-06-26T15:08:09.6…` |
| `question_text` | 設問本文の控え → 設問一覧が変わっても回答が生き残る | `A user on NAMTWS04 created a file …` |

- `answer_evidence`: `answer_id` → (`locator`, `excerpt`) — **answered** 用。
- `answer_candidates`: `answer_id` → (`path`, `reason`) — **pointer** 用（path は `files` に存在必須）。
  例: `(7, "Brw/Downloads/proof.png", "screenshot likely shows the answer")`。

### `emitted_locators` — 引用の登録簿（でっち上げ防止）

いずれかのツールが返したすべての locator。検出結果 / 回答は、ここにある locator しか引用できません。

| 列 | 保持する内容 | 例 |
|--------|-------|---------|
| `locator` (主キー) | 返された locator | `event_logs:Evt/.../Microsoft-Windows-PowerShell%4Operational.evtx:191054` |
| `kind` | `event` \| `file` \| `file_line` | `event` |
| `detail` | 任意（例: `file_line` のファイルパス） | `""` |

### `meta` — case の状態

キー/値。`("ingested","1")` が完了した解析を表す（べき等な取り込み / 再開）。`meta` に加え、スキーマの
`IF NOT EXISTS` + `CaseDB._migrate`（例: `answers.question_text` 列の追加）により、古い `case.db` を開き直すとき
その場で更新できます。

---

## 4. 層 A — 決まった手順での解析（`src/extraction/`）

`ingest.py :: ingest()` は、読み取り専用の証拠の起点をたどって:

1. 対応表（`config/artifact_map*.yaml` — dir-code → (種類, 解析器) の橋渡し）から **バケット一覧
   (coverage manifest)** を作る。表にあるが存在しない code は「なし」と印を付ける。
2. **すべてのファイルを `files` に目録化** する（パス/所有者/サイズ/MAC 時刻）。`is_text` は内容の判定
   （`src/textutil.py`）で決めるので、素のテキストの `.dat` は読め、レジストリハイブはバイナリのまま。
3. 存在する解析可能なバケットに対して、使える各解析器を実行する。解析器（`psh, evtx, registry, browser, lnk,
   usn, srum`）は `case.add_event(...)` を通じて正規化した行を `events` に書き込み、それぞれに
   **安定した `locator`**（§3 参照）を付ける。

2 つの証拠は意図的に **一括解析しません**（大きすぎるため）: フル `$MFT` とメモリイメージ。これらは層 B の間に
遅れて調べられます（§6、必要時ツール参照）。

### 解析器の約束事（すべての解析器が守る）

各 `src/extraction/<x>.py` は 1 つの `parse(case, root, dir_code)` を公開し、同じ 5 つのルールに従います。
そのため互いに置き換え可能で、機能低下の仕方が予測できます:

1. **厳選せよ、丸ごと出すな。** トリアージのコレクションは大半がノイズです（DC の `Security.evtx` だけで
   約 17 万レコード、`$MFT` / USN ジャーナルは数十万ファイル）。解析器は *重要なものだけの許可リスト* — 選んだ
   チャンネル/ID/キー/イベント種別 — を出すので、タイムラインは干し草の山ではなく手がかりであり続けます。
   網羅性は必要時（`get_raw_event`、`mft_lookup`）に取り戻し、最初から抱え込みません。
2. **位置ではなく名前で読む。** CSV は `DictReader`、EVTX は `EventData Name=`、ESE/レジストリは列 / 値名で。
   新しい収集ツールが列を足したり並べ替えても *無視され、致命的にはなりません*。CSV の列参照は寛容な
   `_get(row, *candidates)`（大文字小文字を無視、最初の非空）を通すので、ツールごとの見出しのゆらぎを吸収します。
3. **要約 + 生データの全体。** すべての行は、短く読みやすい `summary` と、その根拠となる完全なレコードを
   `events.raw` に JSON で持ちます。要約が項目を省いたときは `[+N more fields — get_raw_event]` を付け、何も
   黙って失われません — エージェントは `get_raw_event` で完全なオブジェクトを引けます。
4. **行ごとの安定した locator**（引用ハンドル — §3）: `<source>:<relpath>:<record-key>`。
5. **うまく機能低下する。** バックエンドのライブラリの欠如（registry/lnk/srum/evtx）や入力の不在は、1 行のメモと
   ともに *そのバケットを飛ばします*。ファイルの目録があるので、エージェントはなお POINTER できます。

所有ユーザーは、どこでも同じ方法で取り出します — `…/Users/<user>/…` というパスの一部です。

### 各解析器が元データをどう読むか

**`psh` — PowerShell コンソール履歴**（`ConsoleHost_history.txt`、素のテキスト）。バケット内の `*history*` /
`*.txt` をたどり、**空でない行ごとに 1 イベント**（打鍵したコマンド）を出す。これらのファイルは時刻を持たない
ので、イベントは順序は付くが時刻はなし; `raw` はそのままの行。locator `powershell_history:<rel>:<lineno>`。

**`browser` — 履歴 & ダウンロード**（NirSoft *BrowsingHistoryView* / *BrowserDownloadsView* の CSV）。`utf-8-sig`
での `csv.DictReader`（BOM を除く）。`_classify()` が見出しから *履歴* か *ダウンロード* かを判定し、寛容な
`_get` で URL / タイトル / 訪問時刻 / ファイル名 / 保存先パス / 開始+終了時刻 を取り出す。ダウンロードのイベント
時刻は **終了時刻 (End Time)**（完了）で、なければ開始時刻に戻す — 「X をいつダウンロードしたか」は、開始時の
作成ではなく *完了* を意味する。ファイルあたり 5000 行で頭打ち。locator `browser:<rel>:<rownum>`。

**`usn` — USN 変更ジャーナル**（`USNJrnl.csv`、ExtractUSNJrnl の出力）。ジャーナルは巨大で大半がデータ書き込みの
騒音なので、これは **厳選したライフサイクル解析** です: *注目すべき拡張子*（実行ファイル、スクリプト、書庫、
文書、資格情報/ダンプ）の 作成 / 削除 / 名前変更 のレコードのみを、ファイルごとに重複除去し、騒音を除去
（`__PSScriptPolicyTest`、`mpcache-`、Office の `~$` ロック、検索インデクサの騒音）した上で、6000 で頭打ち。
USN はファイルの *名前* は持つがフォルダは持たない（フルパスの解決には `$MFT` が要る → `mft_lookup`）。
locator `usn:<rel>:<usn-number>`。

**`evtx` — Windows イベントログ**（`*.evtx`、バイナリ）。バックエンド: Rust ベースの `evtx`（pure-Python の
`python-evtx` に切り替わる。こちらははるかに遅く、大きなログを黙って切り詰めうる — 起動時の見張りが警告する）。
2 段の厳選: (a) **チャンネルの許可リスト** — `_CHANNELS` がファイル名の一部を「系統 + 注目 ID の集合」に対応させる。
先勝ち（例えば `…%4Security.evtx` は総称の `security.evtx` より先に SMB として解決）。`ids=None` は少量チャンネルの
全 ID を残す。(b) 残ったチャンネル内では、**許可した EventID**（`_SEC`/`_SYS`/`_PS`/…）だけが生き残る。レコード
ごと: `(record_id, timestamp, xml)` を順に回す → ElementTree で XML を解析 → `System` の項目（EventID、Computer、
TimeCreated、SID）と `EventData`/`UserData` の項目を取り出す。名前付きの `<Data Name=…>` は名前を保つ; **名前なし**
の `<Data>`（Application Error、MsiInstaller、SCM のような古い形式の発生源）は位置的に `Data1`、`Data2` … として
取り込む。要約は `_KEY_FIELDS`（最もトリアージに役立つ項目）を先頭に、続いて残りを並べる。チャンネルごとの
進捗表示が、長い走査中にその場で更新する。locator `event_logs:<rel>:<record_id>`。

**`registry` — ハイブ**（`SOFTWARE`/`SYSTEM`/`SAM`/`NTUSER.DAT`/`Amcache.hve`、バイナリ; バックエンド
python-registry）。`_hive_type()` が各ハイブをファイル名で振り分ける（SECURITY/UsrClass は飛ばす）。EVTX と
同様、丸ごとの取り出しではなく **重要キーの許可リスト** です: Run/RunOnce の永続化、Uninstall → インストール済み
ソフトウェア、`CurrentVersion` → OS ビルド/所有者/導入日、`NetworkList` → ネットワークプロファイル、サービス
（`ImagePath` が「怪しい場所」の判定に引っかかり、かつ標準のシステム接頭辞の下にないときだけ表に出す）、
デバイス列挙（`Enum\USBSTOR` + `Enum\SCSI` のディスク / 仮想ディスクの型番 — EBS 形式の `Prod_` の型番はキー名に
入る）、加えてアカウント / ユーザー操作のキー。`raw` は、出したサブキーの下の *すべての* 値を持つ。**`Amcache.hve`**
も同じモジュールで解析されるが、別の `source="amcache"`（SHA-1 ハッシュ付きのプログラム実行の証拠）として出す。
locator `registry:<rel>:<keypath>\<value-or-subkey>`（amcache の行は `amcache:` 接頭辞を使う）。

**`lnk` — ショートカット**（`*.lnk`、特に `Recent/` の下; バックエンド LnkParse3）。ショートカットごとに 1 イベント
で、対象の **フルパス、MAC 時刻、サイズ、ボリューム種別**（ローカル / ネットワーク / リムーバブル）を取り出す —
つまりユーザーが特定のファイル / 共有を開いた証拠。`raw` は完全な解析済みレコード。locator `lnk:<rel>`。

**`srum` — System Resource Usage Monitor**（`SRUDB.dat`、ESE データベース; バックエンド dissect.esedb）。GUID で
2 つの重要テーブルを解析する: *Application Resource Usage* — **アプリごとに集計**（生テーブルは約 1 時間ごとの
数千行なので、前面表示の時間 + ディスク I/O のアプリ単位の合計が手がかり） — と *Network Connectivity*
（レコードごとに 1 イベント）。アプリ/ユーザー id は `SruDbIdMapTable` で解決; OLE オートメーションの `TimeStamp`
は ISO に変換される。locator `srum:<rel>:app:<i>` / `srum:<rel>:net:<id>`。

**必要時（一括解析しない）: `$MFT` とメモリイメージ。** どちらも最初に丸ごと展開するには大きすぎる。`mft_lookup`
はファイル名/USN の参照を `$MFT` に対してフルパス / MAC 時刻に解決し、`vol_run` はメモリイメージに対して
Volatility3 のプラグインを実行する — それぞれ返した行だけを `events` に展開する。§6、必要時ツール参照。

---

## 5. 層 B — エージェント構成

3 つの役割が、すべて Case File を通じて協調します:

```
                         ┌───────────────────────────────────────────┐
                         │  オーケストレーター (src/agents/orchestrator.py) │
                         │  リードの待ち行列エンジン                    │
                         └───────────────────────────────────────────┘
   (任意) 並べ替え           │  優先度が最も高いリードを取り出す
   ルーター ──────────────────▶│  in_progress にする
   src/agents/router.py       │  このリード用にサブエージェントを起動
                              ▼
                         ┌───────────────────────────────────────────┐
     新しいリードを立てる  │  サブエージェント (src/agents/subagent.py)   │
      ◀──────────────────┤  1 リード → 結論、自分専用の文脈で           │
                         │  データを読み、検出結果/回答を書く           │
                         └───────────────────────────────────────────┘
                              │  ツール経由 (src/tools/registry.py)
                              ▼
                         ┌───────────────────────────────────────────┐
                         │  CASE FILE (case.db) — 共有の伝達路          │
                         └───────────────────────────────────────────┘
```

### 5a. オーケストレーター — `src/agents/orchestrator.py`

小さく、決まった手順で動く **待ち行列エンジン**（それ自身は LLM を呼びません）:

1. `reset_in_progress_leads()` — 直前の停止で途中終了したものを開き直す（再開）。
2. `seed()` — リードを積む:
   - CTF の設問ごとに **設問リード** 1 つ（`priority 70`）、
   - 存在するバケットごとに **カバレッジリード** 1 つ（優先度は各バケットの厳選済み表、またはルーターからの
     設問に応じた上書き; 5c 参照）。
3. ループ: `next_lead()`（最高の `priority`、次に `id`）→ `in_progress` にする → `subagent.run(...)` →
   `closed` にする → カバレッジリードなら、そのバケットを `analyzed` にする。待ち行列が尽きるか、安全上の上限
   （`max_total_leads + 50`）に達するまで繰り返す。

オーケストレーターとサブエージェントは、互いを直接呼びません。もっと作業をしたいサブエージェントは `file_lead`
ツールを呼び、`agent` 由来の行を `leads` に挿入します; オーケストレーターは後の周回でそれを拾います。
**協調は待ち行列です。**

### 5b. サブエージェント — `src/agents/subagent.py`

1 つの **汎用** サブエージェントを、リードごとに **まっさらな LLM の文脈** で 1 回実行します。生のツール出力を
手元で「消化」するので、オーケストレーターがそれを抱える必要がなく — 各文脈が小さく保たれます。

- **専門化はコードではなくプレイブックで。** カバレッジリードでは、サブエージェントはまず
  `kb_read('playbooks/<bucket>.md')` するよう指示されます（`_PLAYBOOKS` の dir-code→文書の対応）。同じコードが
  PowerShell、レジストリ、メモリを調べます — 領域知識はプレイブックが供給します。
- **ループ**（最大 `budgets.max_subagent_steps`、既定 20）:
  ```
  history = [task]
  for step in 1..max:
      resp = llm.complete("subagent", system, history, tools=TOOL_SCHEMAS)
      history.append(resp.assistant_turn)
      if resp.stop_reason != "tool_use": break
      for call in resp.tool_calls:
          out, is_err = dispatch(ctx, call.name, call.input)   # ツールを実行
          history.append(tool_result)
  _conclude_unresolved(...)   # 安全網
  ```
- **システムプロンプト**（`_RULES` + その case の設問一覧）: 答えるか指し示すか、決して推測しない; すべての
  主張に実在の locator を引用; そのままのトークン; `find_flags` を早めに呼ぶ; プレイブックを読む; 記録前に
  `list_findings`（重複回避）; 行動したら止まる。
- **エージェント間の把握:** サブエージェントは `list_findings` を呼んで（台帳を読んで）先行サブエージェントの
  作業を知る — これも直接のやり取りではなくブラックボード経由。
- **決して空白にしない:** `_conclude_unresolved()` は、回答を記録せず終わった *設問* リードが、黙って何も生まない
  代わりに正直な `unresolved`（何を検索したか付き）を書くことを保証する — 抜けが停止と区別できる。
- **粘り強さ:** LLM/API の例外は、今のリードだけを中断する（記録に残る）。実行全体は落ちない。

### 5c. ルーター — `src/agents/router.py`（任意）

存在するバケットを、設問への関連度で並べる 1 回の LLM 呼び出し（役割 `orchestrator`）。dir-code の JSON 配列を
返し、次を動かします:
- **リードの優先度**（既定の実行がどのバケットを先に調べるか — カバレッジは依然として保証される）、および
- `--relevant-only` の下での **バケットの選択**（並べられたバケットだけを調べる）。

設問がなく `--relevant-only` もない場合、ルーターは飛ばされ、オーケストレーターの固定の各バケット優先度が
使われます。

---

## 6. ツールの層（`src/tools/registry.py`）

ツールは、サブエージェントがデータに触れる *唯一* の手段です。`TOOL_SCHEMAS` がモデルに送られ、
`dispatch(ctx, name, input)` が処理を実行して `(text, is_error)` を返します。結果の中身は 12 KB で頭打ちの
JSON です。すべての **読み取り** ツールは、返したものに対して `case.emit_locator()` を呼びます（引用可能に
なる）; すべての **書き込み** ツールは引用を検査します。処理中の例外は捕まえられ、ツールエラーの文字列として
モデルに渡されます — 実行が落ちることはありません。

| 分類 | ツール |
|----------|-------|
| **読み取り / 検索** | `kb_read`、`query_timeline`、`grep_artifact`、`find_flags`、`list_files`、`read_file`、`get_raw_event` |
| **必要時（遅い、高コスト）** | `mft_lookup`、`vol_run` |
| **書き込み / 制御** | `list_findings`、`record_finding`、`answer_question`、`file_lead`、`mark_examined` |

### 読み取り / 検索

**`kb_read(doc)`** → プレイブック / 参考のテキスト（≤12 KB）。`doc` は `knowledge_base/` からの相対、例
`"playbooks/registry.md"`。パスの脱出を防ぐ。locator なし。

**`query_timeline(source?, user?, contains?, limit=100)`** → `{count, rows:[{locator, user, ts, text}],
truncated?, total_matched?}`。`events` に対する SQL の絞り込み（`source_artifact=`、`user LIKE`、
`summary LIKE %contains%`）、`ORDER BY id`、**上限 500**。オフセットなし — 絞り込みで狭める。行ごとに locator を
出す。主力の「必要なものだけ取り出す」ツール。

**`grep_artifact(pattern, source?, limit=100)`** → `{count, rows:[{locator, user, text}], truncated?,
total_matched?}`。`events.summary` に対する大文字小文字を無視する **正規表現**（任意で 1 つの source）。
`total_matched` のために全一致を数える; **上限 500**。行ごとに出す。

**`find_flags()`** → `{count, flags:[{flag, locator}]}`。全 `events`（summary+raw）**および** 読めるテキスト
ファイルに対する、CTF マーカー `btv{…}/flag{…}/FL4G={…}/key{…}/ctf{…}`（`_FLAG_RX`）の決まった手順での走査;
値で重複除去、上限 100。フラグごとに最初の locator を出す。LLM なし。早めに呼ぶ。

**`list_files(query?, artifact?, limit=50)`** → `{count, files:[{locator:"file:<path>", path, owner, size,
mtime, ctime, readable}], truncated?, total_matched?}`。`files` の目録を検索（`path LIKE`、`artifact=`）、
**上限 200**。`file:` の locator を出す — POINTER する候補ファイルの見つけ方。

**`read_file(path, offset=0, limit=200)`** → `{path, total_lines, rows:[{locator:"file:<path>:<line>", line,
text}]}`。**テキスト** ファイルを切り出す（BOM を考慮して復号）。**上限 500** 行。バイナリは断る; *解析済み* の
バケット（Evt/Reg/Brw/Lnk/RawData/Sys）内のファイルには、POINTER を勧める代わりに `query_timeline` /
`get_raw_event` への案内を返す。`file_line` の locator を出す。

**`get_raw_event(locator)`** → `{locator, fields}`（`events.raw` からの完全な JSON 項目）、または追加項目が
なければ `{locator, summary}`。要約が `[+N more fields …]` で終わるときに使う。locator の照合は **バックスラッシュに
寛容**（`_resolve_locator` が過剰にエスケープされたレジストリの `\\` をまとめる）なので、実在の引用が書式の癖で
断られない。（正規の）locator を出す。

### 必要時（遅い、高コスト — `events` に展開する）

これらは、一括解析するには大きすぎる証拠を調べ、その結果を引用可能な locator 付きで *同じ* `events` テーブルに
書き込むので、後段の処理は他の行と同じように扱えます。だから **「メモリのエージェント」は別プロセスでは
ありません** — `playbooks/memory.md` に向けられ `vol_run` を呼ぶ、汎用サブエージェントです。

**`mft_lookup(filename, limit=20)`** → `{query, count, results:[{locator:"mft:…", path, deleted, size, si_times,
fn_times}]}`。名前（部分一致、大文字小文字を無視）を `$MFT` に対して解決 — フルパス + `$SI/$FN` の MAC 時刻
（タイムスタンプ改ざんの確認）。最初の呼び出しでプロセス内の索引を作る（数秒）; **上限 100**。`source="mft"` の
行を展開し、その locator を出す。

**`vol_run(plugin, contains?, pid?)`** → Volatility3 の結果を、引用可能な `source="memory"` の行として。`MemDump`
イメージに対して **1 つ** のプラグイン（例: `windows.netscan.NetScan`、`windows.pslist`、`windows.cmdline`、
`windows.malfind`）を実行; `contains` が行を絞り込み、`pid` がプロセスに限定する。`budgets["memory"]`（vol_cmd、
cache_dir）を読み、(イメージ, プラグイン, 引数) ごとに `output/_memcache` にディスクキャッシュする。Volatility は
専用の仮想環境（`.venv-vol`）で動き、ツールはそこを呼び出す。遅い（数十秒〜数分）。メモリが無効 / 不在なら
その旨を言う → イメージを POINTER。このビルドに hashdump/lsadump プラグインはなし。

### 書き込み / 制御（検査あり）

**`list_findings()`** → `{count, findings:[{id, severity, technique, title}]}`。重複ではなく既存の検出結果に
追記するため、記録前に台帳を読む。

**`record_finding(title, severity, evidence[], confidence?, attack_technique?, description?)`** →
`{recorded_finding: id}` または `{merged_into_finding: id}`。`evidence` は `[{locator, excerpt?}]` で **空でない**
こと、かつ **すべての locator が `emitted_locators` にあること** が必須、さもなければ拒否。**同じ
`attack_technique` かつ共有 locator** を持つ検出結果があれば、新しい裏付けはそこに **統合** される（重複なし）。

**`answer_question(question_id, status, …)`** は設問を解決する; `status` ∈:
- `answered` → `answer` + 空でない検査済みの `evidence` が必要（同じ emitted-locator の検査）。
- `pointer` → `candidate_files:[{path, reason?}]` が必要; **各 path は `files` に存在必須**。
- `unresolved` → `reasoning`（何を検索したか）が必要。
任意で `confidence`。重複回答（同じ値）は飛ばされる; **異なる** 候補の回答は、アナリスト向けに並べて残される。

**`file_lead(title, reason?)`** → オーケストレーター用に新しい `source="agent"` のリードを積む（自分で追わない）。
`allow_expansion`、`max_total_leads`、`max_lead_depth`、`dedup_key`（すでに積まれていれば "duplicate" を返す）、
そして **設問ごとの上限**（`max_leads_per_question`）を守る: 発端の設問 id がすべての後続リードに付いて回るので、
答えの出ない 1 問が際限なく広がることはできない — 上限に達すると `file_lead` は断られ、エージェントは結論を
出さねばならない。

**`mark_examined(artifact)`** → そのバケットの `coverage.status="analyzed"` を設定する。実行は、存在するどの
バケットも `unexamined` でなくなったときにだけ終わる。

### 引用強制のしくみ（でっち上げ防止の中核）

```
読み取りツールが行を返す ──▶ 各 locator が case.emit_locator() で記録される
                                       │
                                       ▼  (emitted_locators テーブル)
record_finding / answer_question ──▶ _check_evidence(): emitted_locators に
                                       ない引用 locator を拒否
                                       │
                                       ▼  (保存された検出結果/回答の裏付け)
層 C の検証工程 ────────────────────▶ すべての引用 locator を events/files に対して
                                       再解決; 存在しないものに印を付ける
```

つまりサブエージェントは裏付けをでっち上げられません: この実行でツールが実際に返したものしか引用できず、
レポートが独立にそれを再確認します。

### 横断的なツールのルール

- **切り詰めは明示的:** 上限のある読み取りツールは `truncated` / `total_matched` を返すので、一部が全体と
  取り違えられない。
- **エラーは実行を落とさない:** どの処理の例外も、モデルが見て対応するツールエラーの文字列になる。

---

## 7. LLM の層（`src/llm/`）

- **`LLMClient.complete(role, system, messages, tools)`** は **役割** を、設定済みのプロバイダ+モデル
  （`config/config.yaml :: models`）に振り分ける。役割: `subagent`（調査のループ）と `orchestrator`（ルーターの
  並べ替え）が実際に LLM を呼ぶ; `report` / `verifier` は設定されているが作業は決まった手順。バックエンドは
  遅延読み込みなので、使うプロバイダの SDK だけが必要。
- **プロバイダ:** Anthropic（既定、最もテスト済み）、OpenAI、Gemini — `src/llm/backends/`。
- **Anthropic バックエンド**（`anthropic_backend.py`）: ストリーミング、**適応的な思考（adaptive thinking）** +
  役割ごとの **effort**、そして 3 つの区切りを持つ **プロンプトキャッシュ** — ツール定義、システムプロンプト、
  そして最後のメッセージへの動く区切り — により、25 ステップのツールループの（大きく繰り返される）前半部分が、
  毎回課金される代わりにキャッシュから読まれる。
- assistant のターンは生のプロバイダ内容として保存されるので、思考ブロックの署名がツールループを生き延びる。

---

## 8. 層 C — レポート + 検証（`src/report/`）

決まった手順、LLM なし。`generator.py` は **台帳/回答/カバレッジのみ** から Markdown を生成し（会話履歴は
決して使わない）、`verifier.py :: resolves()` はすべての引用 locator を `events`/`files` に対して再確認し、
失敗を `⚠️UNVERIFIED` と印を付ける。`report_html.py`（`scripts/` にあり、`main.py` が再利用）が、同じ `case.db`
から自己完結の対話的ダッシュボードを作る。

---

## 9. 1 ホストの上: プロセス単位の取りまとめ

上のエージェント構成は **ホストごと**（ホストごとに 1 つの `case.db`）です。複数ホストの作業は、上位の
エージェントではなく、素朴なプロセスの並列です:

- **`run_hosts.py`** — N ホストの `main.py investigate` を別々のプロセスとして実行し（`ThreadPoolExecutor`、
  `--jobs` で上限）、各ホストのタグ付き出力をコンソールに流す。各子プロセスの `main.py` が自分の **時刻付き**
  `output/<host>/run.log` を書く（ログは調査プロセスが持つので、単一ホスト実行でも 1 つ得られる）。その後、
  統合ビューを自動で作る。
- **`scripts/aggregate.py`** — 各ホストの `case.db` を読み、統合回答シート（対応表 + 設問ごとの最良回答）を書く。
- **`scripts/report_html.py`** — ホスト横断（または単一ホスト）の対話的ダッシュボード。

現時点で **ホスト横断で *調査する* エージェントはありません** — ホストは個別に調べ、結果は後から統合します
（和集合/集約の工程）。ホストをまたいでまとめて考える単一エージェントが、今後の課題です。

---

## 10. 不変条件と保証（正直さと終了を保つもの）

- **引用のない断言なし** — 構造として（出す→検査→検証）、§6。
- **終了と有界コスト** — カバレッジリードがすべてのバケットを `analyzed` に強制する; `dedup_key` が同じリードの
  重複登録を防ぐ; `depth`/`max_lead_depth` がエージェントの立てたリードの連鎖を頭打ちにする;
  `max_leads_per_question` が 1 つの（答えが出ないかもしれない）設問がどこまで広がれるかを頭打ちにする;
  `max_subagent_steps` が各リードを頭打ちにする; 全体の安全上の上限が総リード数を有界にする; そして
  `max_host_minutes` が、ホストを止めて途中までのレポートを書く実行時間の上限。
- **決して空白なし** — 設問リードは必ず answered/pointer/unresolved で終わる。
- **再開可能でべき等** — 永続的な SQLite の状態; `meta.ingested` が再解析を飛ばす; `reset_in_progress_leads` が
  中断した作業をやり直す; 設問は内容ハッシュ（`_qid`）されるので変えていないものは回答を保ち、回答は
  `question_text` を控えるので、後の設問一覧の変更を生き延びる。
- **うまい機能低下** — 解析器の欠如、バケットの不在、メモリ環境の無効化はいずれも、エラーではなく
  POINTER / カバレッジのみに機能低下する。

---

## 11. 端から端までの流れ（1 ホスト、設問あり）

```
main.py cmd_investigate
 ├─ ingest()                         # 層 A: 解析 → events/files/coverage
 ├─ router.rank_buckets()            # (設問があれば) LLM がバケットを並べる
 ├─ orchestrator.run()               # 層 B
 │   ├─ リードを積む (設問 + カバレッジ)
 │   └─ while 待ち行列が空でない:
 │        lead = next_lead()         # 優先度順
 │        subagent.run(lead)         # まっさらな文脈
 │          ├─ kb_read プレイブック
 │          ├─ query_timeline / grep_artifact / get_raw_event / read_file / mft_lookup / vol_run
 │          │    └─ 各読み取り → emit_locator()      # 引用の登録簿
 │          ├─ list_findings (重複回避)
 │          ├─ record_finding / answer_question       # 引用がなければ拒否
 │          ├─ file_lead (→ 待ち行列へ戻す)
 │          └─ mark_examined (カバレッジリード)
 ├─ write_report() + verify           # 層 C: Markdown + 引用の検査
 └─ report_html.py                    # 対話的ダッシュボード
```

---

## 12. コードのどこを見るか

| 関心事 | ファイル |
|---------|------|
| 工程の取りまとめ / CLI | `main.py` |
| 解析 + 目録化 | `src/extraction/ingest.py`、`src/extraction/*.py`、`src/textutil.py` |
| Case File（スキーマ + アクセサ） | `src/store/schema.sql`、`src/store/case_db.py` |
| リードの待ち行列エンジン | `src/agents/orchestrator.py` |
| 汎用サブエージェント | `src/agents/subagent.py` |
| バケットの並べ替え | `src/agents/router.py` |
| ツール + dispatch + 引用の強制 | `src/tools/registry.py` |
| LLM の振り分け / キャッシュ / プロバイダ | `src/llm/client.py`、`src/llm/backends/*` |
| レポート + 検証 | `src/report/generator.py`、`src/report/verifier.py` |
| エージェントの領域知識 | `knowledge_base/playbooks/*.md`、`knowledge_base/tool_cookbook.md` |
| 複数ホスト | `run_hosts.py`、`scripts/aggregate.py`、`scripts/report_html.py` |
