# CTF 当日プレイブック

時間制限のあるライブ CTF で **forensic-investigator** を使うための実践的な手順書です。本ツールは、ホストの
**ディスク + メモリ** に関する設問で大きく戦力を底上げしてくれます（引用付きで、hallucination なし）。フラグの
提出、POINTER / UNRESOLVED の項目、そしてツールがカバーしないカテゴリは、自分で対応します。

---

## TL;DR — コマンド早見表

```bash
# (一度だけ) マシンをセットアップする
python install.py                       # 本体 + Volatility メモリ環境
#   その後 ANTHROPIC_API_KEY を .env に貼り付ける

# (ターミナルを開くたびに) 本体用の venv を有効化する
.venv\Scripts\Activate.ps1              # Windows  (POSIX: source .venv/bin/activate)

# (コレクションごとに) 課金する前に、まずフォルダ構成を確認する
python main.py check "<FORENSICS>/ACQ-IR-<host>-<date>"
#   stock AChoirX の場合は追加する:  --artifact-map config/artifact_map.stock.yaml

# 全ホストを一度だけ解析する (高速・AI なし)、4 並列で
python run_hosts.py "<FORENSICS>/ACQ-IR-*" --ingest-only --jobs 4

# 設問に対して全ホストを調査する (解析結果を再利用)、3 並列で
python run_hosts.py "<FORENSICS>/ACQ-IR-*" --questions questions.txt --relevant-only --jobs 3

# 結果を読む
#   output/_combined/report.html    (ブラウザで開く: 全ホストを検索・絞り込み・並べ替え)
#   output/_combined/answer_sheet.md (対応表: どのホストがどの設問に答えたか)
#   output/<host>/report.md          (1 ホスト分の回答シート + 検出結果)
#   output/<host>/run.log            (そのホストのコンソール出力、時刻付き — 実行ごとに 1 つ出力される)
```

`<FORENSICS>` は `ACQ-IR-*` のホストコレクションを含むフォルダです。

> 上の一括実行は **最も簡単** ですが **最も高コスト** です（全設問 × 全ホスト）。
> 設問がどのホストのものか分かる場合は、§5 / §8 でより安い *振り分けてから対象を絞る* 流れを説明します。
> ツールが初めての場合は、まず README の Quick start を読んでからここに戻ってください。

---

## 0. 当日より前に（準備 — 時間制限下ではやらないこと）

- [ ] 使うマシンで **インストールと動作確認** をする（§1 参照）。既知の正常なコレクションに対して
      `python main.py check` を実行し、`COMPATIBLE` を確認する。
- [ ] **API クレジットを補充する。** 課金される AI の層は *2 つ* あります。ツール自身の呼び出し **と**、
      Claude を操作するセッションの両方です。クレジット切れは過去に何度も痛い目を見ています。
- [ ] 昨年のデータ（DC33）で全体の流れを **リハーサル** し、手順を体に覚えさせる。
- [ ] メモリ系の設問が予想されるなら **メモリ解析が動くこと** を確認する: `.venv-vol/Scripts/vol --help`。
- [ ] マシンは **電源につなぎ、蓋を開けたまま** にする（自動スリープは自動で防止されますが、蓋を閉じる操作は
      防げません）。

---

## 1. 新しいマシンへのインストール

```bash
git clone <repo-url> && cd forensic-investigator
python install.py            # .venv + .venv-vol を作成し、依存パッケージを入れ、.env を用意する
#   --no-memory  でメモリ解析 (Volatility) を省略できる（不要なとき）
# install.py が .env を作成してくれる — 開いて設定する: ANTHROPIC_API_KEY=sk-ant-...

# 本体用の venv を有効化する（ツールを実行する前に、新しいターミナルごとに毎回行う）:
.venv\Scripts\Activate.ps1    # Windows (PowerShell)
source .venv/bin/activate     # macOS / Linux
```

> 以下の `python main.py ...` / `python run_hosts.py ...` コマンドはすべて、そのシェルで `.venv` が
> **有効化済み** であることを前提とします。（`.venv-vol` の有効化は不要 — ツールが自分でそちらを呼び出します。）
> 新しいターミナルを開いたら、もう一度有効化してください。

動作確認:
```bash
python main.py check "<FORENSICS>/ACQ-IR-<any-host>"     # COMPATIBLE と表示されるはず
```

必要環境: Python 3.10 以降（3.14 でも動作）、インターネット接続（初回のメモリ解析でシンボルをダウンロード）、
そしてクレジットのある API キー。Volatility 用の venv を除き、すべて pure-Python です。

---

## 2. イベント開始時 — 状況を把握する

1. **コレクション**（`ACQ-IR-*` フォルダ）と **設問リスト** を入手する。
2. 設問を `questions.txt` に **1 行 1 問** で入れる。設問が「問題」/ カテゴリごとにまとまっている場合は、
   **まとまりを保つ** — グループの間に空行を入れる（これで後から、ホストをカテゴリ全体へ広げられます）。
3. 本格実行の前に、1 ホストで **構成を確認** する:
   ```bash
   python main.py check "<FORENSICS>/ACQ-IR-<host>-<date>"
   ```
   - `COMPATIBLE` → 続行。
   - 未知の dir-code / `PARTIAL` → 別の収集ツールです。まず
     `--artifact-map config/artifact_map.stock.yaml` を試す。それでも合わなければ、その YAML をコピーし、
     `check` が挙げた code に合わせて名前を変え、`--artifact-map` で新しい対応表をすべての箇所に渡す。

---

## 3. 全ホストを一度だけ解析する（そして再利用する）

解析は遅い CPU 処理です。**ホストごとに一度だけ行い、`case.db` を再利用します。**

```bash
python run_hosts.py "<FORENSICS>/ACQ-IR-*" --ingest-only --jobs 4
```
- 全ホストの `output/<host>/case.db` を作る（AI なし、コストなし）。
- 各ホストの case-id はそのフォルダ名なので、**調査ステップはこの解析結果を自動で再利用** します
  （解析済みだと気づき、そのまま調査に進みます）。
- 構成の都合で必要なら `--artifact-map config/artifact_map.stock.yaml` を追加する。

---

## 4. どの設問がどのホストのものかを特定する

設問がどのホストのものか、最初から分かることは稀です。次の手がかりを使います（安い順 → 強い順）:

**a) 設問がホスト名を含む。** 多くはそうです（`On namtws003,…`、`NAMTWS04 …`、`workstation #1`）。
抜き出す:
```bash
grep -niE "namtws[0-9]+|namtdc[0-9]+|namtsh[0-9]+|workstation ?#?[0-9]" questions.txt
```

**b) 内容の一致（解析後）。** ホスト名のない設問は、設問中の特徴的な語（ユーザー名、ファイル名、IP、ツール名）で
各ホストの解析済みデータを検索します。ヒットが最も多いホストがそれです。同梱の **`scripts/search.py`** を使う:
```bash
python scripts/search.py olivia.parker        # -> ホストをヒット数で並べる; 最上位が持ち主
python scripts/search.py 13.58.222.12         # IP、ファイル名、ツール名などでも動く
# 複数キーワード: AND (既定) = 1 つの項目 (行) がすべての語を含むこと; --any = OR:
python scripts/search.py olivia.parker 13.58.222.12     # 両方を結びつける正確なイベント/ファイル
python scripts/search.py olivia.parker mimikatz --show  # --show で一致した行 + locator を表示
python scripts/search.py --any AdFind SharpHound BloodHound   # いずれかを含むホストをヒット数で並べる
#   既定はホストごとの件数 + バケット別の内訳 (event_logs / browser / file:Reg …) を表示;
#   複数語はクォートで囲む; case.db が ./output/<host>/ 配下にない場合は --root DIR / --glob 'PATTERN'
```

**c) 回答の裏付け（実行後）。** 設問に *答えた* ホストが、定義上その設問のホストです — 答えはそのホストの
`case.db` にあります。**`scripts/whoanswered.py`** を使う:
```bash
python scripts/whoanswered.py                 # host | question -> answer  (ANSWERED のみ)
python scripts/whoanswered.py --question kerberos   # 一致する設問だけに絞る
python scripts/whoanswered.py --status any    # POINTER / UNRESOLVED も表示
```

**d) カテゴリ単位で広げる（経験則）。** ある問題 / カテゴリの中の 1 問がホスト X に紐づいたら（上のどの手がかりでも
よい）、**そのまとまりの残り** も X に割り当てます。

---

## 5. 調査を実行する

有効なやり方は 2 つ:

**対象を絞る（最も安い）** — §4 でホスト→設問の対応が得られたら、ホストごとに小さな `q_<host>.txt` を作り、
そのホストの設問だけを実行する:
```bash
python main.py investigate "<FORENSICS>/ACQ-IR-<host>-<date>" --case-id ACQ-IR-<host>-<date> \
    --questions q_<host>.txt --relevant-only
```

**広範に（最も簡単 — 設問の持ち主が分からないときに使う）** — 全設問を全ホストで実行する。*どれか* 1 台が
答えれば設問は解決です（和集合）。無駄は多いですが手間がかからず、**設問をホストへ振り分ける必要がありません**:
```bash
python run_hosts.py "<FORENSICS>/ACQ-IR-*" --questions questions.txt --relevant-only --jobs 3
```
完了すると、全ホストを 1 ファイルにまとめた **統合回答シートを自動生成** します — 持ち主を探すために
11 個のレポートを開かずに済みます:
```
output/_combined/answer_sheet.md   # 対応表 (設問 -> ホスト) + 設問ごとの最良回答
```
いつでも作り直せます（読み取り専用・無料）: `python scripts/aggregate.py`。`--relevant-only` でコストを
抑えます（各ホストは、自分のデータが関連しそうな設問だけを調べます）。

コツ: 1 ホストの全設問は **1 回** の実行にまとめる（1 実行 1 設問にしない）。`--relevant-only` や
`--only <buckets>` で範囲を絞る。既定モデルは Sonnet（安い）。難問の最終的な高精度パスには、
`config/config.yaml` で `subagent` を `claude-opus-4-8` に上げる。

---

## 6. 確認、フラグ、そして「外した→直す」ループ

- **複数ホストの実行？** ブラウザで **`output/_combined/report.html`** を開く — 全ホストの
  Answers / Findings / Coverage を横断して検索・並べ替え・絞り込みできるダッシュボードです（行をクリックすると
  引用付きの裏付けを表示）。または対応表（設問 → どのホストが答えたか）として
  **`output/_combined/answer_sheet.md`** を読む。いずれの場合も、詳細はホストの `output/<host>/report.md` へ
  掘り下げる。単一ホストなら、その `report.md` を開くだけ（ANSWERED / POINTER / UNRESOLVED）。
  （ダッシュボードはいつでも作り直せる: `python scripts/report_html.py --open`。）
- **きれいに当たったものを提出する。** エージェントは `find_flags`（仕込まれた `btv{}` / `FL4G={}` マーカー）を
  自動で実行し、ファイル名 / コマンドを **そのまま** 回答するので、それらはそのまま提出できるはずです。
- **POINTER**（読めなかったファイルを候補として挙げている — 見に行く）と **UNRESOLVED**（何を検索したかを
  記録している）の項目は手作業で処理する。
- **外した → 直す → 再実行:** 手作業で 1 問解けたら *それをツールに教え込んで* そのホストを再実行する:
  - 答えが、取り込んでいない特定のイベント ID だった → `src/extraction/evtx.py` の `_SEC` / `_CHANNELS` に追加
  - 振り分け / どこを見るべきかの抜け → 該当する `knowledge_base/playbooks/*.md` に 1 行足す
  - 構成 / dir-code の問題 → 対応表 (artifact map) を編集
  再実行は解析結果を再利用するので高速です。

---

## 7. ツールが **やらない** こと（自分で対応する）

BTV 系 CTF のかなりの割合は、ホストコレクションの **外側** にあります。ツールはこれらを POINTER にするか、
そもそも到達できません — 手作業でやります:
- 脅威インテリジェンス / VirusTotal / OSINT の調査、画像 / スクリーンショットの雑学
- Web アプリ / API の攻撃ログ、メール / フィッシングのヘッダー、Wazuh のダッシュボード
- パスワードクラック、外部サービス系の設問

ホストの証拠に関する設問はツールに高速・引用付きで一気に片付けさせ、自分の時間はこれらに使いましょう。

---

## 8. コストと速度の規律

**最大のコスト要因は広範モード** です（全設問 × 全ホスト = およそ 11 倍の作業量）。統合シート / ダッシュボードは
結果を安く *読む* ためのもので、すべてをどこでも調べる理由ではありません。**振り分けてから対象を絞る** を
優先します:

```bash
# 1. 全ホストを一度だけ解析する — 無料、AI なし:
python run_hosts.py "<FORENSICS>/ACQ-IR-*" --ingest-only --jobs 4
# 2. 各設問をそのホストへ振り分ける (§4): まず本文中のホスト名、次に内容の一致:
python scripts/search.py <distinctive-term>          # ユーザー名 / IP / ファイル名 / ツール
# 3. 各ホストを、そのホスト自身の設問だけに対して調べる (最も安く、かつ正確な道):
python main.py investigate "<FORENSICS>/ACQ-IR-<host>-<date>" --case-id ACQ-IR-<host>-<date> \
    --questions q_<host>.txt --relevant-only
# 4. しつこく残ったものだけ、広範な一括実行に戻す (または Opus に上げる)。
```

これで広範モードに比べコストが最大およそ 11 倍下がり、精度の低下はほとんどありません — ほとんどのホストは、
ほとんどの設問について手がかりを持たないからです。他の手立て:

- **プロンプトキャッシュは自動**（system + tools + 履歴がキャッシュされる） — 操作は不要で、毎回の実行を
  安くします。解析結果も実行間で再利用されるので、追加の設問は安上がりです。
- **一度解析して再利用** する `case.db`（§3）。追加の設問のために解析し直さないこと。
- ホストごとに設問を **まとめる**。1 ホスト 1 設問ずつ実行しない（カバレッジの作業は共有されます）。
- `--relevant-only` / `--only` で **範囲を絞る**。一括実行には **Sonnet**、難問だけ Opus。
- **予算 (budgets) がホストごとのコスト / 時間を制限** します（`config/config.yaml`）: 既定値はすでに CTF 向けに
  調整済み — `max_subagent_steps 20`、`max_total_leads 60`、加えて 2 つの暴走防止: **設問ごとのリード上限**
  （`max_leads_per_question 8`、答えの出ない 1 問が全バケットへ広がるのを防ぐ）と **実行時間の上限**
  （`max_host_minutes 25`、これを超えるとホストは停止してレポートを書き出す — 回答は逐次保存されるので何も
  失われません）。より安い一括実行のためにさらに下げてもよいですが、`max_subagent_steps` は 18 前後より下げない
  こと（「全候補を並べる」処理が枯渇します）。
- `run_hosts.py --jobs N` で **並列化** する（並列を増やすほど速いが、API/分 と CPU も増える）。
- 自動スリープは防止されます。**蓋は開けたまま** に。素のログにするには `NO_COLOR=1` / `NO_EMOJI=1`。

---

## 9. トラブルシューティング

| 症状 | 対処 |
|---|---|
| `credit balance too low` (400) | console.anthropic.com → Plans & Billing で補充する。 |
| 実行が数分間「固まった」ように見える | 大きな EVTX の解析か API の遅延の可能性。`output/<host>/run.log` を確認。回答は見つかり次第 `case.db` に保存されるので、途中で落ちても失われません — 必要なら db からレポートを作り直す。 |
| `check` が未知の dir-code を表示する | 収集ツールの構成が違う。`--artifact-map` を使う / 合わせる（`artifact_map.yaml` をコピーして code の名前を変える）。 |
| EVTX が 0 件 / `no backend` | Windows で `python-evtx` と `evtx` を同居させない（衝突します）。`evtx` だけにする。 |
| メモリ系の設問が → POINTER | Volatility が未設定。`python install.py`（または `memory.enabled: false` にする）。 |
| マシンがスリープして実行が落ちた | 蓋を開け、電源につなぐ。自動スリープは防げるが、蓋を閉じる操作は防げない。 |

---

_全機能の説明は `README.md`、採点は `eval/README.md`、背景はプロジェクトメモリ
（`live-ctf-playbook`、`ctf-eval-results`）を参照。_
