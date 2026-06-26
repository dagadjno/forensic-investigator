#!/usr/bin/env python
"""Build a single, self-contained HTML dashboard from all hosts' case.db files.

Reads the structured results (not the markdown) for every `output/<host>/case.db` and emits
ONE offline HTML file you can open in a browser to **search, filter, and sort** across:
  - Answers  — cross-host: every question, which host(s) answered, the answer + confidence,
               and the cited evidence (expand a row).
  - Findings — every host's findings with severity / ATT&CK technique / evidence.
  - Coverage — per-host bucket coverage (present / parsed / examined).

No network, no dependencies (data is embedded; plain JS). Read-only, no AI, no cost.

    python scripts/report_html.py                 # -> output/_combined/report.html
    python scripts/report_html.py --open          # also open it in your browser
    python scripts/report_html.py --root output --out output/_combined/report.html
"""
from __future__ import annotations

import argparse
import glob
import json
import sqlite3
import sys
import webbrowser
from datetime import datetime, timezone
from pathlib import Path

_CONF_RANK = {"high": 3, "medium": 2, "low": 1, "": 0}
_STATUS_RANK = {"answered": 3, "pointer": 2, "unresolved": 1, "": 0}


def _short(case_id: str) -> str:
    import re
    return re.sub(r"-\d{8}-\d{4}$", "", re.sub(r"^ACQ-IR-", "", case_id)) or case_id


def _read_host(db: str) -> dict:
    host = _short(Path(db).parent.name)
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    out = {"host": host, "questions": {}, "answers": [], "findings": [], "coverage": []}
    try:
        out["questions"] = {r["id"]: r["text"] for r in
                            con.execute("SELECT id, text FROM questions ORDER BY rowid")}
        for a in con.execute("SELECT id, question_id, status, answer, confidence, reasoning FROM answers"):
            ev = [r["locator"] for r in con.execute(
                "SELECT locator FROM answer_evidence WHERE answer_id=?", (a["id"],))]
            cand = [f"{r['path']}{(' — ' + r['reason']) if r['reason'] else ''}" for r in con.execute(
                "SELECT path, reason FROM answer_candidates WHERE answer_id=?", (a["id"],))]
            out["answers"].append({"host": host, "qid": a["question_id"], "status": a["status"],
                                   "answer": a["answer"] or "", "confidence": a["confidence"] or "",
                                   "reasoning": a["reasoning"] or "", "evidence": ev, "candidates": cand})
        for f in con.execute("SELECT id, severity, confidence, attack_technique, title, description FROM findings"):
            ev = [r["locator"] for r in con.execute(
                "SELECT locator FROM finding_evidence WHERE finding_id=?", (f["id"],))]
            out["findings"].append({"host": host, "severity": f["severity"] or "", "title": f["title"] or "",
                                    "technique": f["attack_technique"] or "", "confidence": f["confidence"] or "",
                                    "description": f["description"] or "", "evidence": ev})
        for c in con.execute("SELECT artifact, type, present, parser, status FROM coverage"):
            out["coverage"].append({"host": host, "artifact": c["artifact"], "type": c["type"],
                                    "present": bool(c["present"]), "parsed": bool(c["parser"]),
                                    "status": c["status"] or ""})
    except sqlite3.Error:
        pass
    con.close()
    return out


def build_model(dbs: list[str]) -> dict:
    hosts = [_read_host(db) for db in dbs]
    qtext: dict[str, str] = {}
    qorder: list[str] = []
    by_q: dict[str, list] = {}
    findings, coverage = [], []
    for h in hosts:
        for qid, t in h["questions"].items():
            if qid not in qtext:
                qtext[qid], _ = t, qorder.append(qid)
        for a in h["answers"]:
            if a["qid"] not in qtext:
                qtext[a["qid"]] = a["qid"]; qorder.append(a["qid"])
            by_q.setdefault(a["qid"], []).append(a)
        findings += h["findings"]
        coverage += h["coverage"]

    answers = []
    for qid in qorder:
        rows = by_q.get(qid, [])
        agg = max((r["status"] for r in rows), key=lambda s: _STATUS_RANK.get(s, 0), default="unresolved")
        ans_hosts = sorted({r["host"] for r in rows if r["status"] == "answered"})
        best_conf = max((r["confidence"] for r in rows if r["status"] == "answered"),
                        key=lambda c: _CONF_RANK.get(c.lower(), 0), default="")
        # distinct answer texts (keep first casing), for the summary cell
        seen, distinct = set(), []
        for r in rows:
            if r["status"] == "answered":
                k = " ".join(r["answer"].lower().split())
                if k and k not in seen:
                    seen.add(k); distinct.append(r["answer"])
        answers.append({"qid": qid, "question": qtext.get(qid, qid), "status": agg,
                        "answer": " | ".join(distinct), "hosts": ans_hosts,
                        "confidence": best_conf, "rows": rows})
    return {"generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "hosts": [h["host"] for h in hosts], "answers": answers,
            "findings": findings, "coverage": coverage}


def render(model: dict) -> str:
    data = json.dumps(model, default=str).replace("</", "<\\/")
    return _TEMPLATE.replace("/*__DATA__*/null", data)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default="output")
    ap.add_argument("--glob", dest="pattern", default=None)
    ap.add_argument("--out", default=None)
    ap.add_argument("--open", dest="open_", action="store_true", help="open the result in a browser")
    args = ap.parse_args()

    pattern = args.pattern or str(Path(args.root) / "*" / "case.db")
    dbs = sorted(d for d in glob.glob(pattern) if not Path(d).parent.name.startswith("_"))
    if not dbs:
        sys.exit(f"no case.db found under {pattern!r} — run investigations first.")

    out = Path(args.out) if args.out else Path(args.root) / "_combined" / "report.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(build_model(dbs)), encoding="utf-8")
    print(f"wrote {out}  ({len(dbs)} host(s))")
    if args.open_:
        webbrowser.open(out.resolve().as_uri())
    return 0


# --- self-contained HTML (data embedded at /*__DATA__*/null; plain JS, no network) --------
_TEMPLATE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Forensic investigation — dashboard</title>
<style>
:root{--bg:#0f1216;--panel:#171b22;--panel2:#1e242d;--bd:#2b333f;--fg:#e6e9ee;--mut:#9aa4b2;
--ans:#3fb950;--ptr:#d29922;--unr:#6e7681;--crit:#f85149;--high:#db6d28;--med:#d29922;--low:#3fb950;--info:#58a6ff;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif}
header{position:sticky;top:0;z-index:5;background:var(--panel);border-bottom:1px solid var(--bd);padding:12px 18px}
h1{font-size:16px;margin:0 0 6px}
.meta{color:var(--mut);font-size:12px}
.bar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-top:10px}
.bar input,.bar select{background:var(--panel2);color:var(--fg);border:1px solid var(--bd);border-radius:6px;padding:6px 9px;font-size:13px}
#q{flex:1;min-width:220px}
.tabs{display:flex;gap:4px;margin-top:10px}
.tab{padding:6px 14px;border:1px solid var(--bd);border-bottom:none;border-radius:6px 6px 0 0;background:var(--panel2);color:var(--mut);cursor:pointer}
.tab.on{background:var(--bg);color:var(--fg);font-weight:600}
.wrap{padding:0 18px 40px}
table{width:100%;border-collapse:collapse;margin-top:0}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--bd);vertical-align:top}
th{position:sticky;top:118px;background:var(--panel);cursor:pointer;user-select:none;font-size:12px;color:var(--mut);white-space:nowrap}
th:hover{color:var(--fg)} th .ar{opacity:.5;font-size:10px}
tr.row:hover{background:#12161c} tr.row{cursor:pointer}
td.q{max-width:520px} td.ans{max-width:460px}
.pill{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;font-weight:600;white-space:nowrap}
.s-answered{background:rgba(63,185,80,.15);color:var(--ans)}
.s-pointer{background:rgba(210,153,34,.15);color:var(--ptr)}
.s-unresolved{background:rgba(110,118,129,.18);color:var(--unr)}
.sev-critical{background:rgba(248,81,73,.15);color:var(--crit)} .sev-high{background:rgba(219,109,40,.16);color:var(--high)}
.sev-medium{background:rgba(210,153,34,.15);color:var(--med)} .sev-low{background:rgba(63,185,80,.15);color:var(--low)}
.sev-info{background:rgba(88,166,255,.15);color:var(--info)}
.host{display:inline-block;background:var(--panel2);border:1px solid var(--bd);border-radius:4px;padding:0 6px;margin:1px 3px 1px 0;font-size:11px;color:var(--mut)}
.detail{background:#0c0f13}.detail td{padding:10px 16px}
.detail h4{margin:8px 0 4px;font-size:12px;color:var(--mut);text-transform:uppercase;letter-spacing:.04em}
code{background:#0b1722;border:1px solid #143;border-radius:4px;padding:1px 6px;font-size:12px;color:#7ee787;word-break:break-all}
.muted{color:var(--mut)} .none{color:var(--mut);padding:24px;text-align:center}
.count{color:var(--mut);font-size:12px;margin:8px 0}
.conf{font-size:11px;color:var(--mut)}
</style></head>
<body>
<header>
  <h1>🔎 Forensic investigation — combined dashboard</h1>
  <div class="meta" id="meta"></div>
  <div class="tabs" id="tabs"></div>
  <div class="bar" id="filters"></div>
</header>
<div class="wrap"><div class="count" id="count"></div><table id="tbl"><thead id="head"></thead><tbody id="body"></tbody></table>
<div class="none" id="none" style="display:none">No matching rows.</div></div>
<script>
const DATA = /*__DATA__*/null;
const E = s => (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const hostsPill = a => a.map(h=>`<span class="host">${E(h)}</span>`).join('');
const codeList = a => a.length? a.map(l=>`<div><code>${E(l)}</code></div>`).join('') : '<span class="muted">none</span>';

const TABS = {
  answers: {
    label: 'Answers',
    cols: [['question','Question'],['status','Status'],['answer','Answer'],['hosts','Answered by'],['confidence','Conf.']],
    rows: () => DATA.answers,
    cell: (r,c)=>({
      question:`<td class="q">${E(r.question)}</td>`,
      status:`<td><span class="pill s-${r.status}">${r.status}</span></td>`,
      answer:`<td class="ans">${E(r.answer)||'<span class="muted">—</span>'}</td>`,
      hosts:`<td>${hostsPill(r.hosts)||'<span class="muted">—</span>'}</td>`,
      confidence:`<td class="conf">${E(r.confidence)||'—'}</td>`}[c]),
    key:(r,c)=>({question:r.question,status:_STATUS(r.status),answer:r.answer,hosts:r.hosts.join(','),confidence:_CONF(r.confidence)}[c]),
    text:r=>[r.question,r.answer,r.hosts.join(' '),...r.rows.flatMap(x=>[x.answer,x.reasoning,...x.evidence,...x.candidates])].join(' ').toLowerCase(),
    detail:r=>r.rows.map(x=>`<div style="margin-bottom:10px"><span class="pill s-${x.status}">${x.status}</span> <b>${E(x.host)}</b>`
        +(x.confidence?` <span class="conf">(${E(x.confidence)})</span>`:'')
        +(x.answer?`<div style="margin:4px 0">${E(x.answer)}</div>`:'')
        +(x.reasoning?`<div class="muted" style="margin:4px 0">${E(x.reasoning)}</div>`:'')
        +(x.evidence.length?`<h4>Evidence</h4>${codeList(x.evidence)}`:'')
        +(x.candidates.length?`<h4>Candidate files</h4>${codeList(x.candidates)}`:'')+`</div>`).join('') || '<span class="muted">No records.</span>'
  },
  findings: {
    label: 'Findings',
    cols: [['severity','Severity'],['title','Title'],['technique','Technique'],['host','Host'],['confidence','Conf.']],
    rows: () => DATA.findings,
    cell:(r,c)=>({
      severity:`<td><span class="pill sev-${(r.severity||'info').toLowerCase()}">${E(r.severity||'info')}</span></td>`,
      title:`<td class="q">${E(r.title)}</td>`,
      technique:`<td>${E(r.technique)||'<span class="muted">—</span>'}</td>`,
      host:`<td><span class="host">${E(r.host)}</span></td>`,
      confidence:`<td class="conf">${E(r.confidence)||'—'}</td>`}[c]),
    key:(r,c)=>({severity:_SEV(r.severity),title:r.title,technique:r.technique,host:r.host,confidence:_CONF(r.confidence)}[c]),
    text:r=>[r.title,r.technique,r.host,r.description,...r.evidence].join(' ').toLowerCase(),
    detail:r=>(r.description?`<div style="margin-bottom:8px">${E(r.description)}</div>`:'')+`<h4>Evidence</h4>${codeList(r.evidence)}`
  },
  coverage: {
    label: 'Coverage',
    cols: [['host','Host'],['artifact','Bucket'],['type','Type'],['present','Present'],['parsed','Parsed'],['status','Status']],
    rows: () => DATA.coverage,
    cell:(r,c)=>({
      host:`<td><span class="host">${E(r.host)}</span></td>`,artifact:`<td>${E(r.artifact)}</td>`,type:`<td class="muted">${E(r.type)}</td>`,
      present:`<td>${r.present?'yes':'<span class="muted">no</span>'}</td>`,parsed:`<td>${r.parsed?'yes':'<span class="muted">no</span>'}</td>`,
      status:`<td>${E(r.status)||'—'}</td>`}[c]),
    key:(r,c)=>({host:r.host,artifact:r.artifact,type:r.type,present:r.present?1:0,parsed:r.parsed?1:0,status:r.status}[c]),
    text:r=>[r.host,r.artifact,r.type,r.status].join(' ').toLowerCase(),
    detail:null
  }
};
const _STATUS=s=>({answered:3,pointer:2,unresolved:1}[s]||0);
const _CONF=c=>({high:3,medium:2,low:1}[(c||'').toLowerCase()]||0);
const _SEV=s=>({critical:5,high:4,medium:3,low:2,info:1}[(s||'').toLowerCase()]||0);

let tab='answers', sortCol='status', sortDir=-1, q='', fStatus='', fHost='', fSev='';

document.getElementById('meta').innerHTML =
  `${DATA.hosts.length} hosts · ${DATA.answers.length} questions · `
  +`${DATA.answers.filter(a=>a.status==='answered').length} answered · ${DATA.findings.length} findings`
  +` · <span class="muted">generated ${E(DATA.generated)}</span>`;

document.getElementById('tabs').innerHTML = Object.keys(TABS).map(k=>
  `<div class="tab" data-k="${k}">${TABS[k].label}</div>`).join('');
document.querySelectorAll('.tab').forEach(t=>t.onclick=()=>{tab=t.dataset.k;sortCol=TABS[tab].cols[0][0];sortDir=1;buildFilters();render();});

function buildFilters(){
  let h = `<input id="q" placeholder="Search…" value="${E(q)}">`;
  if(tab==='answers') h+=`<select id="fStatus"><option value="">all status</option>${['answered','pointer','unresolved'].map(s=>`<option ${fStatus===s?'selected':''}>${s}</option>`).join('')}</select>`;
  if(tab==='findings') h+=`<select id="fSev"><option value="">all severity</option>${['critical','high','medium','low','info'].map(s=>`<option ${fSev===s?'selected':''}>${s}</option>`).join('')}</select>`;
  const hostOpts = DATA.hosts.map(x=>`<option ${fHost===x?'selected':''}>${E(x)}</option>`).join('');
  h+=`<select id="fHost"><option value="">all hosts</option>${hostOpts}</select>`;
  document.getElementById('filters').innerHTML=h;
  document.getElementById('q').oninput=e=>{q=e.target.value.toLowerCase();render();};
  const fs=document.getElementById('fStatus'); if(fs) fs.onchange=e=>{fStatus=e.target.value;render();};
  const fv=document.getElementById('fSev'); if(fv) fv.onchange=e=>{fSev=e.target.value;render();};
  document.getElementById('fHost').onchange=e=>{fHost=e.target.value;render();};
}

function hostMatch(r){ if(!fHost) return true;
  if(tab==='answers') return r.rows.some(x=>x.host===fHost);
  return r.host===fHost; }

function render(){
  const T=TABS[tab];
  document.getElementById('head').innerHTML='<tr>'+T.cols.map(([k,lbl])=>
    `<th data-c="${k}">${lbl}${sortCol===k?` <span class="ar">${sortDir>0?'▲':'▼'}</span>`:''}</th>`).join('')+'</tr>';
  document.querySelectorAll('th').forEach(th=>th.onclick=()=>{const c=th.dataset.c;
    if(sortCol===c)sortDir*=-1; else {sortCol=c;sortDir=1;} render();});

  let rows=T.rows().filter(r=>{
    if(q && !T.text(r).includes(q)) return false;
    if(tab==='answers'&&fStatus&&r.status!==fStatus) return false;
    if(tab==='findings'&&fSev&&(r.severity||'info').toLowerCase()!==fSev) return false;
    if(!hostMatch(r)) return false;
    return true;});
  rows=rows.map((r,i)=>[r,i]);
  rows.sort((A,B)=>{let a=T.key(A[0],sortCol),b=T.key(B[0],sortCol);
    if(typeof a==='string')a=a.toLowerCase(); if(typeof b==='string')b=b.toLowerCase();
    return (a<b?-1:a>b?1:A[1]-B[1])*sortDir;});

  const body=document.getElementById('body'); body.innerHTML='';
  document.getElementById('none').style.display = rows.length?'none':'block';
  document.getElementById('count').textContent = `${rows.length} row${rows.length===1?'':'s'}`;
  rows.forEach(([r])=>{
    const tr=document.createElement('tr'); tr.className='row';
    tr.innerHTML=T.cols.map(([k])=>T.cell(r,k)).join('');
    body.appendChild(tr);
    if(T.detail){
      const d=document.createElement('tr'); d.className='detail'; d.style.display='none';
      d.innerHTML=`<td colspan="${T.cols.length}">${T.detail(r)}</td>`;
      body.appendChild(d);
      tr.onclick=()=>{d.style.display=d.style.display==='none'?'table-row':'none';};
    }
  });
}
buildFilters(); render();
</script></body></html>"""


if __name__ == "__main__":
    raise SystemExit(main())
