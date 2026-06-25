# Evaluation

Measure how well the investigator answers a known set of questions, against an answer key.

## 1. Write an answer key

A JSON list of questions and their acceptable answers — see `answers.example.json`. Each
entry needs a `question` and at least one accepted answer (`expected`, or `expected_any`
for several acceptable forms). Accepted strings are matched **case-insensitively as a
substring** of the tool's answer (works well for IPs, filenames, hashes, usernames; prose
answers fall to manual review).

## 2. Generate the questions file from the key

So the question text matches exactly:

```bash
python eval/score.py emit-questions --key eval/answers.json --out questions.txt
```

## 3. Run the investigator

The tool is single-host, so run each host collection with the same questions file, giving
each its own `--case-id`:

```bash
for host in /path/to/FORENSICS/ACQ-IR-*; do
  name=$(basename "$host")
  python main.py investigate "$host" --case-id "$name" --questions questions.txt
done
```

(Use `--relevant-only` or `--only <buckets>` to control cost; see the main README.)

## 4. Score

```bash
python eval/score.py score --key eval/answers.json --cases output --out eval/report.md
```

`--cases` scans `output/*/case.db`. A question is a **HIT** if *any* host answered it
correctly (so per-host runs are scored as a union, which also covers cross-host answers).

## Reading the results

| Verdict | Meaning |
|---|---|
| `HIT` | An accepted answer string was found — auto-scored correct. |
| `WRONG` | The question was answered, but no accepted string matched. |
| `POINTER` | The tool pointed at candidate files instead of answering — confirm manually. |
| `UNRESOLVED` | The tool searched but didn't answer. |
| `NOT_ASKED` | No matching question found in any `case.db`. |
| `REVIEW` | Answered, but the key had no accepted strings to match — review by hand. |

`HIT` is the headline coverage number. `POINTER`/`REVIEW` need a human look. `WRONG` /
`UNRESOLVED` / `NOT_ASKED` are the gaps worth digging into.
