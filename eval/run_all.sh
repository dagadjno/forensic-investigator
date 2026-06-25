#!/usr/bin/env bash
# Run the investigator across all DC33 OBSIDIAN hosts, sequentially, --relevant-only.
set -u
FORENSICS="/c/Users/dagadjno/Downloads/DC33/CTF-OBSIDIAN/CTF-OBSIDIAN/FORENSICS"
LOGDIR="eval/logs"
mkdir -p "$LOGDIR"
MASTER="$LOGDIR/run_all.log"
: > "$MASTER"

echo "[batch] start $(date)" | tee -a "$MASTER"
for host in "$FORENSICS"/ACQ-IR-*; do
  name=$(basename "$host")
  echo "[batch] >>> $name  $(date)" | tee -a "$MASTER"
  python main.py investigate "$host" --case-id "$name" \
      --questions questions.txt --relevant-only \
      > "$LOGDIR/$name.log" 2>&1
  rc=$?
  echo "[batch] <<< $name rc=$rc  $(date)" | tee -a "$MASTER"
done
echo "[batch] done $(date)" | tee -a "$MASTER"
