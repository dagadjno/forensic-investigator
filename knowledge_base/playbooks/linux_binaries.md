# Playbook: Running-program binaries (`RanProg`)

`RanProg` holds **copies of the actual on-disk executables** of processes that were running at
collection time (one file per binary, named `-path-to-binary-<md5>`). These are the real ELF files
— binary, so you can't `read_file` them; you POINT at them for hashing / YARA / VirusTotal, and
correlate by hash with the process snapshot.

## How to work it
- `list_files(artifact="RanProg")` — the filename encodes the original path (dashes for slashes) and
  an md5 suffix. A binary copied from `/tmp/…`, `/home/…`, `/dev/shm/…` is immediately suspect.
- Cross-reference with `source="process"` (Proc): the `sha1=` on a process event identifies the same
  binary; a hash **not** owned by any `dpkg` package (see `Sys/dpkg-l.dat`) is suspect.
- For "what is the hash of the malware" style questions, POINT at the `RanProg` copy (and/or cite the
  `source="process"` `sha1`); for "is it malicious", the answer is a VirusTotal/OSINT lookup on the
  hash — POINT, don't guess.

## What to look for
- A copied binary whose **original path** was a user/tmp/writable location (not `/usr`, `/bin`,
  `/sbin`) — attacker tooling (T1105 / T1059).
- The `avml` copy (memory-acquisition tool) and other DFIR tools are **collector-introduced** — do
  NOT attribute those to the attacker (see `playbooks/acquisition_log.md`).

## Concluding
`mark_examined("RanProg")` when done.
