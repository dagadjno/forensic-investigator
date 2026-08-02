# Playbook: Linux logs (`VarLog` — /var/log)

Two parsers feed the timeline from this bucket; most other logs here are plain text you can
`read_file` / `grep_artifact` directly and cite by line.

- `source="syslog"` — auth.log / syslog / kern.log lines (`event_type="syslog:<program>"`).
- `source="package"` — dpkg.log + apt/history.log (`event_type="package:dpkg:*"` / `package:apt"`).

## How to work it
- `query_timeline(source="syslog", contains="sshd")` / `contains="sudo"` / a username / an IP.
- `query_timeline(source="package", contains="<tool>")` — did the attacker install something?
- Un-parsed logs (journald is binary; cloud-init, bootstrap, cups, dmesg are text): `list_files(artifact="VarLog")` then `read_file`.

## auth.log — the core intrusion trail (source="syslog")
- **SSH (`sshd`)**: `Accepted password/publickey for <user> from <IP>` = successful logon (T1021.004);
  `Failed password for [invalid user] <user> from <IP>` = brute force (T1110); `Accepted` after many
  `Failed` from one IP = successful brute force. The `user` and source `IP` are on the line.
- **sudo**: `sudo: <user> : TTY=… ; PWD=… ; USER=root ; COMMAND=<cmd>` — the **exact command run as
  root** (privilege escalation / execution, T1548.003). `pam_unix(sudo:session): session opened for
  user root by <user>` brackets it.
- **su**: `su: (to root) <user> on pts/N` — switched user.
- **New accounts / passwd**: `useradd`, `passwd[…]: password for '<user>' changed`, `usermod`,
  `groupadd`, adding a user to `sudo`/`wheel` (T1136 / T1098).

## Packages (source="package")
- `dpkg <install>` of an unexpected tool, or an **apt `cmd=…`** the operator typed (e.g.
  `apt install <recon/tunnel/cryptominer tool>`) = how tooling arrived (T1105 / T1072). The apt
  `history.log` block preserves the full command line.

## journald (binary — not parsed)
`VarLog/journal/*.journal` is the systemd binary journal. It often duplicates auth/syslog content
(which IS parsed). If a question needs journal-only data, POINT at the `.journal` files.

## Concluding
When you've reviewed the relevant logs for this lead, `mark_examined("VarLog")`.
