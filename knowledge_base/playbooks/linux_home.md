# Playbook: Linux user home (`Home`)

User dotfiles and shell history. Shell history is parsed into the timeline
(`source="shell_history"`, `event_type="shell_command"`); the other dotfiles are text — `read_file`
and cite by line.

## Shell history (source="shell_history")
- `.bash_history` / `.zsh_history` — the user's / attacker's **typed commands**, one event per line.
  `query_timeline(source="shell_history", user="<user>")` or `contains="<cmd>"`.
- **What to look for** (T1059): downloads (`curl`/`wget`/`scp`), `chmod +x`, running things from
  `/tmp`, reverse shells (`bash -i >& /dev/tcp/…`, `nc`, `socat`), recon (`whoami`, `id`, `uname -a`,
  `netstat`/`ss`, `find / -perm -4000`), privilege escalation, `history -c` / clearing, editing cron
  or `authorized_keys`, credential access (`cat /etc/shadow`, `~/.ssh/`, env dumps).
- Timestamps exist only if `HISTTIMEFORMAT` was set (`#<epoch>` lines) — otherwise commands are
  **ordered but un-timed**; use order, not wall-clock.
- A **truncated / missing / recently-cleared** history is itself suspicious (anti-forensics).

## Dotfiles (read directly)
- **Persistence via shell rc** (T1546.004): `~/.bashrc`, `~/.bash_profile`, `~/.profile`,
  `~/.bash_logout`, `~/.zshrc` — an appended download-and-run, alias hijack, or `PROMPT_COMMAND`.
- **SSH**: `~/.ssh/authorized_keys` (added key = backdoor), `~/.ssh/config`, `known_hosts` (where the
  user connected out — lateral movement).
- **Credentials left behind**: `~/.aws/credentials`, `~/.config/`, `~/.netrc`, `~/.git-credentials`,
  `~/.mozilla` / browser profiles, `~/.gnupg`.

## Concluding
`mark_examined("Home")` when done.
