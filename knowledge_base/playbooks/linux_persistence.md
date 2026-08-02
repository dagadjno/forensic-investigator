# Playbook: Linux persistence (`Cron`, `Svc`, `Etc`)

Where Linux malware survives a reboot. These buckets are mostly plain text — `list_files` then
`read_file`, and cite by line. (`Svc/SystemD.dat` and the `systemctl-*` dumps, cron files, and
`/etc/*` are all readable.)

## Cron (`Cron`)
- `crontab`, `cron.d/*`, `cron.{daily,hourly,weekly,monthly}/*`, `anacrontab`, per-user crontabs.
- **Attacker tells** (T1053.003): a job invoking `curl|wget … | sh`, base64/`eval`, a script in
  `/tmp` `/dev/shm` `/home`, a reverse shell, or an odd `@reboot` entry. Compare against the stock
  Ubuntu jobs (apt-compat, man-db, logrotate, dpkg, e2scrub, apport) — those are baseline.

## Services / systemd (`Svc`)
- `systemctl-list-units`, `list-unit-files`, `list-timers`, `SystemD.dat`, `Services.dat`.
- **Attacker tells** (T1543.002): a unit whose `ExecStart` runs from `/tmp` `/home` `/opt` `/usr/local`
  or a script/interpreter; a unit **enabled** recently; a `.timer` unit used like cron; unit names
  masquerading as system services. `.service` files also live under `/etc/systemd/system/` (in `Etc`).

## /etc autostart & hijacks (`Etc`)
- **`/etc/passwd` + `/etc/group`**: enumerate accounts — UID 0 accounts other than `root` (backdoor),
  new users, users added to `sudo`/`wheel`. (`/etc/shadow` if collected: hashes.)
- **SSH**: `~/.ssh/authorized_keys` (in `Home`) and `/etc/ssh/sshd_config` — an added key = persistent
  access (T1098.004); `PermitRootLogin yes`, `AuthorizedKeysFile` changes.
- **Preload hijack**: `/etc/ld.so.preload` and `LD_PRELOAD` in env/profiles = shared-object injection
  / userland rootkit (T1574.006) — a non-empty `ld.so.preload` is a strong signal.
- **Shell/login hooks**: `/etc/rc.local`, `/etc/profile`, `/etc/profile.d/*`, `/etc/bash.bashrc`,
  `/etc/update-motd.d/*`, `/etc/init.d/*` (T1546).
- **Loadable kernel modules**: `/etc/modules`, `/etc/modules-load.d/*` (rootkit LKM).

## Concluding
`mark_examined` on the bucket you were assigned (`Cron` / `Svc` / `Etc`).
