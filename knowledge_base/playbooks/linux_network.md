# Playbook: Linux network state (`Conn`, `Fwl`)

A snapshot of connections, sockets, and firewall rules at collection time. These are plain-text
`.dat` dumps — `list_files` then `read_file`, and cite by line. (Not parsed into the timeline; read
them directly.)

## Connections & sockets (`Conn`)
- **`ss-tanp.dat`** — `ss -tanp`: every TCP socket with **state, local/peer address:port, and the
  owning process** (`users:(("proc",pid=…))`). The key artifact.
- `lsofConnections.dat` — `lsof -i`: process ↔ socket, another view of who owns a connection.
- `IPAddress.dat` / `IPRoute.dat` / `IPLink.dat` — interfaces, routes, links.

**What to look for** (T1071 / T1571 / T1219):
- **ESTABLISHED** connections to an external IP owned by a process in `/tmp` `/home` `/dev/shm`, or by
  an interpreter (`python`, `bash`, `nc`, `socat`) = live C2 / reverse shell.
- **LISTEN** on an unusual high port owned by a non-daemon process = a backdoor / bind shell.
- Cross-reference the PID/owner with `source="process"` (Proc) and the IP with `source="syslog"`
  (auth.log SSH source IPs) to attribute it.

## Firewall (`Fwl`)
- `IPTables.dat` / `IP6Tables-Lvn.dat` / `UFW-Status.dat`.
- **Attacker tells** (T1562.004): a rule **allowing** an attacker IP/port, a rule redirecting traffic,
  UFW disabled, or a chain policy loosened. Compare against a default-deny baseline.

## Concluding
`mark_examined` on the assigned bucket (`Conn` / `Fwl`).
