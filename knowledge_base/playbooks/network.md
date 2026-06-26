# Playbook: Network connections & config (`Conn`)

Point-in-time network state captured at collection: open ports/connections, ARP, DNS,
routing, interface config. **Not parsed into the timeline** — reach these via
`list_files(artifact="Conn")` then `read_file(path)`. The text dumps (`.dat`, `.csv`) are
readable; cite the `file:<path>:<line>` locator a read returns.

## The high-value file: `CPorts.csv`
A CurrPorts dump that maps **each open port/connection to the owning process** — this is
how you tie a C2/remote-access connection to a binary. It is a **headerless** CSV; the
leading columns are, in order:

1. Process Name 2. PID 3. Protocol (TCP/UDP) 4. Local Port 5. Local Port Name
6. Local Address 7. **Remote Port** 8. Remote Port Name 9. **Remote Address (IP)**
10. **Remote Host Name** 11. State (Established/Listening/…)

…and later in the same row: full **Process Path**, Product/Company, Process-Created time,
and the **User Name** the process runs as. Because there's no header, rely on this order.

What to extract:
- **Remote Address (col 9) + Remote Host Name (col 10)** on an `Established` row = a live
  outbound connection — the prime **C2 / remote-access** candidate (e.g. an `AnyDesk` /
  `AnyDesk relay` row, a raw IP on 443/4444, etc.).
- **Listening** rows on odd high ports = a possible backdoor/bind shell.
- The **Process Name + Path + User** column tells you *what* owns the socket and *as whom*
  (SYSTEM is notable for a user-space tool).

## The other `Conn/*.dat` files
- `IPConfig.dat` / `IPCfgDNS.dat` — host IP(s), gateway, DNS servers, domain suffix
  (identifies the host and its segment).
- `ArpInfo.dat` — recently-contacted LAN hosts (lateral-movement neighbors).
- `NetBios.dat` — NetBIOS names/sessions.
Use `read_file` on these for host/network identity and to corroborate a target IP.

## Cross-reference
- Memory `windows.netscan` / `netstat` (vol_run) — live sockets straight from RAM.
- SRUM (`source="srum"`) — per-app network *usage* over time (bytes sent/received).
- Browser downloads + PowerShell history — the URL/IP a payload came from.

## Concluding
Call `find_flags` if you haven't (a flag may be planted in a text dump), then
`mark_examined("Conn")` once you've reviewed the relevant connections for this lead.
