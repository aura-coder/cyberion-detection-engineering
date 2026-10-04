# IOC Research Notes

Extracted from Hunt 002 and Incident 001 evidence.

## IP Indicators

| IOC | Type | First seen | Context | Operational use |
|-----|------|------------|---------|-----------------|
| 45.76.12.27 | IPv4 | 2019-05-23 | Vultr VPS (`45-76-12-27.static.afterburst.com`). Contacted by `WMIC.exe` on 443. | Blocklist; alert on any outbound connection. |
| 105.73.6.105 | IPv4 | 2019-05-21 | `aka105.inwitelecom.net` (Moroccan ISP). Contacted by `mshta.exe` on 80 and later `WMIC.exe`. | Blocklist; historical C2. |
| 105.73.6.112 | IPv4 | 2019-05-21 | `aka112.inwitelecom.net`. Contacted by `mshta.exe` on 80. | Blocklist. |
| 108.179.232.58 | IPv4 | 2019-05-21 | `gator4243.hostgator.com`. Contacted by `mshta.exe` on 443. | Watchlist (shared hosting — block at URL level, not IP). |

## Domain Indicators

| Domain | Context | Operational use |
|--------|---------|-----------------|
| afterburst.com | Legacy Vultr brand, appears in PTR for C2 IP | DNS watchlist |
| inwitelecom.net | Legitimate Moroccan ISP, abused for attacker-hosted VPS | Not blockable; alert only on suspicious process behavior to these IPs |
| hostgator.com | Legitimate shared hosting, abused for HTA staging | URL-level blocking only |

## File Indicators

| Path | Context | Operational use |
|------|---------|-----------------|
| `C:\Windows\System32\notepad.bin` | comsvcs MiniDump output filename (public PoC default) | Alert on file create with this name |
| `C:\Windows\System32\mimilsa.log` | Cobalt Strike / mimikatz default log file | Alert on creation, esp. by `lsass.exe` |

## Process Behavior Indicators

| Behavior | Context | Detection |
|----------|---------|-----------|
| `rundll32 comsvcs.dll, MiniDump <pid> <file> full` | LSASS credential dump | `win_comsvcs_minidump.yml` |
| `WmiPrvSE.exe` → `cmd.exe /Q /c ... 1> \\<host>\ADMIN$\...` | Impacket wmiexec | `win_wmi_impacket_redirect.yml` |
| `lsass.exe` writes any file in `System32` | Injected mimikatz logging | `win_lsass_mimikatz_log_artifact.yml` |

## Enrichment Sources Used

- VirusTotal (IP reputation — manual reference)
- AbuseIPDB (community reports)
- Shodan (infrastructure fingerprint)
- Public OTRF write-ups on the EVTX-ATTACK-SAMPLES dataset
