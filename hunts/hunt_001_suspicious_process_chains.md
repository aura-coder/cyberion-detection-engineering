# Threat Hunt 001: Suspicious Parent-Child Process Chains

**Status:** Complete — CONFIRMED
**Analyst:** Detection Engineering
**Date:** 2026-04-04
**Dataset:** EVTX-ATTACK-SAMPLES (278 EVTX files, 37,364 total events, 1,501 Sysmon EventID 1 records)

## Hypothesis

An adversary operating in the sampled environment will execute a shell or scripting interpreter as a direct child of an unusual parent (Office suite, spooler, WMI provider host), which should be detectable in Sysmon Process Create (EventID 1) records.

## Data Sources

- `data/processed/evtx-json/**/*.jsonl` (all 278 files)
- Sysmon EventID 1 (Process Create)
- Fields: `Event.EventData.ParentImage`, `Event.EventData.Image`, `Event.EventData.CommandLine`

## Method

1. Extracted all 1,501 Sysmon EventID 1 events into a flat JSONL using `jq`.
2. Filtered for parents matching the suspicious list: `WINWORD|EXCEL|POWERPNT|OUTLOOK|spoolsv|WmiPrvSE|wmiprvse`.
3. Built baseline distributions of top parent and child processes to compare findings against expected system activity.

Evidence file: `hunts/hunt_001_evidence/all_proc_creation.jsonl`

## Findings

### Finding 1 — Masqueraded WINWORD.exe dropping and cleaning up a DLL (T1204.002, T1059.003)

Parent-child chain observed:

    C:\Users\IEUser\AppData\Roaming\WINWORD.exe  ->  C:\Windows\SysWOW64\cmd.exe
    CommandLine: cmd /c ping 127.0.0.1&&del del /F /Q /A:H "C:\Users\IEUser\AppData\Roaming\wwlib.dll"

- The Microsoft Word binary is running from `AppData\Roaming\`, not `Program Files\Microsoft Office\`.
- It spawns `cmd.exe` with an obfuscated delete command targeting `wwlib.dll`.
- `ping 127.0.0.1` is a classic **sleep replacement** used to delay execution in sandboxes and simple macros.
- The `del /F /Q /A:H` flag combination removes a **hidden** DLL, consistent with an implant leaving no trace.

### Finding 2 — WMI-driven lateral movement (T1047, T1021.006)

Multiple `WmiPrvSE.exe` process creations:

    WmiPrvSE.exe -> cmd.exe /Q /c cd  1> \\127.0.0.1\ADMIN$\__1556656369.7 2>&1
    WmiPrvSE.exe -> cmd.exe /Q /c whoami /all 1> \\127.0.0.1\ADMIN$\__1556656369.7 2>&1
    WmiPrvSE.exe -> cmd.exe /Q /c cd \ 1> \\127.0.0.1\C$\WqEVwJZYOe 2>&1

- The `/Q` flag (quiet) plus output redirection to `\\127.0.0.1\ADMIN$\__<epoch>` is the **Impacket wmiexec.py signature**.
- The files `__1556656369.7` (epoch-timestamped) and `WqEVwJZYOe` (random 10-char) are characteristic of the tool's temp output.
- `whoami /all` is immediate post-exploitation reconnaissance.
- Technique mapping: T1047 (WMI), T1021.006 (WinRM/remote exec), T1033 (System Owner/User Discovery).

### Finding 3 — LSASS credential dumping via comsvcs.dll (T1003.001)

    WmiPrvSE.exe -> rundll32.exe
    CommandLine: rundll32 C:\windows\system32\comsvcs.dll, MiniDump 4868 C:\Windows\System32\notepad.bin full

- **Validates detection rule `win_comsvcs_minidump.yml`**.
- `4868` is the LSASS PID at the time of the dump.
- `notepad.bin` in `System32\` is a hardcoded output path used by public PoCs.
- The `full` argument dumps the complete process memory, capturing credential material.

### Finding 4 — Execution from Volume Shadow Copy (T1564.002, T1055)

    WmiPrvSE.exe -> \Device\HarddiskVolumeShadowCopy7\Windows\Temp\svhost64.exe
    CommandLine: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy7\\Windows\Temp\svhost64.exe

- Binary executed directly from a shadow copy, bypassing normal path-based controls.
- `svhost64.exe` masquerades as the legitimate `svchost.exe` but with a `6`/`4` twist.
- `\\?\GLOBALROOT\Device\...` prefix is a common way to access shadow copies without mounting.

## Baseline Comparison

Top parent processes across 1,501 events:

| Parent | Count |
|--------|-------|
| `cmd.exe` | 547 |
| `powershell.exe` | 232 |
| `services.exe` | 137 |
| `svchost.exe` | 111 |
| `explorer.exe` | 52 |
| `winlogon.exe` | 39 |
| **`WmiPrvSE.exe`** | **14** |

`WmiPrvSE.exe` at 14 occurrences is low-volume compared to the baseline. All 14 are suspicious — none reflect routine OS activity in this corpus.

## Conclusion

**CONFIRMED** — the hypothesis holds. Multiple independent adversarial behaviors are observable in the Sysmon Process Create stream:

1. **Macro-based initial execution** masquerading as Office (Finding 1).
2. **WMI-based lateral movement** with Impacket signatures (Finding 2).
3. **Credential dumping** via comsvcs.dll (Finding 3) — this validates our existing detection rule.
4. **Shadow-copy execution** for defense evasion (Finding 4).

## New Detections Enabled

Findings 1, 2, and 4 are **not yet covered** by the current 15-rule library. The following rules should be added:

| Rule Name | Technique | Basis |
|-----------|-----------|-------|
| `win_office_masquerade_appdata.yml` | T1036.005 | Office binary running from AppData |
| `win_wmi_impacket_redirect.yml` | T1047 | `WmiPrvSE` -> `cmd.exe` with `ADMIN$`/`C$` redirect |
| `win_shadow_copy_execution.yml` | T1564.002 | `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy` in CommandLine |

Finding 3 is already covered by `win_comsvcs_minidump.yml`.

## ATT&CK Mapping

- T1204.002 — User Execution: Malicious File
- T1059.003 — Windows Command Shell
- T1036.005 — Masquerading: Match Legitimate Name or Location
- T1047 — Windows Management Instrumentation
- T1021.006 — Remote Services: Windows Remote Management
- T1033 — System Owner/User Discovery
- T1003.001 — OS Credential Dumping: LSASS Memory
- T1564.002 — Hide Artifacts: Hidden Users
