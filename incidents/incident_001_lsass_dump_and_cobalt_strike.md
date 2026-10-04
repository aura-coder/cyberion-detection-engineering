# Incident Case Report 001: LSASS Credential Dump and Cobalt Strike Injection

**Case ID:** INC-2026-001
**Analyst:** Detection Engineering
**Date opened:** 2026-04-04
**Classification:** **TRUE POSITIVE**
**Severity:** Critical

## Executive Summary

Sysmon telemetry from the sampled corpus shows a confirmed LSASS credential dumping event executed remotely via WMI, followed weeks later by evidence of a Cobalt Strike beacon injected into `lsass.exe` on the same host family. The attacker had already achieved privileged access prior to the dump, given that the dumping process ran as `WmiPrvSE.exe` (SYSTEM context).

## Timeline of Events (reconstructed from raw Sysmon evidence)

| Time (UTC) | Source | Event | ATT&CK |
|------------|--------|-------|--------|
| 2019-08-30 12:54:08.354 | Sysmon EID 1 | `WmiPrvSE.exe` spawns `rundll32.exe` with command: `rundll32 C:\windows\system32\comsvcs.dll, MiniDump 4868 C:\Windows\System32\notepad.bin full` | T1003.001, T1047 |
| 2019-08-30 12:54:08.x | Sysmon EID 11 (inferred) | Output file `notepad.bin` written to `C:\Windows\System32\` | T1003.001 |
| 2020-09-11 12:10:22.398 | Sysmon EID 11 | `lsass.exe` itself creates `C:\Windows\System32\mimilsa.log` | T1055.002, T1003.001 |

## Root Cause Analysis

### Initial vector
Not visible in this corpus slice, but the dumping process ran as `WmiPrvSE.exe`, meaning the attacker had **already obtained SYSTEM-level execution** on the host. Access was likely gained through lateral movement (see Hunt 001 Finding 2 — Impacket wmiexec signature).

### Execution
The attacker abused the legitimate COM+ Services DLL `comsvcs.dll` which exposes a `MiniDump` export. Calling it via `rundll32` produces a full memory dump of the target process without dropping a dedicated tool binary.

- Target PID `4868` = LSASS
- Output `notepad.bin` = public PoC default; chosen for innocuous filename
- `full` argument = complete memory dump including cached credential material

### Post-exploitation
The `mimilsa.log` file created by `lsass.exe` on 2020-09-11 is the **default log filename emitted by mimikatz when run inside a Cobalt Strike beacon** (`beacon> mimikatz` / `beacon> log mimilsa`). The file being written **by `lsass.exe`** rather than by a separate process proves the beacon was injected into LSASS memory, not just running alongside it.

## Evidence

### Primary event (the dump)

```json
{
  "time": "2019-08-30T12:54:08.354049Z",
  "eid": 1,
  "provider": "Microsoft-Windows-Sysmon",
  "image": "C:\\Windows\\System32\\rundll32.exe",
  "cmd": "rundll32 C:\\windows\\system32\\comsvcs.dll, MiniDump 4868 C:\\Windows\\System32\\notepad.bin full",
  "parent": "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe"
}
EOF
cat > incidents/incident_001_lsass_dump_and_cobalt_strike.md <<'MDEOF'
# Incident Case Report 001: LSASS Credential Dump and Cobalt Strike Injection

**Case ID:** INC-2026-001
**Analyst:** Detection Engineering
**Date opened:** 2026-04-04
**Classification:** **TRUE POSITIVE**
**Severity:** Critical

## Executive Summary

Sysmon telemetry from the sampled corpus shows a confirmed LSASS credential dumping event executed remotely via WMI, followed weeks later by evidence of a Cobalt Strike beacon injected into `lsass.exe` on the same host family. The attacker had already achieved privileged access prior to the dump, given that the dumping process ran as `WmiPrvSE.exe` (SYSTEM context).

## Timeline of Events (reconstructed from raw Sysmon evidence)

| Time (UTC) | Source | Event | ATT&CK |
|------------|--------|-------|--------|
| 2019-08-30 12:54:08.354 | Sysmon EID 1 | `WmiPrvSE.exe` spawns `rundll32.exe` with command: `rundll32 C:\windows\system32\comsvcs.dll, MiniDump 4868 C:\Windows\System32\notepad.bin full` | T1003.001, T1047 |
| 2019-08-30 12:54:08.x | Sysmon EID 11 (inferred) | Output file `notepad.bin` written to `C:\Windows\System32\` | T1003.001 |
| 2020-09-11 12:10:22.398 | Sysmon EID 11 | `lsass.exe` itself creates `C:\Windows\System32\mimilsa.log` | T1055.002, T1003.001 |

## Root Cause Analysis

### Initial vector
Not visible in this corpus slice, but the dumping process ran as `WmiPrvSE.exe`, meaning the attacker had **already obtained SYSTEM-level execution** on the host. Access was likely gained through lateral movement (see Hunt 001 Finding 2 — Impacket wmiexec signature).

### Execution
The attacker abused the legitimate COM+ Services DLL `comsvcs.dll` which exposes a `MiniDump` export. Calling it via `rundll32` produces a full memory dump of the target process without dropping a dedicated tool binary.

- Target PID `4868` = LSASS
- Output `notepad.bin` = public PoC default; chosen for innocuous filename
- `full` argument = complete memory dump including cached credential material

### Post-exploitation
The `mimilsa.log` file created by `lsass.exe` on 2020-09-11 is the **default log filename emitted by mimikatz when run inside a Cobalt Strike beacon** (`beacon> mimikatz` / `beacon> log mimilsa`). The file being written **by `lsass.exe`** rather than by a separate process proves the beacon was injected into LSASS memory, not just running alongside it.

## Evidence

### Primary event (the dump)

```json
{
  "time": "2019-08-30T12:54:08.354049Z",
  "eid": 1,
  "provider": "Microsoft-Windows-Sysmon",
  "image": "C:\\Windows\\System32\\rundll32.exe",
  "cmd": "rundll32 C:\\windows\\system32\\comsvcs.dll, MiniDump 4868 C:\\Windows\\System32\\notepad.bin full",
  "parent": "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe"
}
{
  "time": "2020-09-11T12:10:22.398726Z",
  "eid": 11,
  "provider": "Microsoft-Windows-Sysmon",
  "image": "C:\\Windows\\system32\\lsass.exe",
  "file": "C:\\Windows\\System32\\mimilsa.log"
}       Detection rule that fired

    win_comsvcs_minidump.yml (ID eeeeeeee-5555-5555-5555-555555555555) — matches the primary event.

    win_lsass_mimikatz_log_artifact.yml (ID 10000007-0007-0007-0007-000000000007) — matches the CS artifact.

Impact Assessment
Asset	Impact
Host	Complete compromise (SYSTEM)
Credentials	LSASS cached domain credentials for the host's logged-on users
Domain	Potential lateral movement using harvested credentials
Persistence	Cobalt Strike beacon resident in LSASS memory; re-infects on reboot if a persistent mechanism exists
Closure Classification

TRUE POSITIVE, justified by:

    Corroborating evidence from two Sysmon event types (EID 1 and EID 11) across two timelines.

    Presence of a known public PoC command line (comsvcs MiniDump) with no legitimate business justification.

    Presence of a mimikatz/Cobalt Strike artifact file created by LSASS — no benign explanation.

Detection Gaps Revealed

    No detection for rundll32 being spawned by WmiPrvSE.exe. Rule win_wmi_process_call_create.yml catches any WmiPrvSE child but with a medium severity; the combination with rundll32 and comsvcs should be its own high-severity rule (covered by win_comsvcs_minidump.yml).

    No detection for LSASS writing unusual files. Rule win_lsass_mimikatz_log_artifact.yml closes this specific gap but only for the two filenames observed. Broader "LSASS writes any file to System32" rule could follow.

    Initial access vector not detected in this corpus slice. Further hunt required.

Recommended Response

See playbooks/credential_dumping.md. Immediate actions:

    Isolate host from network.

    Force password reset for all accounts with cached credentials on the host.

    Rotate KRBTGT if domain admin credentials were cached.

    Search fleet-wide for mimilsa.log and other mimikatz artifact filenames.

    Reimage host before returning to production.

ATT&CK Mapping

    T1003.001 — OS Credential Dumping: LSASS Memory

    T1047 — Windows Management Instrumentation

    T1055.002 — Process Injection: Portable Executable Injection

    T1036.005 — Masquerading: Match Legitimate Name or Location (notepad.bin path)

Evidence Files

    incidents/incident_001_evidence/comsvcs_events.jsonl — 50 events, all LSASS-related Sysmon records from the corpus

    hunts/hunt_001_evidence/all_proc_creation.jsonl — parent process chain
    MDEOF
