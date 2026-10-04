# IR Playbook: Lateral Movement via WMI

**Scenario:** Adversary uses WMI to execute commands on a remote host.
**Triggered by rules:** `win_wmi_process_call_create.yml`, `win_wmi_impacket_redirect.yml`
**Severity:** High

## Trigger Conditions

- `WmiPrvSE.exe` spawns `cmd.exe`, `powershell.exe`, or `rundll32.exe`.
- `WmiPrvSE.exe` child command line contains `\\<host>\ADMIN$\` or `\\<host>\C$\` redirects.
- Security event 4648 (explicit credential logon) followed by WMI activity.
- `mshta.exe` or `rundll32.exe` spawned by `WmiPrvSE.exe`.

## Investigation Steps

### 1. Confirm the WMI activity is remote
- WMI can be invoked locally (rare) or remotely.
- Check `WorkstationName`/`SourceHost` on the associated 4648 event if present.
- Look at inbound RPC (port 135) connections to the host at the time of the WMI activity.

### 2. Reconstruct the chain
- Parent image of the WMI call tells you who initiated it.
- Look for `wmic.exe /node:` in the calling process's command line.
- If Impacket (`wmiexec.py`), expect output redirects to `ADMIN$` or `C$`.

### 3. Post-exploitation
- Look for LSASS dumps within 30 minutes.
- Look for reconnaissance commands: `whoami`, `hostname`, `net group`, `ipconfig`.
- Look for additional lateral movement targets.

## Containment

1. Isolate both source and destination hosts from the network.
2. Disable the compromised account used for the WMI call.
3. Block WMI (RPC 135 / WMI 5985) at the firewall between segments if business allows.

## Eradication / Recovery

1. Reset credentials for all accounts used in the lateral movement.
2. Remove any persistence created by the WMI activity.
3. Reimage the destination host.

## Stakeholder Communications

| When | Who | What |
|------|-----|------|
| Immediately | SOC lead | Lateral movement confirmed, hosts isolated |
| Within 1 hour | CISO, IT ops | Accounts involved, hosts isolated |
| Within 4 hours | All | Password reset campaign |

## Detection Feedback

- If the WMI call came from a process not yet in the rules, add it.
- If a legitimate admin tool uses WMI with SMB redirect, add to the rule's filter list.
