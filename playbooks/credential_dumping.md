# IR Playbook: Credential Dumping

**Scenario:** LSASS memory access or dump, indicative of credential harvesting (T1003.001).
**Triggered by rules:** `win_sysmon_lsass_access.yml`, `win_comsvcs_minidump.yml`
**Severity:** Critical

## Trigger Conditions

Any of the following:

- Sysmon EventID 10 where `TargetImage` ends with `\lsass.exe` and `SourceImage` is not a known-good process (see filter list in rule `win_sysmon_lsass_access.yml`).
- Sysmon EventID 1 where `CommandLine` contains both `comsvcs` and `MiniDump`.
- Security EventID 4656 or 4663 with `lsass.exe` object access from a non-standard process.
- EDR/AV alert named "credential dumping", "LSASS access", or "MiniDump".

## Investigation Steps

### 1. Confirm the alert is a true positive
- Pull Sysmon EventID 10 events for the last 24 hours; identify the calling process.
- Pull Sysmon EventID 1 to reconstruct the parent chain of the caller.
- Verify the caller is not a known endpoint-protection or backup agent.

### 2. Identify the dumping method
- **comsvcs.dll MiniDump:** `rundll32 comsvcs.dll, MiniDump <pid> <output> full`
- **ProcDump:** `procdump.exe -ma lsass.exe`
- **Task Manager:** `Taskmgr.exe` with `"Create dump file"` (often benign if user-initiated)
- **Custom loader:** any unsigned binary opening `lsass.exe` with `PROCESS_VM_READ` or `PROCESS_ALL_ACCESS`

### 3. Determine scope
- Which hosts did the dumping process run on? Use Sysmon EventID 1 across fleet.
- Where did the dump file go? Search for files with `.dmp` or `.bin` extension recently created by the responsible process (Sysmon EventID 11).
- Did the attacker exfiltrate it? Look for network connections from the same host in the following 15 minutes (Sysmon EventID 3).

### 4. Assess lateral movement risk
- Enumerate all successful logons (Security 4624) from the host in the next 30 minutes.
- Check for remote execution via SMB (445), WinRM (5985), WMI, or RDP (3389) using harvested credentials.

## Containment

### Immediate (within 15 minutes)
1. **Isolate the host** from the network using EDR or firewall rules (block all except management VLAN).
2. **Preserve volatile evidence** before reboot:
   - Full memory capture if supported.
   - Copy `C:\Windows\Temp\*`, `%TEMP%\*`, `%APPDATA%\*`.
   - Export relevant Event Logs (Security, System, Sysmon, PowerShell).
3. **Reset credentials for any account that logged on** in the 30 minutes before the dump, including service accounts.

### Short-term (within 4 hours)
1. Identify any secondary hosts the attacker reached using the dumped credentials.
2. Reset passwords for all accounts from step 3 above; rotate Kerberos KRBTGT if domain-admin credentials are suspected.
3. Review privileged group membership (`Domain Admins`, `Enterprise Admins`) for unauthorized changes.

## Eradication / Recovery

1. Remove persistence: check Run keys, scheduled tasks, services, WMI subscriptions.
2. Reimage the host if the attacker had interactive access.
3. Re-enable the host on the network only after verifying no persistence remains.
4. Force re-authentication of all users who had cached credentials on the host.

## Stakeholder Communications

| When | Who | What |
|------|-----|------|
| Immediately | SOC lead | Confirmed TP, host isolated |
| Within 1 hour | CISO | Scope (hosts, accounts), initial assessment |
| Within 4 hours | IT ops, HR (if insider) | Password reset campaign |
| Within 24 hours | Legal / compliance | Data exposure assessment, regulatory notification if required |
| Post-incident | All | Written RCA and lessons-learned |

## Detection Feedback

- Confirm `win_sysmon_lsass_access.yml` and `win_comsvcs_minidump.yml` fired.
- If the attacker used an alternate dumping method not caught, write a new rule.
- Add the observed parent process name(s) to the rule filter list if they were benign.
