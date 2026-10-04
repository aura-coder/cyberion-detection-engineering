# IR Playbook: Masqueraded Office Dropper

**Scenario:** Binary masquerading as Microsoft Office (`WINWORD.EXE`, `EXCEL.EXE`) executing from a user directory and dropping a secondary payload.
**Triggered by rules:** `win_office_masquerade_appdata.yml`, `win_exe_created_in_appdata_roaming.yml`, `win_ping_delay_and_hidden_delete.yml`
**Severity:** High

## Trigger Conditions

- A process named `WINWORD.EXE`, `EXCEL.EXE`, `POWERPNT.EXE`, or `OUTLOOK.EXE` executing from `%APPDATA%`, `%TEMP%`, `Downloads`, or `Public`.
- A user-directory binary spawning `cmd.exe` with `ping 127.0.0.1` and `del /A:H` in the same command line.
- An `.exe`/`.dll` file created in `%APPDATA%\Roaming\` by a non-whitelisted process.

## Investigation Steps

### 1. Confirm the masquerade
- Verify the hash of the "Office" binary. Real Microsoft Word hashes are stable and signed by Microsoft.
- Check the file's digital signature: `Get-AuthenticodeSignature <path>`.
- Compare against the legitimate Office install path.

### 2. Reconstruct the parent chain
- Pull Sysmon EID 1 for the last 24 hours; trace from `explorer.exe` → user download → dropped binary → cmd.exe chain.
- Identify the original delivery vector (email, browser download, USB).

### 3. Enumerate dropped files
- List all files created in `%APPDATA%\Roaming\`, `%TEMP%`, and `%LOCALAPPDATA%\` in the last 24 hours.
- Look for hidden attribute (`attrib`).

### 4. Persistence check
- Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- Scheduled tasks: `schtasks /query /fo LIST /v | findstr /i <payload>`
- Startup folder: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`

## Containment

1. Isolate the host from the network.
2. Preserve memory for forensics before cleanup.
3. Hunt fleet-wide for the same masqueraded filename + hash.

## Eradication / Recovery

1. Remove dropped binaries and any persistence entries.
2. Reset credentials for the impacted user (browser caches, saved passwords).
3. Reimage if interactive attacker access is confirmed.

## Stakeholder Communications

| When | Who | What |
|------|-----|------|
| Immediately | SOC lead | Confirmed masquerade, host isolated |
| Within 1 hour | CISO | Vector, scope |
| Within 4 hours | IT ops | User password reset, email gateway review |

## Detection Feedback

- Confirm `win_office_masquerade_appdata.yml`, `win_exe_created_in_appdata_roaming.yml`, and `win_ping_delay_and_hidden_delete.yml` all fired.
- If a legitimate app uses Office-masquerading binaries, add it to the rule filter.
