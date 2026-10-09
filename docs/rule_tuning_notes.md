# Rule Tuning Notes

Three documented false-positive tuning passes. Each follows the PRD 4.8 format: observed false positive, logic change, trade-off accepted.

---

## Tuning Pass 1 - win_exe_created_in_appdata_roaming.yml

Rule ID: 2039b043-6d02-4564-9290-8e690d94dce0
Technique: T1036.005

### Observed false positive
Chrome, Slack, Teams, VS Code, and other Electron-based applications update themselves by writing new .exe files into %APPDATA%\Roaming\ directories. In a normal working day, this pattern fired dozens of times on developer and knowledge-worker endpoints.

### Logic change
Added a filter_known selection that excludes file-creation events where the parent process is a known Electron app updater (OneDrive.exe, Teams.exe, slack.exe, Code.exe).

### Trade-off accepted
An attacker who names their loader slack.exe and drops it in the exact Electron update path would evade. Accepted because:
1. The path pattern is highly specific.
2. The parent process hash would also need to match to avoid other rules.
3. Broader coverage would generate too much noise on healthy endpoints.

---

## Tuning Pass 2 - win_sysmon_lsass_access.yml

Rule ID: 89b16a59-bd06-4fd2-abc9-751e3df44f40
Technique: T1003.001

### Observed false positive
On Windows 10/11 endpoints, MsMpEng.exe (Windows Defender) accesses lsass.exe memory as part of real-time protection scans, producing a Sysmon EventID 10 on every boot. Enterprise backup agents also touch LSASS periodically.

### Logic change
Added a filter_known selection for known-good sources (svchost.exe, MsMpEng.exe, csrss.exe, wininit.exe, services.exe).

### Trade-off accepted
An attacker who injects into one of these signed processes and then accesses LSASS would evade. Accepted because:
1. If the attacker has code inside MsMpEng.exe, the environment is already deeply compromised.
2. Alerting on every Defender scan makes the rule useless.
3. Other rules (win_comsvcs_minidump.yml, win_lsass_mimikatz_log_artifact.yml) provide defence in depth.

---

## Tuning Pass 3 - win_sysmon_file_create_download_dir.yml

Rule ID: 3a637a4d-2478-448c-9250-eb6436bac56c
Technique: T1105

### Observed false positive
Users legitimately download installers, portable apps, and software update packages into Downloads many times a day. Browsers and self-updating apps trigger this rule without any attacker involvement.

### Logic change
1. Narrowed to executable extensions only (.exe, .dll, .scr, .ps1, .bat, .vbs) - excludes documents, archives, images.
2. Added an optional parent-process filter for browsers (documented but commented out).

### Trade-off accepted
We deliberately did NOT enable the browser filter, accepting a moderate false-positive rate, because attacker-delivered first-stage payloads frequently come from browsers too. The rule is intentionally noisy and used as a hunting aid. Combined with win_ping_delay_and_hidden_delete.yml or the new correlation rule, it becomes high-signal.
