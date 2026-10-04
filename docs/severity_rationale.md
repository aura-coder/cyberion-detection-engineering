# Severity Rationale

Why each Sigma rule is assigned a particular level value. PRD 8 requires levels to be chosen deliberately and the choice to be documented.

## Level Definitions

| Level | Meaning |
|-------|---------|
| critical | Immediate, active compromise indicator. High fidelity. Requires incident response. |
| high | Strong indicator of attacker behavior. Should page on-call. |
| medium | Suspicious behavior that warrants investigation but has benign triggers. |
| low | Broad indicator. Useful in aggregate or during hunts. |
| informational | Telemetry or baseline events. No alerting on its own. |

## Rules by Level

### Critical (2 rules)
- win_comsvcs_minidump.yml (T1003.001) - no routine legitimate use
- win_lsass_mimikatz_log_artifact.yml (T1055.002) - cryptographic proof of Cobalt Strike

### High (15 rules, 3 of which are correlation rules)
- win_security_audit_log_cleared.yml (T1070)
- win_office_masquerade_appdata.yml (T1036.005)
- win_wmi_impacket_redirect.yml (T1047/T1021.006)
- win_shadow_copy_execution.yml (T1564.002)
- win_sysmon_lsass_access.yml (T1003.001)
- win_sysmon_create_remote_thread.yml (T1055)
- win_office_spawns_powershell.yml (T1204.002)
- win_spoolsv_spawns_shell.yml (T1068)
- win_mshta_external_connection.yml (T1218.005)
- win_regsvr32_external_connection.yml (T1218.010)
- win_certutil_download.yml (T1105)
- win_ping_delay_and_hidden_delete.yml (T1070.004)
- correlation_win_failed_logon_burst_then_success.yml (T1110/T1078)
- correlation_win_download_then_external_callback.yml (T1105/T1071)
- correlation_win_encoded_powershell_then_external.yml (T1059.001/T1071)

### Medium (7 rules)
- win_security_scheduled_task_created.yml (T1053.005)
- win_system_new_service_installed.yml (T1543.003)
- win_sysmon_file_create_download_dir.yml (T1105)
- win_sysmon_run_key_persistence.yml (T1547.001)
- win_winrm_session_created.yml (T1021.006)
- win_wmi_process_call_create.yml (T1047)
- win_exe_created_in_appdata_roaming.yml (T1036.005)

### Low (2 rules)
- win_powershell_scriptblock_logged.yml (T1059.001)
- win_bits_job_created.yml (T1197)

### Informational (1 rule)
- proc_creation_win_powershell_encoded_command.yml (T1059.001)

## Design Principle

High-severity rules must be precise. Alert fatigue is prevented by keeping broad-purpose rules at low/informational and reserving critical/high for unambiguous indicators. Correlation rules sit at high because they combine multiple signals.
