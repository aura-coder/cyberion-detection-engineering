# Correlation Rules

Three correlation-style rules satisfying PRD 4.2: "At least 3 rules must be correlation-style (i.e., they depend on a sequence or combination of events, not a single log line)."

Sigma correlations require a paired structure:
- One or more **base** rules (type: test) that define primitive selections
- A **correlation** rule that references base rules by `name` and defines the temporal or aggregation logic

## Correlation 1 - Failed Logon Burst Then Success

- **File:** `correlation_win_failed_logon_burst_then_success.yml`
- **Base rules:** `base_win_failed_logon_event`, `base_win_successful_logon_event`
- **Type:** temporal
- **Group by:** `TargetUserName`
- **Timespan:** 5 minutes
- **Techniques:** T1110 (Brute Force), T1078 (Valid Accounts)
- **Severity:** high
- **Why correlation:** A single 4625 is noise; the combination of repeated 4625 followed by 4624 within 5 minutes for the same account is brute-force-to-compromise.

## Correlation 2 - Download Then External Callback

- **File:** `correlation_win_download_then_external_callback.yml`
- **Base rules:** `base_win_file_created_in_downloads`, `base_win_network_connection_event`
- **Type:** temporal
- **Timespan:** 2 minutes
- **Techniques:** T1105 (Ingress Tool Transfer), T1071 (Application Layer Protocol)
- **Severity:** high
- **Why correlation:** Neither file create nor network connection is meaningful alone; the ordered pair is the download-and-execute pattern.

## Correlation 3 - Encoded PowerShell Then External Connection

- **File:** `correlation_win_encoded_powershell_then_external.yml`
- **Base rules:** `base_win_encoded_powershell_execution`, `base_win_powershell_network_connection`
- **Type:** temporal
- **Timespan:** 2 minutes
- **Techniques:** T1059.001 (PowerShell), T1071 (Application Layer Protocol)
- **Severity:** high
- **Why correlation:** Encoded PowerShell is suspicious; encoded PowerShell that immediately makes an external connection is a download cradle or C2 stager.
