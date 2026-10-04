# Data Dictionary

Source corpus: `data/raw/EVTX-ATTACK-SAMPLES` — 278 real Windows Event Log files from public adversary emulation, converted to JSONL via `scripts/convert_evtx.sh` using `evtx_dump -o jsonl`.

Each line in a `.jsonl` file has the shape:

    {"Event": {"#attributes": {...}, "System": {...}, "EventData": {...}}}

## Source 1: Microsoft-Windows-Sysmon/Operational (192 files)

Primary detection surface for host-level behavior.

### System block (common to all events)
| Field | Meaning | Detection relevance |
|-------|---------|---------------------|
| Event.System.Provider."#attributes".Name | Provider name | Log source routing |
| Event.System.EventID | Sysmon event type | Primary selector |
| Event.System.TimeCreated."#attributes".SystemTime | UTC timestamp | Timeline |
| Event.System.Computer | Hostname | Scoping |
| Event.System.Channel | Microsoft-Windows-Sysmon/Operational | Source routing |

### Sysmon EventID map
| EventID | Meaning | Example ATT&CK techniques |
|---------|---------|---------------------------|
| 1 | Process Create | T1059 (Execution) |
| 3 | Network Connection | T1071 (C2), T1041 (Exfil) |
| 5 | Process Terminated | Timeline support |
| 7 | Image Loaded | T1055 (Injection) |
| 8 | CreateRemoteThread | T1055 |
| 10 | ProcessAccess (LSASS) | T1003.001 (Credential Dumping) |
| 11 | FileCreate | T1105 (Ingress Tool Transfer) |
| 12 | RegistryEvent (create/delete) | T1547 (Persistence) |
| 13 | RegistryEvent (set) | T1547 |
| 17/18 | PipeEvent | T1055 |

### EventID 1 (Process Create) — EventData
| Field | Meaning | Detection relevance |
|-------|---------|---------------------|
| Image | Full path to executable | Selection field |
| CommandLine | Full command line | Primary indicator for LOLBins and obfuscation |
| ParentImage | Parent executable | Anomaly detection |
| ParentCommandLine | Parent command line | Correlation |
| User | Account | Privilege context |
| ProcessGuid / ProcessId | Process identifiers | Correlation |
| IntegrityLevel | Token level | Privilege escalation |
| Hashes | MD5/SHA256/IMPHASH | IOC matching |

### EventID 3 (Network Connection) — EventData
| Field | Meaning | Detection relevance |
|-------|---------|---------------------|
| Image | Process making the connection | Attribution |
| DestinationIp / DestinationHostname | Remote endpoint | C2 IOC |
| DestinationPort | Remote port | Beaconing patterns |
| SourceIp / SourcePort | Local endpoint | Pivot context |
| Protocol | tcp/udp | Filter |
| Initiated | true/false | Direction |

### EventID 11 (FileCreate) — EventData
| Field | Meaning |
|-------|---------|
| Image | Process creating file |
| TargetFilename | Path created |
| CreationUtcTime | When |

### EventID 13 (Registry Set) — EventData
| Field | Meaning |
|-------|---------|
| Image | Process modifying registry |
| TargetObject | Registry key |
| Details | New value |
| EventType | e.g. SetValue |

## Source 2: Microsoft-Windows-Security-Auditing (27 files)

| EventID | Meaning | Detection relevance |
|---------|---------|---------------------|
| 4624 | Successful logon | T1078, T1021 |
| 4625 | Failed logon | T1110 (Brute Force) |
| 4648 | Explicit credential logon | T1078 |
| 4698 | Scheduled task created | T1053.005 |
| 4699 | Scheduled task deleted | Timeline |
| 4720 | User account created | T1136 |
| 4728/4732 | Group membership changed | T1098 |
| 5145 | Network share object access | T1039, T1083 |
| 1102 | Audit log cleared | T1070.001 |

### EventID 4624 (Logon) — EventData
| Field | Meaning |
|-------|---------|
| TargetUserName | Account logging in |
| LogonType | 2=interactive, 3=network, 10=RDP |
| IpAddress | Source IP |
| WorkstationName | Source host |

## Source 3: Microsoft-Windows-PowerShell/Operational

| EventID | Meaning |
|---------|---------|
| 4104 | Script block logged (T1059.001) |
| 4103 | Module logging |
| 400 / 403 | Engine state |

### EventID 4104 — EventData
| Field | Meaning |
|-------|---------|
| ScriptBlockText | Full script content |
| Path | Script file path if applicable |
| ScriptBlockId | Correlation hash |

## Source 4: Service Control Manager

| EventID | Meaning |
|---------|---------|
| 7045 | New service installed (T1543.003) |
| 7036 | Service state change |

### EventID 7045 — EventData
| Field | Meaning |
|-------|---------|
| ServiceName | Service name |
| ImagePath | Binary path |
| ServiceType | e.g. user mode service |
| StartType | e.g. demand start |

## Source 5: Microsoft-Windows-Eventlog

| EventID | Meaning |
|---------|---------|
| 104 | Log cleared (T1070.001) |

## Source 6: Microsoft-Windows-Bits-Client/Operational

| EventID | Meaning |
|---------|---------|
| 3 | BITS job created (T1197) |
| 59 / 60 | BITS transfer events |

## Source 7: Microsoft-Windows-WinRM/Operational

| EventID | Meaning |
|---------|---------|
| 6 | WSMan session created (T1021.006) |
| 91 / 142 | Session operations |

## Source 8: Microsoft-Windows-TerminalServices-RemoteConnectionManager

| EventID | Meaning |
|---------|---------|
| 1149 | RDP auth succeeded (T1021.001) |

## Field access notes
- Attributes use `#attributes` wrapper: `TimeCreated."#attributes".SystemTime`
- Sigma rules use plain names (`Image`, `CommandLine`, `EventID`); the `ecs_windows` pipeline maps them to backend paths
- Raw `jq` access: `.Event.EventData.Image`, `.Event.System.EventID`
