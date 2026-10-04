# Threat Hunt 001: Suspicious Parent-Child Process Chains

## Hypothesis
An adversary operating in the sampled environment will execute a shell or scripting interpreter as a direct child of an unusual parent (Office suite, spooler, WMI provider host), which should be detectable in Sysmon Process Create (EventID 1) records.

## Data Sources
- `data/processed/evtx-json/**/*.jsonl`
- Sysmon EventID 1 (Process Create)
- Fields: `Event.EventData.ParentImage`, `Event.EventData.Image`, `Event.EventData.CommandLine`

## Method
Enumerate all Process Create events, group by `ParentImage`, count child images, and flag suspicious pairs.

## Findings
(to be filled in with real query results)

## Conclusion
(to be filled in)

## ATT&CK Mapping
- T1204.002 — Malicious File
- T1059 — Command and Scripting Interpreter
- T1047 — Windows Management Instrumentation
