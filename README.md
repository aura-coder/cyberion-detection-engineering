# Cyberion Detection Engineering & Threat Hunting

> Detection engineering engagement — 33 Sigma rules, 2 confirmed threat hunts, 2 true-positive incident reports, 4 IR playbooks, and a full MITRE ATT&CK coverage matrix.

![Sigma](https://img.shields.io/badge/Sigma-33%20rules-0e7c86)
![ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-23%20techniques-blueviolet)
![Hunts](https://img.shields.io/badge/Threat%20Hunts-2%20confirmed-success)
![Incidents](https://img.shields.io/badge/Incidents-2%20true%20positive-critical)
![Tests](https://img.shields.io/badge/Tests-26%2F26%20passing-brightgreen)

---

## What This Is

A detection engineering portfolio built from **real attacker telemetry** — 278 public Windows EVTX files (34,870 events) from the EVTX-ATTACK-SAMPLES corpus. Every rule in this repo was written, tested against real data, and validated.

**No application, backend, or deployed service** — this is detection content, analysis, and documentation, mirroring the day-to-day output of a SOC detection engineer.

---

## Quick Start

    git clone https://github.com/aura-coder/cyberion-detection-engineering.git
    cd cyberion-detection-engineering
    python3 -m venv .venv && source .venv/bin/activate
    pip install -r requirements.txt
    
    bash scripts/fetch_datasets.sh
    bash scripts/convert_evtx.sh
    sigma check rules/sigma
    ./tests/run_all_tests.sh
    ./menu.sh

---

## Detection Rules

**33 Sigma rules** across 8 ATT&CK tactics, all mapped to current technique IDs, all validated (sigma check -> 0 errors).

Notable rules:

| Rule | Technique | Detects |
|------|-----------|---------|
| win_comsvcs_minidump.yml | T1003.001 | LSASS credential dumping via rundll32 comsvcs.dll, MiniDump |
| win_wmi_impacket_redirect.yml | T1047 / T1021.006 | Impacket wmiexec lateral movement signature |
| win_office_masquerade_appdata.yml | T1036.005 | Office binary running from %APPDATA% (masquerade) |
| win_lsass_mimikatz_log_artifact.yml | T1055.002 | Cobalt Strike beacon injected into LSASS |
| win_shadow_copy_execution.yml | T1564.002 | Process execution from a Volume Shadow Copy |

### Correlation Rules (sequence-based)

- correlation_win_failed_logon_burst_then_success.yml — brute force -> credential compromise (5-min window, grouped by user)
- correlation_win_download_then_external_callback.yml — download -> C2 callback (2-min window)
- correlation_win_encoded_powershell_then_external.yml — encoded PowerShell -> outbound connection

---

## ATT&CK Coverage

**40 techniques assessed** on the coverage matrix:

- **30 Covered** — a tested, mapped rule exists
- **4 Partially Covered** — some coverage with documented gaps
- **6 Not Covered** — honest gaps (Account Discovery, Ransomware, etc.)

Files:

- coverage/attack_coverage.csv — machine-readable matrix
- coverage/attack_coverage_layer.json — import into ATT&CK Navigator

---

## Threat Hunts

**2 hypothesis-driven hunts, both confirmed.**

### Hunt 001 — Suspicious Process Chains

Extracted 1,501 Sysmon process-create events; baselined against top parents. Found: masqueraded WINWORD, Impacket wmiexec, comsvcs LSASS dump, shadow-copy execution.

See hunts/hunt_001_suspicious_process_chains.md

### Hunt 002 — Outbound C2 / Beaconing

Extracted 421 network-connection events; classified internal vs. external. Found: mshta.exe -> Moroccan ISP, WMIC.exe -> Vultr, 61-second LOLBin chain (mshta -> regsvr32 -> rundll32 -> certutil).

See hunts/hunt_002_c2_beaconing.md

---

## Incident Reports

**2 true-positive incident case reports** with timelines, raw evidence, RCA, ATT&CK mapping, impact, and closure classification.

### Incident 001 — LSASS Dump + Cobalt Strike Injection

- WmiPrvSE.exe -> rundll32 comsvcs.dll, MiniDump 4868 notepad.bin full
- Later: lsass.exe itself writes mimilsa.log (Cobalt Strike beacon in LSASS memory)
- Closure: True Positive

### Incident 002 — Masqueraded Office Dropper

- Fake WINWORD.exe from %APPDATA% spawning cmd.exe with anti-sandbox + hidden-file delete
- Closure: True Positive

---

## IR Playbooks

**4 operational playbooks** — each with trigger conditions, investigation, containment, eradication, stakeholder comms, and detection feedback.

- playbooks/credential_dumping.md
- playbooks/c2_beaconing.md
- playbooks/lateral_movement_wmi.md
- playbooks/masqueraded_office_dropper.md

---

## Testing

    ./tests/run_all_tests.sh

| Test level | Result |
|------------|--------|
| Sigma syntax validation | 0 errors, 0 issues |
| Rules matched against real telemetry | 17/17 rules matched |
| Correlation rules vs. synthetic sequences | 3/3 fire as designed |
| Full deliverable suite | 26/26 checks pass |

See tests/results/SUMMARY.md for the complete breakdown.

---

## Repository Structure

    rules/sigma/         33 Sigma rules (incl. 3 correlation + 6 base)
    rules/converted/     Splunk SPL, Elastic Lucene, Elastic EQL
    coverage/            ATT&CK coverage CSV + Navigator layer JSON
    hunts/               2 threat hunt reports + evidence JSONL
    incidents/           2 incident case reports + evidence
    playbooks/           4 IR procedures
    iocs/                IOC research notes (IPs, domains, files)
    reports/             Executive summary, methodology, presentation
    docs/                Data dictionary, severity rationale, tuning notes
    scripts/             Automation (fetch, convert, validate, navigator)
    tests/               Test suite + results
    menu.sh              Interactive terminal console

---

## Methodology

- Datasets: EVTX-ATTACK-SAMPLES — 278 files, 34,870 events
- Tooling: sigma-cli / pySigma, Rust evtx parser, jq, Python 3.11+
- Validation: Every rule tested with sigma check; effectiveness measured by matching against the full corpus
- Full methodology: docs/methodology.md

---

## Author

Built as a 4-week detection engineering engagement on the Individual Contributor Track.
