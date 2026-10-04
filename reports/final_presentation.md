# Final Presentation — Detection Engineering & Threat Hunting Engagement

> Paste each `##` section into one slide in Google Slides / PowerPoint / Keynote.

---

## Slide 1 — Title

**Detection Engineering & Threat Hunting Engagement**

- Cyberion Defense Labs
- Prepared for: Security Engineering Program
- Author: Detection Engineering & Threat Intelligence Office
- Date: 2026-04-04

---

## Slide 2 — Executive Headline

**Two real attacks confirmed against real telemetry.**

- Cobalt Strike intrusion: LSASS dump + injection into the credential process
- LOLBin C2 chain: mshta / WMIC contacting Vultr and Moroccan VPS infrastructure
- 24 Sigma rules built, tested, and mapped to 23 MITRE ATT&CK techniques

---

## Slide 3 — Business Problem

- Detections were ad hoc and undocumented
- No ATT&CK-mapped view of coverage
- Threat hunting rare, no repeatable method
- Incidents not written up in a way that feeds back into detection

---

## Slide 4 — What We Built

| Deliverable | Count |
|-------------|-------|
| Sigma detection rules | 24 |
| MITRE ATT&CK techniques mapped | 23 |
| Threat hunts (both confirmed) | 2 |
| Incident case reports (True Positive) | 2 |
| IR playbooks | 4 |
| IOC indicators documented | 4 IPs, 3 domains, 2 files |

---

## Slide 5 — Attack #1: Cobalt Strike Intrusion

- **T1003.001** — LSASS memory dumped via `rundll32 comsvcs.dll, MiniDump`
- **T1047** — Dump executed remotely via WMI (`WmiPrvSE.exe` parent)
- **T1055.002** — Beacon injected into `lsass.exe` (evidenced by `mimilsa.log` created by LSASS itself)
- **Impact:** All domain credentials cached on that host must be treated as compromised

---

## Slide 6 — Attack #2: LOLBin C2 Chain

- **T1218.005** — `mshta.exe` contacting attacker infrastructure
- **T1218.010** — `regsvr32.exe` "Squiblydoo" pattern
- **T1105** — `certutil.exe` download cradle
- **Destinations:** `45.76.12.27` (Vultr), `105.73.6.105` (Moroccan ISP), `108.179.232.58` (HostGator)
- **Impact:** Active attacker beacon traffic from corporate hosts

---

## Slide 7 — Coverage Gaps Closed

| Gap | New Rule |
|-----|----------|
| Office masquerade in AppData | `win_office_masquerade_appdata.yml` |
| WMI + SMB redirect (Impacket) | `win_wmi_impacket_redirect.yml` |
| Shadow copy execution | `win_shadow_copy_execution.yml` |
| LOLBin external traffic | 3 rules added |
| LSASS mimikatz artifact | `win_lsass_mimikatz_log_artifact.yml` |
| Ping-delay + hidden delete | `win_ping_delay_and_hidden_delete.yml` |

---

## Slide 8 — ATT&CK Coverage Matrix

- 23 unique techniques mapped across 8 tactics
- Every rule references a specific technique ID
- Layer file: `coverage/attack_coverage_layer.json` (importable into ATT&CK Navigator)
- Coverage is auditable — each "Covered" row traces to a tested rule

---

## Slide 9 — Threat Hunting Outcomes

**Hunt 001 — Process Chains**
- Result: CONFIRMED
- 4 findings including masqueraded WINWORD and shadow-copy execution

**Hunt 002 — C2 Beaconing**
- Result: CONFIRMED
- 3 findings including Vultr C2 and a 61-second LOLBin chain

Both hunts fed directly into new Sigma rules.

---

## Slide 10 — Detection Quality

- **100%** of rules validated against real telemetry
- **100%** of rules include documented false-positive discussion
- **0** validation errors across 24 rules
- Every rule converted to Splunk SPL, Elastic Lucene, and EQL

---

## Slide 11 — Deliverables Summary

- 24 Sigma rules (versioned in git)
- ATT&CK coverage matrix + Navigator layer
- 2 hunt reports with evidence
- 2 incident case reports (True Positive)
- 4 IR playbooks
- IOC research notes
- Executive summary
- Methodology document

---

## Slide 12 — Recommendations

**Immediate:**
- Rotate credentials for any account that logged on to the compromised host
- Deploy the 24 Sigma rules via the SIEM pipeline

**Short-term:**
- Extend coverage to cloud logs (Azure AD, CloudTrail)
- Continuous purple-team loop via Atomic Red Team

**Long-term:**
- Adopt Sigma as the standard detection format
- Maintain ATT&CK Navigator as a living artifact

---

## Slide 13 — Bottom Line

**Reproducible, evidence-based detection library that caught real attacks.**

Every claim traces to specific log evidence, a written rule, and a MITRE ATT&CK technique ID.

- Repository: `~/cyberion-detection-engineering`
- 127 git-tracked files
- 5-week reproducible methodology

---

## Slide 14 — Questions
