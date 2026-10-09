# Methodology

## Datasets Used

### Primary: EVTX-ATTACK-SAMPLES
- Source: https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
- Size: 278 raw .evtx files (~50 MB)
- Contents: Real Windows Event Log samples organized by ATT&CK tactic (Command and Control, Credential Access, Defense Evasion, Discovery, Execution, Lateral Movement, Persistence, Privilege Escalation)
- Why chosen: Contains unaltered Windows event logs from real adversary emulation runs, giving authentic field structures and event sequences.

### Secondary (reference only): Security-Datasets (OTRF Mordor)
- Source: https://github.com/OTRF/Security-Datasets
- Size: 1.2 GB
- Contents: Adversary emulation runs in Zip archives with YAML metadata
- Role: Reviewed for context; not used as the primary corpus because most data is zipped and requires additional extraction beyond the engagement scope.

### Adversary emulation reference: Atomic Red Team
- Source: https://github.com/redcanaryco/atomic-red-team
- Size: 416 MB
- Role: Reference library mapping ATT&CK techniques to test cases. Used to understand what behaviors correspond to which techniques.

## How Telemetry Was Obtained

1. All datasets were cloned via `git clone --depth 1` into `data/raw/`.
2. No live production systems or client environments were accessed.
3. No attack techniques were executed during this engagement - the corpus is pre-recorded.

## Telemetry Conversion

Raw EVTX files were converted to JSONL using the Rust evtx parser:

    evtx_dump -o jsonl <file.evtx> > <file>.jsonl

- Tool: `evtx` crate version 0.12.3 (installed via `cargo install evtx`)
- Output format: JSON Lines (one JSON object per event)
- Field structure: `{"Event": {"System": {...}, "EventData": {...}}}`
- Total: 278 JSONL files, 37,364 individual events

Automation script: `scripts/convert_evtx.sh`

## Testing Approach

### Sigma rule validation
Every rule was validated with:

    sigma check rules/sigma

Result: 0 errors, 0 condition errors, 0 issues across all rules.

### Query conversion testing
Each rule was converted to three backends to prove portability:

- Splunk SPL: `sigma convert -t splunk --without-pipeline`
- Elastic Lucene: `sigma convert -t lucene -p ecs_windows`
- Elastic EQL: `sigma convert -t eql -p ecs_windows`

Standalone and base rules converted to all three backends. Correlation rules convert to Splunk SPL only (Sigma's Lucene and EQL backends do not support correlation rules). 93 non-empty converted artifacts live in `rules/converted/` (Splunk 33, Lucene 30, EQL 30).

### Rule effectiveness testing
Rules were tested against the JSONL corpus using `jq` queries. Example:

    find data/processed/evtx-json -name '*.jsonl' -exec cat {} \; | \
      jq -c 'select(.Event.System.EventID == 1)' | wc -l

This confirmed that rules which target specific EventIDs and process names actually match real events in the corpus. Of 24 standalone detection rules, 14 matched real events; 10 had no match in this corpus and are reported as untested. Note: the full corpus is 37,364 events; the rule-effectiveness run in `tests/results/SUMMARY.md` used a flattened subset (34,870 events) and the exact filtering step is being re-derived with a reproducible harness. Evidence files are stored under `hunts/*_evidence/` and `incidents/*_evidence/`.

## Limitations

1. The corpus is a sample, not a full enterprise environment. It lacks email gateway logs, cloud audit logs, EDR process trees, and DNS query logs.
2. Timestamps span 2019-2021. Some techniques seen in newer attacks (e.g., cloud-native, container) are not represented.
3. Adversary emulation differs from real adversary behavior in scope, tooling, and pacing.
4. Sigma's near operator support varies by backend. Correlation rules were written to be portable but require the target SIEM to support the semantics.

## Reproducibility

Any analyst with the following can reproduce every finding in this repository:

- Fedora (or any Linux with Rust and Python)
- The cloned EVTX-ATTACK-SAMPLES corpus
- sigma-cli 3.1.0+ and pySigma 1.5.1+
- evtx parser installed via cargo

Steps:

    git clone <this repo>
    cd cyberion-detection-engineering
    python3 -m venv .venv && source .venv/bin/activate
    pip install -r requirements.txt
    bash scripts/fetch_datasets.sh
    bash scripts/convert_evtx.sh
    ./scripts/validate.sh
