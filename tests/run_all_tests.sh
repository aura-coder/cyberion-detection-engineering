#!/usr/bin/env bash
# Full test suite for the detection engineering engagement
set -uo pipefail
cd "$(dirname "$0")/.."
source .venv/bin/activate

PASS=0
FAIL=0

check() {
  local name="$1"
  local cmd="$2"
  echo ""
  echo "=========================================="
  echo "TEST: $name"
  echo "=========================================="
  if eval "$cmd"; then
    echo "[PASS] $name"
    PASS=$((PASS+1))
  else
    echo "[FAIL] $name"
    FAIL=$((FAIL+1))
  fi
}

# Test 1: Sigma syntax
check "Sigma syntax validation" "sigma check rules/sigma 2>&1 | grep -q 'Found 0 errors'"

# Test 2: Rule count
check "At least 15 rules exist" "[ \$(ls rules/sigma/*.yml | wc -l) -ge 15 ]"

# Test 3: Correlation rules
check "At least 3 correlation rules" "[ \$(grep -l '^correlation:' rules/sigma/*.yml | wc -l) -ge 3 ]"

# Test 4: Backend conversions exist
check "Splunk conversions exist" "[ \$(ls rules/converted/splunk/*.spl 2>/dev/null | wc -l) -ge 30 ]"
check "Lucene conversions exist" "[ \$(ls rules/converted/elastic/*.lucene 2>/dev/null | wc -l) -ge 30 ]"
check "EQL conversions exist" "[ \$(ls rules/converted/elastic/*.eql 2>/dev/null | wc -l) -ge 30 ]"

# Test 5: Coverage matrix
check "Coverage CSV exists and has rows" "[ \$(tail -n +2 coverage/attack_coverage.csv | wc -l) -ge 20 ]"
check "Coverage Navigator layer exists" "[ -f coverage/attack_coverage_layer.json ]"

# Test 6: Deliverables
check "2+ hunts exist" "[ \$(ls hunts/*.md | grep -v template | wc -l) -ge 2 ]"
check "2+ incidents exist" "[ \$(ls incidents/*.md | grep -v template | wc -l) -ge 2 ]"
check "3+ playbooks exist" "[ \$(ls playbooks/*.md | grep -v template | wc -l) -ge 3 ]"
check "IOC notes exist" "[ -f iocs/ioc_research_notes.md ]"
check "Executive summary exists" "[ -f reports/executive_summary.md ]"
check "Methodology exists" "[ -f docs/methodology.md ]"
check "Presentation exists" "[ -f reports/final_presentation.md ]"

# Test 7: Documentation
check "Data dictionary exists" "[ -f docs/data_dictionary.md ]"
check "Severity rationale exists" "[ -f docs/severity_rationale.md ]"
check "Tuning notes exist" "[ -f docs/rule_tuning_notes.md ]"
check "Correlation docs exist" "[ -f docs/correlation_rules.md ]"

# Test 8: Git
check "Git repo initialized" "[ -d .git ]"
check "At least 10 commits" "[ \$(git rev-list --count HEAD) -ge 10 ]"

# Test 9: Evidence files
check "Hunt 001 evidence exists" "[ -f hunts/hunt_001_evidence/all_proc_creation.jsonl ]"
check "Hunt 002 evidence exists" "[ -f hunts/hunt_002_evidence/all_network.jsonl ]"
check "Incident 001 evidence exists" "[ -f incidents/incident_001_evidence/comsvcs_events.jsonl ]"

# Test 10: Real EVTX corpus
check "Raw EVTX files present" "[ \$(find data/raw/EVTX-ATTACK-SAMPLES -name '*.evtx' 2>/dev/null | wc -l) -ge 200 ]"
check "Processed JSONL present" "[ \$(find data/processed/evtx-json -name '*.jsonl' 2>/dev/null | wc -l) -ge 200 ]"

echo ""
echo "=========================================="
echo "              TEST SUMMARY"
echo "=========================================="
echo "Passed: $PASS"
echo "Failed: $FAIL"
echo ""
if [ $FAIL -eq 0 ]; then
  echo "[SUCCESS] ALL TESTS PASSED"
  exit 0
else
  echo "[FAILURE] $FAIL TEST(S) FAILED"
  exit 1
fi
