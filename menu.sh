#!/usr/bin/env bash
# Cyberion Detection Engineering Console - compact one-screen version

set -uo pipefail
cd "$(dirname "$0")"
[ -d ".venv" ] && source .venv/bin/activate 2>/dev/null || true

# Colors
BOLD=$'\033[1m'; DIM=$'\033[2m'; NC=$'\033[0m'
BLUE=$'\033[38;5;33m'; SKY=$'\033[38;5;45m'
GREEN=$'\033[38;5;41m'; YELLOW=$'\033[38;5;220m'
RED=$'\033[38;5;203m'; ORANGE=$'\033[38;5;215m'
MAGENTA=$'\033[38;5;177m'; GREY=$'\033[38;5;244m'
WHITE=$'\033[38;5;255m'; TEAL=$'\033[38;5;44m'

# Width
W=76
compute_indent() {
  local cols
  cols=$(tput cols 2>/dev/null || echo 100)
  INDENT=$(( (cols - W) / 2 ))
  [ "$INDENT" -lt 0 ] && INDENT=0
  SPACES=$(printf '%*s' "$INDENT" "")
}
p()  { printf '%s' "$SPACES"; printf '%s\n' "$*"; }
pf() { printf '%s' "$SPACES"; printf "$@"; }

# Data
c_rules()        { ls rules/sigma/*.yml 2>/dev/null | wc -l | tr -d ' '; }
c_corr()         { grep -l '^correlation:' rules/sigma/*.yml 2>/dev/null | wc -l | tr -d ' '; }
c_hunts()        { ls hunts/*.md 2>/dev/null | grep -v template | wc -l | tr -d ' '; }
c_inc()          { ls incidents/*.md 2>/dev/null | grep -v template | wc -l | tr -d ' '; }
c_pb()           { ls playbooks/*.md 2>/dev/null | grep -v template | wc -l | tr -d ' '; }
c_cov()          { tail -n +2 coverage/attack_coverage.csv 2>/dev/null | wc -l | tr -d ' '; }
c_commits()      { git rev-list --count HEAD 2>/dev/null || echo 0; }
c_conv()         { ls rules/converted/splunk/*.spl rules/converted/elastic/*.lucene rules/converted/elastic/*.eql 2>/dev/null | wc -l | tr -d ' '; }

# Working indicator — shows spinner while a command runs
working() {
  local msg="$1"; shift
  local frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
  local i=0
  "$@" > /tmp/menu_cmd.out 2>&1 &
  local pid=$!
  while kill -0 "$pid" 2>/dev/null; do
    printf '%s' "$SPACES"
    printf '\r  %s%s%s %s...' "${SKY}" "${frames[$i]}" "${NC}" "$msg"
    i=$(( (i + 1) % 10 ))
    sleep 0.08
  done
  wait "$pid" 2>/dev/null
  printf '%s' "$SPACES"
  printf '\r  %s✓%s %s            \n' "${GREEN}${BOLD}" "${NC}" "$msg"
  cat /tmp/menu_cmd.out
}

pause() {
  echo ""
  printf '%s' "$SPACES"
  printf '%s↵ Press Enter to return to menu%s' "${DIM}" "${NC}"
  read -r _ || true
}

invalid() {
  echo ""
  printf '%s' "$SPACES"
  printf '%s✗ Invalid selection%s' "${BOLD}${RED}" "${NC}"
  [ -n "${1:-}" ] && printf ' %s"%s"%s' "${YELLOW}" "$1" "${NC}"
  echo ""
  printf '%s' "$SPACES"
  printf '%s  Please enter a number between 0 and 12.%s\n' "${GREY}" "${NC}"
  echo ""
  printf '%s' "$SPACES"
  printf '%s↵ Press Enter to try again...%s' "${DIM}" "${NC}"
  read -r _ || true
}

# ---------- compact banner + dashboard ----------
draw_banner() {
  compute_indent
  clear

  # Compact header line
  pf '%s%s━%.0s%s\n' "${BLUE}" "${NC}" "$(seq 1 $W)" 2>/dev/null || \
    pf '%s%s%s\n' "${BLUE}" "$(printf '━%.0s' $(seq 1 $W))" "${NC}"

  printf '%s' "$SPACES"
  printf '  %s%sCYBERION DEFENSE LABS%s' "${BOLD}${WHITE}" "${NC}" "${NC}"
  local brand_pad=$(( W - 50 ))
  [ $brand_pad -lt 0 ] && brand_pad=0
  printf '%*s' $brand_pad ""
  printf '%s●%s %sOPERATIONAL%s  %s│%s  v1.0.0\n' \
    "${GREEN}" "${NC}" "${WHITE}" "${NC}" "${GREY}" "${NC}"

  # Stats single line
  printf '%s' "$SPACES"
  printf '  %sRules%s:%s%-3s%s  %sCorr%s:%s%-3s%s  %sHunts%s:%s%-3s%s  %sIncid%s:%s%-3s%s  %sCover%s:%s%-3s%s  %sCommits%s:%s%s%s\n' \
    "${GREY}" "${NC}" "${BOLD}${GREEN}" "$(c_rules)" "${NC}" \
    "${GREY}" "${NC}" "${BOLD}${MAGENTA}" "$(c_corr)" "${NC}" \
    "${GREY}" "${NC}" "${BOLD}${SKY}" "$(c_hunts)" "${NC}" \
    "${GREY}" "${NC}" "${BOLD}${ORANGE}" "$(c_inc)" "${NC}" \
    "${GREY}" "${NC}" "${BOLD}${YELLOW}" "$(c_cov)" "${NC}" \
    "${GREY}" "${NC}" "${BOLD}${BLUE}" "$(c_commits)" "${NC}"

  pf '%s%s%s\n' "${BLUE}" "$(printf '━%.0s' $(seq 1 $W))" "${NC}"
  echo ""
}

# ---------- compact menu ----------
# label_w is fixed width for label part; description is right after
mi() {
  local key="$1" label="$2" desc="$3"
  local left="    [$key]  $label"
  local vis=${#left}
  local pad=$(( 46 - vis ))
  [ "$pad" -lt 0 ] && pad=0
  pf '  %s%s%s' "${WHITE}" "$left" "${NC}"
  printf '%*s' "$pad" ""
  pf '%s%s%s\n' "${GREY}" "$desc" "${NC}"
}

draw_menu() {
  # Sections with headers inline (no blank lines between items)
  pf '  %s%sVALIDATION & TESTING%s\n' "${BOLD}" "${BLUE}" "${NC}"
  mi "1"  "Validate Sigma rules"      "sigma check"
  mi "2"  "Run full test suite"       "26 checks"
  mi "3"  "Rule effectiveness"        "matched vs 34,870 events"

  pf '  %s%sCOVERAGE & ANALYSIS%s\n' "${BOLD}" "${BLUE}" "${NC}"
  mi "4"  "ATT&CK coverage matrix"    "40 techniques"
  mi "5"  "Rebuild Navigator layer"   "visual heatmap"

  pf '  %s%sREPORTS%s\n' "${BOLD}" "${BLUE}" "${NC}"
  mi "6"  "Threat hunt reports"       "2 confirmed hunts"
  mi "7"  "Incident case reports"     "2 true positives"
  mi "8"  "Executive summary"         "MD / PDF / HTML / DOCX"

  pf '  %s%sOPERATIONS%s\n' "${BOLD}" "${BLUE}" "${NC}"
  mi "9"  "Convert to Splunk/Lucene/EQL" "108 query files"
  mi "10" "Git history"               "commit log"
  mi "11" "Project statistics"        "project snapshot"
  mi "12" "Presentation"              "PPTX / PDF / HTML / DOCX"

  pf '  %s%sSESSION%s\n' "${BOLD}" "${BLUE}" "${NC}"
  mi "0"  "Exit"                      "quit console"

  echo ""
  pf '%s%s%s\n' "${GREY}" "$(printf '─%.0s' $(seq 1 $W))" "${NC}"
}

# Prompt with selection echo
prompt() {
  echo ""
  printf '%s' "$SPACES"
  printf '  %s%s❯%s Enter selection %s[0-12]%s: ' "${BOLD}${SKY}" "${NC}" "${NC}" "${GREY}" "${NC}"
}

# Show "You selected..." before running action
show_selection() {
  local n="$1" label="$2"
  echo ""
  printf '%s' "$SPACES"
  printf '  %s▶%s You selected %s[%s]%s — %s%s%s\n' \
    "${BOLD}${SKY}" "${NC}" "${BOLD}${WHITE}" "$n" "${NC}" "${GREY}" "$label" "${NC}"
  echo ""
}

# ---------- Actions ----------
action_1() { show_selection "1" "Validate Sigma rules"
  working "Validating rules" sigma check rules/sigma
  pause; }

action_2() { show_selection "2" "Run full test suite"
  ./tests/run_all_tests.sh
  pause; }

action_3() { show_selection "3" "Rule effectiveness"
  python3 - <<'PY'
import json
from pathlib import Path
G="\033[38;5;41m"; R="\033[38;5;203m"; B="\033[1m"; NC="\033[0m"
d = json.loads(Path("tests/results/effectiveness.json").read_text())
m = sum(1 for v in d.values() if v > 0); t = len(d)
for k, v in d.items():
    badge = f"{G}●{v:>4}{NC}" if v > 0 else f"{R}●   0{NC}"
    print(f"  {k[:54]:<54s} {badge}")
print(f"\n  {B}Success: {G}{m}/{t}{NC}")
PY
  pause; }

action_4() { show_selection "4" "ATT&CK coverage matrix"
  python3 - <<'PY'
import csv
G="\033[38;5;41m"; Y="\033[38;5;220m"; R="\033[38;5;203m"; NC="\033[0m"; B="\033[1m"
rows = list(csv.DictReader(open("coverage/attack_coverage.csv")))
cov = sum(1 for r in rows if r["Status"]=="Covered")
par = sum(1 for r in rows if "Partially" in r["Status"])
nco = sum(1 for r in rows if r["Status"]=="Not Covered")
print(f"  Total: {len(rows)}  |  {G}Covered: {cov}{NC}  |  {Y}Partial: {par}{NC}  |  {R}Not Covered: {nco}{NC}\n")
for r in rows:
    st = r["Status"]
    c = G if st=="Covered" else (Y if "Partially" in st else R)
    print(f"  {r['Tactic']:<20s} {r['Technique ID']:<12s} {r['Technique Name'][:36]:<38s} {c}{st}{NC}")
PY
  pause; }

action_5() { show_selection "5" "Rebuild ATT&CK Navigator layer"
  python scripts/csv_to_navigator.py
  echo ""
  echo "  ${GREEN}✓${NC} coverage/attack_coverage_layer.json"
  echo "  Upload to https://mitre-attack.github.io/attack-navigator/"
  pause; }

action_6() { while true; do
  clear
  compute_indent
  show_selection "6" "Threat hunt reports"
  echo "    [1]  Hunt 001 — Suspicious Process Chains"
  echo "    [2]  Hunt 002 — C2 Beaconing Candidates"
  echo "    [3]  Back"
  echo ""
  printf '  Choose: '
  read -r sub || return
  case "$sub" in
    1) less hunts/hunt_001_suspicious_process_chains.md ;;
    2) less hunts/hunt_002_c2_beaconing.md ;;
    3|"") return ;;
    *) invalid "$sub" ;;
  esac
done; }

action_7() { while true; do
  clear
  compute_indent
  show_selection "7" "Incident case reports"
  echo "    [1]  Incident 001 — LSASS Dump + Cobalt Strike"
  echo "    [2]  Incident 002 — Masqueraded Office Dropper"
  echo "    [3]  Back"
  echo ""
  printf '  Choose: '
  read -r sub || return
  case "$sub" in
    1) less incidents/incident_001_lsass_dump_and_cobalt_strike.md ;;
    2) less incidents/incident_002_masqueraded_office_macro.md ;;
    3|"") return ;;
    *) invalid "$sub" ;;
  esac
done; }

action_8() { while true; do
  clear; compute_indent
  show_selection "8" "Executive summary"
  echo "    [1] View    [2] .md    [3] .pdf    [4] .html"
  echo "    [5] .docx   [6] .pptx  [7] ALL      [0] Back"
  echo ""
  printf '  Choose: '
  read -r fmt || return
  mkdir -p reports/exports
  case "$fmt" in
    1) less reports/executive_summary.md ;;
    2) cp reports/executive_summary.md reports/exports/executive_summary.md
       echo "  ✓ reports/exports/executive_summary.md"; pause ;;
    3) pandoc reports/executive_summary.md -o reports/exports/executive_summary.pdf --pdf-engine=weasyprint 2>/dev/null && \
         echo "  ✓ reports/exports/executive_summary.pdf" || echo "  PDF unavailable"; pause ;;
    4) pandoc reports/executive_summary.md -o reports/exports/executive_summary.html --standalone 2>/dev/null
       echo "  ✓ reports/exports/executive_summary.html"; pause ;;
    5) pandoc reports/executive_summary.md -o reports/exports/executive_summary.docx 2>/dev/null
       echo "  ✓ reports/exports/executive_summary.docx"; pause ;;
    6) pandoc reports/final_presentation.md -o reports/exports/final_presentation.pptx 2>/dev/null
       echo "  ✓ reports/exports/final_presentation.pptx"; pause ;;
    7) cp reports/executive_summary.md reports/exports/executive_summary.md
       pandoc reports/executive_summary.md -o reports/exports/executive_summary.html --standalone 2>/dev/null
       pandoc reports/executive_summary.md -o reports/exports/executive_summary.docx 2>/dev/null
       pandoc reports/executive_summary.md -o reports/exports/executive_summary.pdf --pdf-engine=weasyprint 2>/dev/null
       pandoc reports/final_presentation.md -o reports/exports/final_presentation.pptx 2>/dev/null
       echo "  ✓ all written"; ls -1 reports/exports/ 2>/dev/null; pause ;;
    0|"") return ;;
    *) invalid "$fmt" ;;
  esac
done; }

action_9() { show_selection "9" "Convert to Splunk/Lucene/EQL"
  mkdir -p rules/converted/splunk rules/converted/elastic
  local n=0 total=$(ls rules/sigma/*.yml 2>/dev/null | wc -l | tr -d ' ')
  for f in rules/sigma/*.yml; do
    base=$(basename "$f" .yml)
    sigma convert -t splunk --without-pipeline "$f" > "rules/converted/splunk/${base}.spl" 2>/dev/null || true
    sigma convert -t lucene -p ecs_windows "$f" > "rules/converted/elastic/${base}.lucene" 2>/dev/null || true
    sigma convert -t eql -p ecs_windows "$f" > "rules/converted/elastic/${base}.eql" 2>/dev/null || true
    n=$((n+1)); printf '\r  Converting %d/%d...' "$n" "$total"
  done
  printf '\r  ✓ %d rules converted\n\n' "$total"
  echo "  Splunk:  $(ls rules/converted/splunk/*.spl 2>/dev/null | wc -l)"
  echo "  Lucene:  $(ls rules/converted/elastic/*.lucene 2>/dev/null | wc -l)"
  echo "  EQL:     $(ls rules/converted/elastic/*.eql 2>/dev/null | wc -l)"
  pause; }

action_10() { show_selection "10" "Git history"
  git log --oneline --decorate --color=always | head -25
  echo ""; echo "  Total: $(git rev-list --count HEAD) commits"
  pause; }

action_11() { show_selection "11" "Project statistics"
  printf '  %-28s %s\n' "Sigma rules"        "$(c_rules)"
  printf '  %-28s %s\n' "Correlation rules"  "$(c_corr)"
  printf '  %-28s %s\n' "Converted queries"  "$(c_conv)"
  printf '  %-28s %s\n' "ATT&CK rows"        "$(c_cov)"
  printf '  %-28s %s\n' "Threat hunts"       "$(c_hunts)"
  printf '  %-28s %s\n' "Incident reports"   "$(c_inc)"
  printf '  %-28s %s\n' "IR playbooks"       "$(c_pb)"
  printf '  %-28s %s\n' "Git files"          "$(git ls-files | wc -l)"
  printf '  %-28s %s\n' "Git commits"        "$(c_commits)"
  pause; }

action_12() { while true; do
  clear; compute_indent
  show_selection "12" "Presentation export"
  echo "    [1] View    [2] .pptx  [3] .pdf   [4] .html"
  echo "    [5] .docx   [6] .md    [7] ALL    [8] Open PPTX"
  echo "    [0] Back"
  echo ""
  printf '  Choose: '
  read -r fmt || return
  mkdir -p reports/exports
  case "$fmt" in
    1) less reports/final_presentation.md ;;
    2) pandoc reports/final_presentation.md -o reports/exports/final_presentation.pptx 2>/dev/null
       echo "  ✓ reports/exports/final_presentation.pptx"; pause ;;
    3) pandoc reports/final_presentation.md -o reports/exports/final_presentation.pdf --pdf-engine=weasyprint 2>/dev/null && \
         echo "  ✓ reports/exports/final_presentation.pdf" || echo "  PDF unavailable"; pause ;;
    4) pandoc reports/final_presentation.md -o reports/exports/final_presentation.html --standalone 2>/dev/null
       echo "  ✓ reports/exports/final_presentation.html"; pause ;;
    5) pandoc reports/final_presentation.md -o reports/exports/final_presentation.docx 2>/dev/null
       echo "  ✓ reports/exports/final_presentation.docx"; pause ;;
    6) cp reports/final_presentation.md reports/exports/final_presentation.md
       echo "  ✓ reports/exports/final_presentation.md"; pause ;;
    7) cp reports/final_presentation.md reports/exports/final_presentation.md
       pandoc reports/final_presentation.md -o reports/exports/final_presentation.html --standalone 2>/dev/null
       pandoc reports/final_presentation.md -o reports/exports/final_presentation.docx 2>/dev/null
       pandoc reports/final_presentation.md -o reports/exports/final_presentation.pptx 2>/dev/null
       pandoc reports/final_presentation.md -o reports/exports/final_presentation.pdf --pdf-engine=weasyprint 2>/dev/null
       echo "  ✓ all written"; pause ;;
    8) xdg-open reports/exports/final_presentation.pptx 2>/dev/null || \
       xdg-open reports/final_presentation.pptx 2>/dev/null || echo "No pptx yet"; pause ;;
    0|"") return ;;
    *) invalid "$fmt" ;;
  esac
done; }

# ---------- Main loop ----------
trap 'echo ""; exit 130' INT

while true; do
  draw_banner
  draw_menu
  prompt

  if ! IFS= read -r choice; then
    echo ""; exit 0
  fi

  case "$choice" in
    1) action_1 ;;
    2) action_2 ;;
    3) action_3 ;;
    4) action_4 ;;
    5) action_5 ;;
    6) action_6 ;;
    7) action_7 ;;
    8) action_8 ;;
    9) action_9 ;;
    10) action_10 ;;
    11) action_11 ;;
    12) action_12 ;;
    0|q|Q) clear; echo "Bye."; exit 0 ;;
    "?") clear; echo "Numbers 0-12. q=quit."; pause ;;
    *) invalid "$choice" ;;
  esac
done
