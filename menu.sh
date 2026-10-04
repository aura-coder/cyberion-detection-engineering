#!/usr/bin/env bash
# Cyberion Detection Engineering Console - clean centered version

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

# Fixed menu width
W=78

# Compute left indent for centering
compute_indent() {
  local cols
  cols=$(tput cols 2>/dev/null || echo 100)
  INDENT=$(( (cols - W) / 2 ))
  [ "$INDENT" -lt 0 ] && INDENT=0
  SPACES=$(printf '%*s' "$INDENT" "")
}

# Print with indent prefix
p() { printf '%s' "$SPACES"; printf '%s\n' "$*"; }
pf() { printf '%s' "$SPACES"; printf "$@"; }

# Data collectors
c_rules()        { ls rules/sigma/*.yml 2>/dev/null | wc -l | tr -d ' '; }
c_correlations() { grep -l '^correlation:' rules/sigma/*.yml 2>/dev/null | wc -l | tr -d ' '; }
c_hunts()        { ls hunts/*.md 2>/dev/null | grep -v template | wc -l | tr -d ' '; }
c_incidents()    { ls incidents/*.md 2>/dev/null | grep -v template | wc -l | tr -d ' '; }
c_playbooks()    { ls playbooks/*.md 2>/dev/null | grep -v template | wc -l | tr -d ' '; }
c_coverage()     { tail -n +2 coverage/attack_coverage.csv 2>/dev/null | wc -l | tr -d ' '; }
c_commits()      { git rev-list --count HEAD 2>/dev/null || echo 0; }
c_converted()    { ls rules/converted/splunk/*.spl rules/converted/elastic/*.lucene rules/converted/elastic/*.eql 2>/dev/null | wc -l | tr -d ' '; }
c_last()         { git log -1 --format='%s' 2>/dev/null | cut -c1-52; }

# Pause
pause() {
  echo ""
  printf '%s' "$SPACES"
  printf '%s↵ Press Enter to return to menu%s' "${DIM}" "${NC}"
  read -r _ || true
}

# Clear + reposition
redraw() {
  clear
  compute_indent
}

# Open file helper
open_file() {
  local f="$1"
  [ -f "$f" ] || { echo "File not found: $f"; return 1; }
  local ext="${f##*.}"
  local opener="less"
  case "$ext" in
    pdf)    opener="xdg-open" ;;
    html|htm) opener="firefox" ;;
    docx|doc|pptx|ppt|xlsx|xls|odt|ods) opener="libreoffice --norestore" ;;
    *) opener="${PAGER:-less}" ;;
  esac
  $opener "$f" &
}

ask_open() {
  local f="$1"; [ -f "$f" ] || return 1
  echo ""
  printf '%s' "$SPACES"
  printf 'Open the file now? [y/N]: '
  read -r ans || return
  case "$ans" in y|Y|yes|YES) open_file "$f" ;; esac
}

# ============================================================
# DRAW MAIN MENU
# ============================================================
draw_main() {
  redraw

  local rules=$(c_rules) corr=$(c_correlations) hunts=$(c_hunts) incs=$(c_incidents)
  local pb=$(c_playbooks) cov=$(c_coverage) commits=$(c_commits)
  local conv=$(c_converted) last=$(c_last)

  # Top line
  pf '%s%s%s\n' "${BLUE}" "$(printf '━%.0s' $(seq 1 $W))" "${NC}"

  # Brand row
  pf '  %s%sCYBERION DEFENSE LABS%s' "${BOLD}" "${WHITE}" "${NC}"
  # pad to right side: brand is ~22 visible, need to pad to W-30
  printf '%*s' $((W - 50)) ""
  pf '%s●%s %sOPERATIONAL%s  %s│%s  %sv1.0.0%s\n' \
    "${GREEN}" "${NC}" "${WHITE}" "${NC}" "${GREY}" "${NC}" "${GREY}" "${NC}"

  pf '  %sDetection Engineering & Threat Hunting Console%s\n' "${GREY}" "${NC}"
  pf '  %s%s%s\n' "${DIM}" "$(date '+%Y-%m-%d %H:%M:%S')" "${NC}"
  pf '%s%s%s\n' "${BLUE}" "$(printf '━%.0s' $(seq 1 $W))" "${NC}"
  echo ""

  # Status box
  pf '  %s╭─%s%s SYSTEM STATUS %s' "${SKY}" "${BOLD}${WHITE}" "${NC}" "${SKY}"
  printf '%s' "$(printf '─%.0s' $(seq 1 56))"
  pf '%s╮%s\n' "${SKY}" "${NC}"

  _row() {
    local l1="$1" v1="$2" c1="$3" l2="$4" v2="$5" c2="$6"
    pf '  %s│%s  ' "${SKY}" "${NC}"
    printf '%s%-22s%s' "${GREY}" "$l1" "${NC}"
    printf '%s%-5s%s' "${BOLD}${c1}" "$v1" "${NC}"
    printf '  %s%-22s%s' "${GREY}" "$l2" "${NC}"
    printf '%s%-5s%s' "${BOLD}${c2}" "$v2" "${NC}"
    pf '  %s│%s\n' "${SKY}" "${NC}"
  }
  _row "Detection Rules" "$rules" "${GREEN}" "Git Commits" "$commits" "${SKY}"
  _row "Correlation Rules" "$corr" "${MAGENTA}" "ATT&CK Rows" "$cov" "${YELLOW}"
  _row "Threat Hunts" "$hunts" "${SKY}" "Converted Queries" "$conv" "${TEAL}"
  _row "Incident Reports" "$incs" "${ORANGE}" "IR Playbooks" "$pb" "${SKY}"

  pf '  %s╰─%s last commit: %s%s%s\n' "${SKY}" "${NC}" "${DIM}${GREY}" "$last" "${NC}"
  echo ""

  # Menu items — each printed as: label padded to fixed width, then description
  # Total inner width = W - 4 (2 left indent + 2 right)
  local label_w=48   # width reserved for "[N]  Label"

  _mi() {
    local key="$1" label="$2" desc="$3"
    local left="    [$key]  $label"
    local left_vis=${#left}
    local pad=$((label_w - left_vis))
    [ "$pad" -lt 0 ] && pad=0
    pf '%s%s%s' "${WHITE}" "$left" "${NC}"
    printf '%*s' "$pad" ""
    pf '%s%s%s\n' "${GREY}" "$desc" "${NC}"
  }

  _sec() { echo ""; pf '  %s%s%s\n' "${BOLD}" "${BLUE}" "$1"; echo ""; }
  _sec ""    # spacer only

  pf '  %s%sVALIDATION & TESTING%s\n' "${BOLD}" "${BLUE}" "${NC}"
  echo ""
  _mi "1"  "Validate Sigma rules"      "sigma check"
  _mi "2"  "Run full test suite"       "26 checks"
  _mi "3"  "Rule effectiveness"        "matched vs 34,870 events"
  echo ""

  pf '  %s%sCOVERAGE & ANALYSIS%s\n' "${BOLD}" "${BLUE}" "${NC}"
  echo ""
  _mi "4"  "ATT&CK coverage matrix"    "40 techniques"
  _mi "5"  "Rebuild Navigator layer"   "visual heatmap"
  echo ""

  pf '  %s%sREPORTS%s\n' "${BOLD}" "${BLUE}" "${NC}"
  echo ""
  _mi "6"  "Threat hunt reports"       "2 confirmed hunts"
  _mi "7"  "Incident case reports"     "2 true positives"
  _mi "8"  "Executive summary"         "MD / PDF / HTML / DOCX"
  echo ""

  pf '  %s%sOPERATIONS%s\n' "${BOLD}" "${BLUE}" "${NC}"
  echo ""
  _mi "9"  "Convert to Splunk/Lucene/EQL" "108 query files"
  _mi "10" "Git history"               "commit log"
  _mi "11" "Project statistics"        "project snapshot"
  _mi "12" "Presentation"              "PPTX / PDF / HTML / DOCX"
  echo ""

  pf '  %s%sSESSION%s\n' "${BOLD}" "${BLUE}" "${NC}"
  echo ""
  _mi "0"  "Exit"                      "quit console"
  echo ""

  # Footer
  pf '%s%s%s\n' "${GREY}" "$(printf '─%.0s' $(seq 1 $W))" "${NC}"
  pf '  %sENTER%s number  %s│%s  %sq%s quit  %s│%s  %s?%s help\n' \
    "${BOLD}${WHITE}" "${NC}" "${GREY}" "${NC}" \
    "${BOLD}${WHITE}" "${NC}" "${GREY}" "${NC}" \
    "${BOLD}${WHITE}" "${NC}"
  pf '%s%s%s\n' "${GREY}" "$(printf '─%.0s' $(seq 1 $W))" "${NC}"
  echo ""
  pf '  %s%s❯%s Enter selection %s[0-12]%s: ' "${BOLD}" "${SKY}" "${NC}" "${GREY}" "${NC}"
}

# ============================================================
# ACTIONS
# ============================================================

action_1() {
  echo ""; pf '  %s%sSigma Rule Validation%s\n\n' "${BOLD}" "${WHITE}" "${NC}"
  sigma check rules/sigma
  pause
}

action_2() {
  echo ""; pf '  %s%sFull Test Suite%s\n\n' "${BOLD}" "${WHITE}" "${NC}"
  ./tests/run_all_tests.sh
  pause
}

action_3() {
  echo ""; pf '  %s%sRule Effectiveness — 34,870 real events%s\n\n' "${BOLD}" "${WHITE}" "${NC}"
  python3 - <<'PY'
import json
from pathlib import Path
G="\033[38;5;41m"; R="\033[38;5;203m"; B="\033[1m"; NC="\033[0m"; D="\033[2m"
d = json.loads(Path("tests/results/effectiveness.json").read_text())
matched = sum(1 for v in d.values() if v > 0); total = len(d)
print(f"  {'Rule':<54s} {'Matches':>8s}")
print(f"  {'─'*64}")
for k, v in d.items():
    badge = f"{G}● {v:>3d}{NC}" if v > 0 else f"{R}●   0{NC}"
    print(f"  {k[:54]:<54s} {badge}")
print(f"  {'─'*64}")
print(f"  {B}Success: {G}{matched}/{total}{NC} ({matched/total*100:.0f}%)")
PY
  pause
}

action_4() {
  echo ""; pf '  %s%sATT&CK Coverage Matrix%s\n\n' "${BOLD}" "${WHITE}" "${NC}"
  python3 - <<'PY'
import csv
G="\033[38;5;41m"; Y="\033[38;5;220m"; R="\033[38;5;203m"; B="\033[1m"; NC="\033[0m"
rows = list(csv.DictReader(open("coverage/attack_coverage.csv")))
cov = sum(1 for r in rows if r["Status"] == "Covered")
par = sum(1 for r in rows if "Partially" in r["Status"])
nco = sum(1 for r in rows if r["Status"] == "Not Covered")
print(f"  Total: {len(rows)}  |  {G}Covered: {cov}{NC}  |  {Y}Partial: {par}{NC}  |  {R}Not Covered: {nco}{NC}")
print()
print(f"  {B}{'Tactic':<22s} {'Technique':<12s} {'Name':<38s} {'Status'}{NC}")
print(f"  {'─'*88}")
for r in rows:
    st = r["Status"]
    c = G if st == "Covered" else (Y if "Partially" in st else R)
    print(f"  {r['Tactic']:<22s} {r['Technique ID']:<12s} {r['Technique Name'][:36]:<38s} {c}{st}{NC}")
PY
  pause
}

action_5() {
  echo ""; pf '  %s%sRebuild ATT&CK Navigator Layer%s\n\n' "${BOLD}" "${WHITE}" "${NC}"
  python scripts/csv_to_navigator.py
  echo ""
  pf '  %s✓%s coverage/attack_coverage_layer.json\n\n' "${GREEN}" "${NC}"
  pf '  %sView heatmap:%s\n' "${BOLD}" "${NC}"
  pf '    1. Open https://mitre-attack.github.io/attack-navigator/\n'
  pf '    2. Open Existing Layer → Upload from local\n'
  pf '    3. Select %s/coverage/attack_coverage_layer.json\n' "$(pwd)"
  pause
}

action_6() {
  while true; do
    redraw
    pf '  %s%sThreat Hunt Reports%s\n\n' "${BOLD}" "${WHITE}" "${NC}"
    pf '    [1]  Hunt 001 — Suspicious Process Chains\n'
    pf '    [2]  Hunt 002 — C2 Beaconing Candidates\n'
    pf '    [3]  Back\n\n'
    pf '  %sChoose:%s ' "${BOLD}" "${NC}"
    read -r sub || return
    case "$sub" in
      1) less hunts/hunt_001_suspicious_process_chains.md ;;
      2) less hunts/hunt_002_c2_beaconing.md ;;
      3|"") return ;;
    esac
  done
}

action_7() {
  while true; do
    redraw
    pf '  %s%sIncident Case Reports%s\n\n' "${BOLD}" "${WHITE}" "${NC}"
    pf '    [1]  Incident 001 — LSASS Dump + Cobalt Strike\n'
    pf '    [2]  Incident 002 — Masqueraded Office Dropper\n'
    pf '    [3]  Back\n\n'
    pf '  %sChoose:%s ' "${BOLD}" "${NC}"
    read -r sub || return
    case "$sub" in
      1) less incidents/incident_001_lsass_dump_and_cobalt_strike.md ;;
      2) less incidents/incident_002_masqueraded_office_macro.md ;;
      3|"") return ;;
    esac
  done
}

action_8() {
  while true; do
    redraw
    pf '  %s%sExecutive Summary — Export%s\n\n' "${BOLD}" "${WHITE}" "${NC}"
    pf '    [1]  View on screen\n'
    pf '    [2]  Export Markdown       .md\n'
    pf '    [3]  Export PDF            .pdf\n'
    pf '    [4]  Export HTML           .html\n'
    pf '    [5]  Export Word           .docx\n'
    pf '    [6]  Export PowerPoint     .pptx\n'
    pf '    [7]  Export ALL formats\n'
    pf '    [0]  Back\n\n'
    pf '  %sChoose:%s ' "${BOLD}" "${NC}"
    read -r fmt || return
    mkdir -p reports/exports
    case "$fmt" in
      1) less reports/executive_summary.md ;;
      2) cp reports/executive_summary.md reports/exports/executive_summary.md
         echo "  ✓ reports/exports/executive_summary.md"; ask_open reports/exports/executive_summary.md; pause ;;
      3) pandoc reports/executive_summary.md -o reports/exports/executive_summary.pdf --pdf-engine=weasyprint 2>/dev/null && \
           { echo "  ✓ reports/exports/executive_summary.pdf"; ask_open reports/exports/executive_summary.pdf; } || echo "  PDF engine unavailable"
         pause ;;
      4) pandoc reports/executive_summary.md -o reports/exports/executive_summary.html --standalone 2>/dev/null
         echo "  ✓ reports/exports/executive_summary.html"; ask_open reports/exports/executive_summary.html; pause ;;
      5) pandoc reports/executive_summary.md -o reports/exports/executive_summary.docx 2>/dev/null
         echo "  ✓ reports/exports/executive_summary.docx"; ask_open reports/exports/executive_summary.docx; pause ;;
      6) pandoc reports/final_presentation.md -o reports/exports/final_presentation.pptx 2>/dev/null
         echo "  ✓ reports/exports/final_presentation.pptx"; ask_open reports/exports/final_presentation.pptx; pause ;;
      7) cp reports/executive_summary.md reports/exports/executive_summary.md
         pandoc reports/executive_summary.md -o reports/exports/executive_summary.html --standalone 2>/dev/null
         pandoc reports/executive_summary.md -o reports/exports/executive_summary.docx 2>/dev/null
         pandoc reports/executive_summary.md -o reports/exports/executive_summary.pdf --pdf-engine=weasyprint 2>/dev/null
         pandoc reports/final_presentation.md -o reports/exports/final_presentation.pptx 2>/dev/null
         echo "  ✓ all written to reports/exports/"
         ls -1 reports/exports/ 2>/dev/null
         pause ;;
      0|"") return ;;
      *) echo "  Invalid"; sleep 1 ;;
    esac
  done
}

action_9() {
  echo ""; pf '  %s%sConverting Rules to Backend Queries%s\n\n' "${BOLD}" "${WHITE}" "${NC}"
  mkdir -p rules/converted/splunk rules/converted/elastic
  local n=0 total=$(ls rules/sigma/*.yml 2>/dev/null | wc -l | tr -d ' ')
  for f in rules/sigma/*.yml; do
    base=$(basename "$f" .yml)
    sigma convert -t splunk --without-pipeline "$f" > "rules/converted/splunk/${base}.spl" 2>/dev/null || true
    sigma convert -t lucene -p ecs_windows "$f" > "rules/converted/elastic/${base}.lucene" 2>/dev/null || true
    sigma convert -t eql -p ecs_windows "$f" > "rules/converted/elastic/${base}.eql" 2>/dev/null || true
    n=$((n+1)); printf '\r  Converting %d/%d...' "$n" "$total"
  done
  printf '\r  ✓ Converted %d rules           \n\n' "$total"
  pf '    Splunk:  %s files\n' "$(ls rules/converted/splunk/*.spl 2>/dev/null | wc -l)"
  pf '    Lucene:  %s files\n' "$(ls rules/converted/elastic/*.lucene 2>/dev/null | wc -l)"
  pf '    EQL:     %s files\n' "$(ls rules/converted/elastic/*.eql 2>/dev/null | wc -l)"
  pause
}

action_10() {
  echo ""; pf '  %s%sGit History%s\n\n' "${BOLD}" "${WHITE}" "${NC}"
  git log --oneline --decorate --color=always | head -30
  echo ""
  pf '  Total commits: %s\n' "$(git rev-list --count HEAD)"
  pause
}

action_11() {
  echo ""; pf '  %s%sProject Statistics%s\n\n' "${BOLD}" "${WHITE}" "${NC}"
  pf '  %-28s %s\n' "Sigma detection rules"   "$(c_rules)"
  pf '  %-28s %s\n' "Correlation rules"       "$(c_correlations)"
  pf '  %-28s %s\n' "Base rules"              "$(ls rules/sigma/base_*.yml 2>/dev/null | wc -l)"
  pf '  %-28s %s\n' "Converted queries"       "$(c_converted)"
  pf '  %-28s %s\n' "ATT&CK coverage rows"    "$(c_coverage)"
  pf '  %-28s %s\n' "Threat hunts"            "$(c_hunts)"
  pf '  %-28s %s\n' "Incident reports"        "$(c_incidents)"
  pf '  %-28s %s\n' "IR playbooks"            "$(c_playbooks)"
  pf '  %-28s %s\n' "Git-tracked files"       "$(git ls-files | wc -l)"
  pf '  %-28s %s\n' "Git commits"             "$(c_commits)"
  pause
}

action_12() {
  while true; do
    redraw
    pf '  %s%sPresentation — Export%s\n\n' "${BOLD}" "${WHITE}" "${NC}"
    pf '    [1]  View slide outline\n'
    pf '    [2]  Export PowerPoint     .pptx\n'
    pf '    [3]  Export PDF            .pdf\n'
    pf '    [4]  Export HTML           .html\n'
    pf '    [5]  Export Word           .docx\n'
    pf '    [6]  Export Markdown       .md\n'
    pf '    [7]  Export ALL formats\n'
    pf '    [8]  Open existing PPTX\n'
    pf '    [0]  Back\n\n'
    pf '  %sChoose:%s ' "${BOLD}" "${NC}"
    read -r fmt || return
    mkdir -p reports/exports
    case "$fmt" in
      1) less reports/final_presentation.md ;;
      2) pandoc reports/final_presentation.md -o reports/exports/final_presentation.pptx 2>/dev/null
         echo "  ✓ reports/exports/final_presentation.pptx"; ask_open reports/exports/final_presentation.pptx; pause ;;
      3) pandoc reports/final_presentation.md -o reports/exports/final_presentation.pdf --pdf-engine=weasyprint 2>/dev/null && \
           { echo "  ✓ reports/exports/final_presentation.pdf"; ask_open reports/exports/final_presentation.pdf; } || echo "  PDF engine unavailable"
         pause ;;
      4) pandoc reports/final_presentation.md -o reports/exports/final_presentation.html --standalone 2>/dev/null
         echo "  ✓ reports/exports/final_presentation.html"; ask_open reports/exports/final_presentation.html; pause ;;
      5) pandoc reports/final_presentation.md -o reports/exports/final_presentation.docx 2>/dev/null
         echo "  ✓ reports/exports/final_presentation.docx"; ask_open reports/exports/final_presentation.docx; pause ;;
      6) cp reports/final_presentation.md reports/exports/final_presentation.md
         echo "  ✓ reports/exports/final_presentation.md"; ask_open reports/exports/final_presentation.md; pause ;;
      7) cp reports/final_presentation.md reports/exports/final_presentation.md
         pandoc reports/final_presentation.md -o reports/exports/final_presentation.html --standalone 2>/dev/null
         pandoc reports/final_presentation.md -o reports/exports/final_presentation.docx 2>/dev/null
         pandoc reports/final_presentation.md -o reports/exports/final_presentation.pptx 2>/dev/null
         pandoc reports/final_presentation.md -o reports/exports/final_presentation.pdf --pdf-engine=weasyprint 2>/dev/null
         echo "  ✓ all written to reports/exports/"; ls -1 reports/exports/ 2>/dev/null | grep presentation; pause ;;
      8) [ -f reports/exports/final_presentation.pptx ] && ask_open reports/exports/final_presentation.pptx; pause ;;
      0|"") return ;;
      *) echo "  Invalid"; sleep 1 ;;
    esac
  done
}

# ============================================================
# MAIN LOOP
# ============================================================
trap 'echo ""; exit 130' INT

while true; do
  draw_main

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
    *) echo "  Invalid"; sleep 1 ;;
  esac
done
