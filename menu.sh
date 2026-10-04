#!/usr/bin/env bash
# Cyberion Detection Engineering Console - clean centered version

set -uo pipefail
cd "$(dirname "$0")"
[ -d ".venv" ] && source .venv/bin/activate 2>/dev/null || true

# ---------- Colors ----------
BOLD=$'\033[1m'; DIM=$'\033[2m'; NC=$'\033[0m'
BLUE=$'\033[38;5;33m'; SKY=$'\033[38;5;45m'; TEAL=$'\033[38;5;44m'
GREEN=$'\033[38;5;41m'; YELLOW=$'\033[38;5;220m'; RED=$'\033[38;5;203m'
ORANGE=$'\033[38;5;215m'; MAGENTA=$'\033[38;5;177m'
GREY=$'\033[38;5;244m'; WHITE=$'\033[38;5;255m'

# ---------- Fixed content width ----------
W=76

# ---------- Centering helper ----------
# Reads lines from stdin, prints each with left padding
center() {
  local cols pad
  cols=$(tput cols 2>/dev/null || echo 100)
  pad=$(( (cols - W) / 2 ))
  [ "$pad" -lt 0 ] && pad=0
  local spaces
  spaces=$(printf '%*s' "$pad" "")
  while IFS= read -r line; do
    printf '%s%s\n' "$spaces" "$line"
  done
}

# ---------- Data ----------
count_rules()        { ls rules/sigma/*.yml 2>/dev/null | wc -l | tr -d ' '; }
count_correlations() { grep -l '^correlation:' rules/sigma/*.yml 2>/dev/null | wc -l | tr -d ' '; }
count_hunts()        { ls hunts/*.md 2>/dev/null | grep -v template | wc -l | tr -d ' '; }
count_incidents()    { ls incidents/*.md 2>/dev/null | grep -v template | wc -l | tr -d ' '; }
count_playbooks()    { ls playbooks/*.md 2>/dev/null | grep -v template | wc -l | tr -d ' '; }
count_coverage()     { tail -n +2 coverage/attack_coverage.csv 2>/dev/null | wc -l | tr -d ' '; }
count_commits()      { git rev-list --count HEAD 2>/dev/null || echo 0; }
count_converted()    { ls rules/converted/splunk/*.spl rules/converted/elastic/*.lucene rules/converted/elastic/*.eql 2>/dev/null | wc -l | tr -d ' '; }
last_commit()        { git log -1 --format='%s' 2>/dev/null | cut -c1-48; }
now_str()            { date '+%Y-%m-%d %H:%M:%S'; }

# ---------- Frame builder (writes to stdout; caller pipes to center) ----------
build_frame() {
  local rules=$(count_rules) corr=$(count_correlations) hunts=$(count_hunts)
  local incs=$(count_incidents) pb=$(count_playbooks) cov=$(count_coverage)
  local commits=$(count_commits) conv=$(count_converted) last=$(last_commit)

  # Top banner
  printf '%s%s%s\n' "${BLUE}" "$(printf '━%.0s' $(seq 1 $W))" "${NC}"
  printf '  %s%sCYBERION DEFENSE LABS%s%*s%s●%s %sOPERATIONAL%s  %s│%s  %sv1.0.0%s\n' \
    "${BOLD}" "${WHITE}" "${NC}" $((W - 64)) "" "${GREEN}" "${NC}" "${WHITE}" "${NC}" \
    "${GREY}" "${NC}" "${GREY}" "${NC}"
  printf '  %sDetection Engineering & Threat Hunting Console%s\n' "${GREY}" "${NC}"
  printf '  %s%s%s\n' "${DIM}" "$(now_str)" "${NC}"
  printf '%s%s%s\n' "${BLUE}" "$(printf '━%.0s' $(seq 1 $W))" "${NC}"
  echo ""

  # Status box
  printf '  %s╭─%s%s SYSTEM STATUS %s%s%s╮%s\n' \
    "${SKY}" "${BOLD}${WHITE}" "${NC}" "${SKY}" "$(printf '─%.0s' $(seq 1 57))" "${NC}" "${NC}"
  printf '  %s│%s  %s%-22s%s %s%-6s%s    %s%-22s%s %s%-6s%s %s│%s\n' \
    "${SKY}" "${NC}" "${GREY}" "Detection Rules" "${NC}" "${BOLD}${GREEN}" "$rules" "${NC}" \
    "${GREY}" "Git Commits" "${NC}" "${BOLD}${SKY}" "$commits" "${NC}" "${SKY}" "${NC}"
  printf '  %s│%s  %s%-22s%s %s%-6s%s    %s%-22s%s %s%-6s%s %s│%s\n' \
    "${SKY}" "${NC}" "${GREY}" "Correlation Rules" "${NC}" "${BOLD}${MAGENTA}" "$corr" "${NC}" \
    "${GREY}" "ATT&CK Rows" "${NC}" "${BOLD}${YELLOW}" "$cov" "${NC}" "${SKY}" "${NC}"
  printf '  %s│%s  %s%-22s%s %s%-6s%s    %s%-22s%s %s%-6s%s %s│%s\n' \
    "${SKY}" "${NC}" "${GREY}" "Threat Hunts" "${NC}" "${BOLD}${SKY}" "$hunts" "${NC}" \
    "${GREY}" "Converted Queries" "${NC}" "${BOLD}${TEAL}" "$conv" "${NC}" "${SKY}" "${NC}"
  printf '  %s│%s  %s%-22s%s %s%-6s%s    %s%-22s%s %s%-6s%s %s│%s\n' \
    "${SKY}" "${NC}" "${GREY}" "Incident Reports" "${NC}" "${BOLD}${ORANGE}" "$incs" "${NC}" \
    "${GREY}" "IR Playbooks" "${NC}" "${BOLD}${SKY}" "$pb" "${NC}" "${SKY}" "${NC}"
  printf '  %s╰─%s last commit: %s%s%s%s\n' "${SKY}" "${NC}" "${DIM}${GREY}" "$last" "${NC}" "${NC}"
  echo ""

  # Menu sections
  printf '  %s%sVALIDATION & TESTING%s\n' "${BOLD}" "${BLUE}" "${NC}"
  echo ""
  printf '    %s%s[1]%s  %sValidate Sigma rules%s%*ssigma check%s\n' \
    "${BOLD}" "${SKY}" "${NC}" "${WHITE}" "${NC}" $((W - 36)) "" "${GREY}" "${NC}"
  printf '    %s%s[2]%s  %sRun full test suite%s%*s26 checks%s\n' \
    "${BOLD}" "${SKY}" "${NC}" "${WHITE}" "${NC}" $((W - 36)) "" "${GREY}" "${NC}"
  printf '    %s%s[3]%s  %sRule effectiveness%s%*smatched vs 34,870 events%s\n' \
    "${BOLD}" "${SKY}" "${NC}" "${WHITE}" "${NC}" $((W - 36)) "" "${GREY}" "${NC}"
  echo ""

  printf '  %s%sCOVERAGE & ANALYSIS%s\n' "${BOLD}" "${BLUE}" "${NC}"
  echo ""
  printf '    %s%s[4]%s  %sATT&CK coverage matrix%s%*s40 techniques%s\n' \
    "${BOLD}" "${SKY}" "${NC}" "${WHITE}" "${NC}" $((W - 36)) "" "${GREY}" "${NC}"
  printf '    %s%s[5]%s  %sRebuild Navigator layer%s%*svisual heatmap%s\n' \
    "${BOLD}" "${SKY}" "${NC}" "${WHITE}" "${NC}" $((W - 36)) "" "${GREY}" "${NC}"
  echo ""

  printf '  %s%sREPORTS%s\n' "${BOLD}" "${BLUE}" "${NC}"
  echo ""
  printf '    %s%s[6]%s  %sThreat hunt reports%s%*s2 confirmed hunts%s\n' \
    "${BOLD}" "${SKY}" "${NC}" "${WHITE}" "${NC}" $((W - 36)) "" "${GREY}" "${NC}"
  printf '    %s%s[7]%s  %sIncident case reports%s%*s2 true positives%s\n' \
    "${BOLD}" "${SKY}" "${NC}" "${WHITE}" "${NC}" $((W - 36)) "" "${GREY}" "${NC}"
  printf '    %s%s[8]%s  %sExecutive summary%s%*sMD / PDF / HTML / DOCX%s\n' \
    "${BOLD}" "${SKY}" "${NC}" "${WHITE}" "${NC}" $((W - 36)) "" "${GREY}" "${NC}"
  echo ""

  printf '  %s%sOPERATIONS%s\n' "${BOLD}" "${BLUE}" "${NC}"
  echo ""
  printf '    %s%s[9]%s   %sConvert to Splunk/Lucene/EQL%s%*s108 query files%s\n' \
    "${BOLD}" "${SKY}" "${NC}" "${WHITE}" "${NC}" $((W - 37)) "" "${GREY}" "${NC}"
  printf '    %s%s[10]%s  %sGit history%s%*scommit log%s\n' \
    "${BOLD}" "${SKY}" "${NC}" "${WHITE}" "${NC}" $((W - 36)) "" "${GREY}" "${NC}"
  printf '    %s%s[11]%s  %sProject statistics%s%*sproject snapshot%s\n' \
    "${BOLD}" "${SKY}" "${NC}" "${WHITE}" "${NC}" $((W - 36)) "" "${GREY}" "${NC}"
  printf '    %s%s[12]%s  %sPresentation%s%*sPPTX / PDF / HTML / DOCX%s\n' \
    "${BOLD}" "${SKY}" "${NC}" "${WHITE}" "${NC}" $((W - 36)) "" "${GREY}" "${NC}"
  echo ""

  printf '  %s%sSESSION%s\n' "${BOLD}" "${BLUE}" "${NC}"
  echo ""
  printf '    %s%s[0]%s   %sExit%s%*squit console%s\n' \
    "${BOLD}" "${SKY}" "${NC}" "${WHITE}" "${NC}" $((W - 36)) "" "${GREY}" "${NC}"
  echo ""

  # Footer
  printf '%s%s%s\n' "${GREY}" "$(printf '─%.0s' $(seq 1 $W))" "${NC}"
  printf '  %sENTER%s number   %s│%s   %sq%s quit   %s│%s   %s?%s help%s\n' \
    "${BOLD}${WHITE}" "${NC}" "${GREY}" "${NC}" "${BOLD}${WHITE}" "${NC}" \
    "${GREY}" "${NC}" "${BOLD}${WHITE}" "${NC}" "${NC}"
  printf '%s%s%s\n' "${GREY}" "$(printf '─%.0s' $(seq 1 $W))" "${NC}"
}

# ---------- Draw the screen ----------
draw() {
  clear
  build_frame | center
}

# ---------- Pause ----------
pause() {
  echo ""
  printf '  %s↵ Press Enter to return to menu%s' "${DIM}" "${NC}"
  read -r _ || return
}

# ---------- Sub-menu header (centered) ----------
sub_header() {
  clear
  {
    printf '%s%s%s\n' "${BLUE}" "$(printf '━%.0s' $(seq 1 $W))" "${NC}"
    printf '  %s%s%s%s\n' "${BOLD}${WHITE}" "$1" "${NC}" "${NC}"
    printf '%s%s%s\n' "${BLUE}" "$(printf '━%.0s' $(seq 1 $W))" "${NC}"
    echo ""
  } | center
}

sub_footer() {
  echo ""
  printf '  %sChoose:%s ' "${BOLD}" "${NC}"
}

# ---------- Open file ----------
open_file() {
  local f="$1"
  [ -f "$f" ] || { echo "File not found: $f"; return 1; }
  local ext="${f##*.}" opener=""
  case "$ext" in
    md|txt|log|json|yml|yaml) opener="${PAGER:-less}" ;;
    pdf)    command -v xdg-open >/dev/null 2>&1 && opener="xdg-open" || opener="firefox" ;;
    html|htm) command -v firefox >/dev/null 2>&1 && opener="firefox" || opener="xdg-open" ;;
    docx|doc|pptx|ppt|xlsx|xls|odt|ods) command -v libreoffice >/dev/null 2>&1 && opener="libreoffice --norestore" || opener="xdg-open" ;;
    *) opener="xdg-open" ;;
  esac
  $opener "$f" &
}

ask_open() {
  local f="$1"; [ -f "$f" ] || return 1
  echo ""
  printf '  Open the file now? [y/N]: '
  read -r ans || return
  case "$ans" in y|Y|yes|YES) open_file "$f" ;; esac
}

# ============================================================
# ACTIONS
# ============================================================

action_1() {
  echo ""
  echo "  ${BOLD}${WHITE}Sigma Rule Validation${NC}"
  echo ""
  sigma check rules/sigma
  pause
}

action_2() {
  echo ""
  echo "  ${BOLD}${WHITE}Full Test Suite${NC}"
  echo ""
  ./tests/run_all_tests.sh
  pause
}

action_3() {
  echo ""
  echo "  ${BOLD}${WHITE}Rule Effectiveness — 34,870 real events${NC}"
  echo ""
  python3 - <<'PY'
import json
from pathlib import Path
G="\033[38;5;41m"; R="\033[38;5;203m"; B="\033[1m"; NC="\033[0m"
d = json.loads(Path("tests/results/effectiveness.json").read_text())
matched = sum(1 for v in d.values() if v > 0)
total = len(d)
print(f"  {'Rule':<52s} {'Matches':>8s}")
print(f"  {'─'*62}")
for k, v in d.items():
    badge = f"{G}● {v:>3d}{NC}" if v > 0 else f"{R}●   0{NC}"
    print(f"  {k[:52]:<52s} {badge}")
print(f"  {'─'*62}")
print(f"  {B}Success: {G}{matched}/{total}{NC} ({matched/total*100:.0f}%)")
PY
  pause
}

action_4() {
  echo ""
  echo "  ${BOLD}${WHITE}ATT&CK Coverage Matrix${NC}"
  echo ""
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
  echo ""
  echo "  ${BOLD}${WHITE}Rebuild ATT&CK Navigator Layer${NC}"
  echo ""
  python scripts/csv_to_navigator.py
  echo ""
  echo "  ${GREEN}✓${NC} coverage/attack_coverage_layer.json"
  echo ""
  echo "  ${BOLD}View heatmap:${NC}"
  echo "   1. Open https://mitre-attack.github.io/attack-navigator/"
  echo "   2. Open Existing Layer → Upload from local"
  echo "   3. Select $(pwd)/coverage/attack_coverage_layer.json"
  pause
}

action_6() {
  while true; do
    sub_header "Threat Hunt Reports"
    {
      echo "    [1]  Hunt 001 — Suspicious Process Chains"
      echo "    [2]  Hunt 002 — C2 Beaconing Candidates"
      echo "    [3]  Back to main menu"
    } | center
    sub_footer
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
    sub_header "Incident Case Reports"
    {
      echo "    [1]  Incident 001 — LSASS Dump + Cobalt Strike"
      echo "    [2]  Incident 002 — Masqueraded Office Dropper"
      echo "    [3]  Back to main menu"
    } | center
    sub_footer
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
    sub_header "Executive Summary — Export"
    {
      echo "    [1]  View on screen"
      echo "    [2]  Export Markdown       .md"
      echo "    [3]  Export PDF            .pdf"
      echo "    [4]  Export HTML           .html"
      echo "    [5]  Export Word           .docx"
      echo "    [6]  Export PowerPoint     .pptx"
      echo "    [7]  Export ALL formats"
      echo "    [0]  Back"
    } | center
    sub_footer
    read -r fmt || return
    mkdir -p reports/exports
    local out=""
    case "$fmt" in
      1) less reports/executive_summary.md ;;
      2) out="reports/exports/executive_summary.md"; cp reports/executive_summary.md "$out"
         echo "  ✓ $out"; ask_open "$out"; pause ;;
      3) out="reports/exports/executive_summary.pdf"
         pandoc reports/executive_summary.md -o "$out" --pdf-engine=weasyprint 2>/dev/null && \
           { echo "  ✓ $out"; ask_open "$out"; } || echo "  PDF engine unavailable"
         pause ;;
      4) out="reports/exports/executive_summary.html"
         pandoc reports/executive_summary.md -o "$out" --standalone 2>/dev/null
         echo "  ✓ $out"; ask_open "$out"; pause ;;
      5) out="reports/exports/executive_summary.docx"
         pandoc reports/executive_summary.md -o "$out" 2>/dev/null
         echo "  ✓ $out"; ask_open "$out"; pause ;;
      6) out="reports/exports/final_presentation.pptx"
         pandoc reports/final_presentation.md -o "$out" 2>/dev/null
         echo "  ✓ $out"; ask_open "$out"; pause ;;
      7) cp reports/executive_summary.md reports/exports/executive_summary.md
         pandoc reports/executive_summary.md -o reports/exports/executive_summary.html --standalone 2>/dev/null
         pandoc reports/executive_summary.md -o reports/exports/executive_summary.docx 2>/dev/null
         pandoc reports/executive_summary.md -o reports/exports/executive_summary.pdf --pdf-engine=weasyprint 2>/dev/null
         pandoc reports/final_presentation.md -o reports/exports/final_presentation.pptx 2>/dev/null
         echo "  ✓ all exports written to reports/exports/"
         ls -1 reports/exports/ 2>/dev/null
         pause ;;
      0|"") return ;;
      *) echo "  Invalid"; sleep 1 ;;
    esac
  done
}

action_9() {
  echo ""
  echo "  ${BOLD}${WHITE}Converting Rules to Backend Queries${NC}"
  echo ""
  mkdir -p rules/converted/splunk rules/converted/elastic
  local n=0 total=$(ls rules/sigma/*.yml 2>/dev/null | wc -l | tr -d ' ')
  for f in rules/sigma/*.yml; do
    base=$(basename "$f" .yml)
    sigma convert -t splunk --without-pipeline "$f" > "rules/converted/splunk/${base}.spl" 2>/dev/null || true
    sigma convert -t lucene -p ecs_windows "$f" > "rules/converted/elastic/${base}.lucene" 2>/dev/null || true
    sigma convert -t eql -p ecs_windows "$f" > "rules/converted/elastic/${base}.eql" 2>/dev/null || true
    n=$((n+1))
    printf '\r  Converting %d/%d...' "$n" "$total"
  done
  printf '\r  ✓ Converted %d rules           \n' "$total"
  echo ""
  echo "    Splunk:  $(ls rules/converted/splunk/*.spl 2>/dev/null | wc -l) files"
  echo "    Lucene:  $(ls rules/converted/elastic/*.lucene 2>/dev/null | wc -l) files"
  echo "    EQL:     $(ls rules/converted/elastic/*.eql 2>/dev/null | wc -l) files"
  pause
}

action_10() {
  echo ""
  echo "  ${BOLD}${WHITE}Git History${NC}"
  echo ""
  git log --oneline --decorate --color=always | head -30
  echo ""
  echo "  Total commits: $(git rev-list --count HEAD)"
  pause
}

action_11() {
  echo ""
  echo "  ${BOLD}${WHITE}Project Statistics${NC}"
  echo ""
  printf '  %-28s %s\n' "Sigma detection rules"   "$(count_rules)"
  printf '  %-28s %s\n' "Correlation rules"       "$(count_correlations)"
  printf '  %-28s %s\n' "Base rules"              "$(ls rules/sigma/base_*.yml 2>/dev/null | wc -l)"
  printf '  %-28s %s\n' "Converted queries"       "$(count_converted)"
  printf '  %-28s %s\n' "ATT&CK coverage rows"    "$(count_coverage)"
  printf '  %-28s %s\n' "Threat hunts"            "$(count_hunts)"
  printf '  %-28s %s\n' "Incident reports"        "$(count_incidents)"
  printf '  %-28s %s\n' "IR playbooks"            "$(count_playbooks)"
  printf '  %-28s %s\n' "Git-tracked files"       "$(git ls-files | wc -l)"
  printf '  %-28s %s\n' "Git commits"             "$(count_commits)"
  pause
}

action_12() {
  while true; do
    sub_header "Presentation — Export"
    {
      echo "    [1]  View slide outline"
      echo "    [2]  Export PowerPoint     .pptx"
      echo "    [3]  Export PDF            .pdf"
      echo "    [4]  Export HTML           .html"
      echo "    [5]  Export Word           .docx"
      echo "    [6]  Export Markdown       .md"
      echo "    [7]  Export ALL formats"
      echo "    [8]  Open existing PPTX"
      echo "    [0]  Back"
    } | center
    sub_footer
    read -r fmt || return
    mkdir -p reports/exports
    local out=""
    case "$fmt" in
      1) less reports/final_presentation.md ;;
      2) out="reports/exports/final_presentation.pptx"
         pandoc reports/final_presentation.md -o "$out" 2>/dev/null
         echo "  ✓ $out"; ask_open "$out"; pause ;;
      3) out="reports/exports/final_presentation.pdf"
         pandoc reports/final_presentation.md -o "$out" --pdf-engine=weasyprint 2>/dev/null && \
           { echo "  ✓ $out"; ask_open "$out"; } || echo "  PDF engine unavailable"
         pause ;;
      4) out="reports/exports/final_presentation.html"
         pandoc reports/final_presentation.md -o "$out" --standalone 2>/dev/null
         echo "  ✓ $out"; ask_open "$out"; pause ;;
      5) out="reports/exports/final_presentation.docx"
         pandoc reports/final_presentation.md -o "$out" 2>/dev/null
         echo "  ✓ $out"; ask_open "$out"; pause ;;
      6) out="reports/exports/final_presentation.md"
         cp reports/final_presentation.md "$out"
         echo "  ✓ $out"; ask_open "$out"; pause ;;
      7) cp reports/final_presentation.md reports/exports/final_presentation.md
         pandoc reports/final_presentation.md -o reports/exports/final_presentation.html --standalone 2>/dev/null
         pandoc reports/final_presentation.md -o reports/exports/final_presentation.docx 2>/dev/null
         pandoc reports/final_presentation.md -o reports/exports/final_presentation.pptx 2>/dev/null
         pandoc reports/final_presentation.md -o reports/exports/final_presentation.pdf --pdf-engine=weasyprint 2>/dev/null
         echo "  ✓ all exports written to reports/exports/"
         ls -1 reports/exports/ 2>/dev/null | grep presentation
         pause ;;
      8) [ -f reports/exports/final_presentation.pptx ] && ask_open reports/exports/final_presentation.pptx
         pause ;;
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
  draw

  # Center the prompt too
  cols=$(tput cols 2>/dev/null || echo 100)
  pad=$(( (cols - W) / 2 ))
  [ "$pad" -lt 0 ] && pad=0
  sp=$(printf '%*s' "$pad" "")

  printf '%s  %s❯%s Enter selection %s[0-12]%s: ' \
    "$sp" "${BOLD}${SKY}" "${NC}" "${GREY}" "${NC}"

  if ! IFS= read -r choice; then
    echo ""
    exit 0
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
