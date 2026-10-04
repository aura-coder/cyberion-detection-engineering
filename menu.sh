#!/usr/bin/env bash
# ============================================================
# Cyberion Defense Labs - Detection Engineering Console
# Enterprise terminal UI v3.0
# ============================================================

set -uo pipefail
cd "$(dirname "$0")"

if [ -d ".venv" ]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate 2>/dev/null || true
fi

# ---------- Fixed layout ----------
W=78                                # inner width
LINE_HEAVY="━"
LINE_LIGHT="─"
LINE_DOT="·"

# ---------- Colors (professional palette) ----------
if [ -t 1 ]; then
  BOLD=$'\033[1m'; DIM=$'\033[2m'; NC=$'\033[0m'
  # Brand
  BLUE=$'\033[38;5;33m'           # strong blue
  SKY=$'\033[38;5;45m'            # sky blue
  TEAL=$'\033[38;5;44m'
  # Status
  GREEN=$'\033[38;5;41m'
  YELLOW=$'\033[38;5;220m'
  RED=$'\033[38;5;203m'
  ORANGE=$'\033[38;5;215m'
  # Text
  GREY=$'\033[38;5;244m'
  LGREY=$'\033[38;5;250m'
  WHITE=$'\033[38;5;255m'
  # Accents
  MAGENTA=$'\033[38;5;177m'
else
  BOLD=""; DIM=""; NC=""
  BLUE=""; SKY=""; TEAL=""
  GREEN=""; YELLOW=""; RED=""; ORANGE=""
  GREY=""; LGREY=""; WHITE=""
  MAGENTA=""
fi

# ---------- Utilities ----------
pause() {
  echo ""
  printf '  %s↵ Press Enter to return to main menu%s' "${DIM}" "${NC}"
  read -r _
}

pad_right() {
  # pad a string to fixed width (accounting for visible chars)
  local s="$1"; local w="$2"
  local visible
  visible=$(printf '%s' "$s" | sed 's/\x1b\[[0-9;]*m//g' | wc -c)
  local pad=$((w - visible + 1))
  [ "$pad" -lt 0 ] && pad=0
  printf '%s%*s' "$s" "$pad" ""
}

# ---------- Timestamp / uptime ----------
now_str() { date '+%Y-%m-%d %H:%M:%S'; }
start_ts_file=".menu_start_ts"
if [ ! -f "$start_ts_file" ]; then date +%s > "$start_ts_file"; fi
uptime_str() {
  local start now diff
  start=$(cat "$start_ts_file" 2>/dev/null || date +%s)
  now=$(date +%s)
  diff=$((now - start))
  local h=$((diff/3600)) m=$(((diff%3600)/60)) s=$((diff%60))
  printf '%02dh %02dm %02ds' "$h" "$m" "$s"
}

# ---------- Data helpers ----------
count_rules()        { ls rules/sigma/*.yml 2>/dev/null | wc -l | tr -d ' '; }
count_correlations() { grep -l '^correlation:' rules/sigma/*.yml 2>/dev/null | wc -l | tr -d ' '; }
count_hunts()        { ls hunts/*.md 2>/dev/null | grep -v template | wc -l | tr -d ' '; }
count_incidents()    { ls incidents/*.md 2>/dev/null | grep -v template | wc -l | tr -d ' '; }
count_playbooks()    { ls playbooks/*.md 2>/dev/null | grep -v template | wc -l | tr -d ' '; }
count_coverage()     { tail -n +2 coverage/attack_coverage.csv 2>/dev/null | wc -l | tr -d ' '; }
count_commits()      { git rev-list --count HEAD 2>/dev/null || echo 0; }
count_converted()    { ls rules/converted/splunk/*.spl rules/converted/elastic/*.lucene rules/converted/elastic/*.eql 2>/dev/null | wc -l | tr -d ' '; }
last_commit()        { git log -1 --format='%s' 2>/dev/null | cut -c1-42; }

# ---------- Drawing primitives ----------
draw_hline_heavy() {
  printf '%s%s%s\n' "${BLUE}" "$(printf "${LINE_HEAVY}%.0s" $(seq 1 $W))" "${NC}"
}
draw_hline_light() {
  printf '%s%s%s\n' "${GREY}" "$(printf "${LINE_LIGHT}%.0s" $(seq 1 $W))" "${NC}"
}

# ---------- Header ----------
draw_header() {
  clear
  echo ""
  draw_hline_heavy

  # Row 1: brand + status
  local left="  ${BOLD}${WHITE}CYBERION DEFENSE LABS${NC}"
  local right="${GREEN}●${NC} ${LGREY}OPERATIONAL${NC}  ${GREY}│${NC}  ${LGREY}v1.0.0${NC}  "
  local left_vis=24
  local right_vis=41
  local gap=$((W - left_vis - right_vis))
  printf '%s%*s%s\n' "$left" "$gap" "" "$right"

  # Row 2: subtitle
  printf '  %sDetection Engineering & Threat Hunting Console%s\n' "${GREY}" "${NC}"
  printf '  %s%s%s\n' "${DIM}${GREY}" "$(now_str) │ uptime $(uptime_str)" "${NC}"

  draw_hline_heavy
  echo ""
}

# ---------- Status box ----------
draw_status_box() {
  local rules=$(count_rules)
  local corr=$(count_correlations)
  local hunts=$(count_hunts)
  local incs=$(count_incidents)
  local pb=$(count_playbooks)
  local cov=$(count_coverage)
  local commits=$(count_commits)
  local conv=$(count_converted)
  local last=$(last_commit)

  printf '  %s╭─ %sSYSTEM STATUS%s %s%s─%s╮%s\n' \
    "${BLUE}" "${BOLD}${WHITE}" "${NC}" "${BLUE}" \
    "$(printf "${LINE_LIGHT}%.0s" $(seq 1 30))" "${NC}" "${BLUE}" "${NC}"

  printf '  %s│%s %s%-20s%s %s%-8s%s  %s%-18s%s %s%-8s%s %s│%s\n' \
    "${BLUE}" "${NC}" \
    "${GREY}" "Detection Rules" "${NC}" "${BOLD}${GREEN}" "$rules" "${NC}" \
    "${GREY}" "Git Commits" "${NC}" "${BOLD}${SKY}" "$commits" "${NC}" \
    "${BLUE}" "${NC}"

  printf '  %s│%s %s%-20s%s %s%-8s%s  %s%-18s%s %s%-8s%s %s│%s\n' \
    "${BLUE}" "${NC}" \
    "${GREY}" "Correlation Rules" "${NC}" "${BOLD}${MAGENTA}" "$corr" "${NC}" \
    "${GREY}" "ATT&CK Rows" "${NC}" "${BOLD}${YELLOW}" "$cov" "${NC}" \
    "${BLUE}" "${NC}"

  printf '  %s│%s %s%-20s%s %s%-8s%s  %s%-18s%s %s%-8s%s %s│%s\n' \
    "${BLUE}" "${NC}" \
    "${GREY}" "Threat Hunts" "${NC}" "${BOLD}${SKY}" "$hunts" "${NC}" \
    "${GREY}" "Converted Queries" "${NC}" "${BOLD}${TEAL}" "$conv" "${NC}" \
    "${BLUE}" "${NC}"

  printf '  %s│%s %s%-20s%s %s%-8s%s  %s%-18s%s %s%-8s%s %s│%s\n' \
    "${BLUE}" "${NC}" \
    "${GREY}" "Incident Reports" "${NC}" "${BOLD}${ORANGE}" "$incs" "${NC}" \
    "${GREY}" "IR Playbooks" "${NC}" "${BOLD}${SKY}" "$pb" "${NC}" \
    "${BLUE}" "${NC}"

  printf '  %s╰─ %slast commit%s %s%s%s%s\n' \
    "${BLUE}" "${BOLD}${WHITE}" "${NC}" "${DIM}${LGREY}" "$last" "${NC}" "${BLUE}" "${NC}"

  echo ""
}

# ---------- Menu items ----------
menu_row() {
  local key="$1" label="$2" desc="$3"
  local key_col="[$key]"
  local label_width=42
  local label_padded
  label_padded=$(printf '%-*s' "$label_width" "$label")
  printf '    %s%s%-4s%s %s%s%s %s%s%s\n' \
    "${BOLD}" "${SKY}" "$key_col" "${NC}" \
    "${LGREY}" "$label_padded" "${NC}" \
    "${DIM}${GREY}" "$desc" "${NC}"
}

draw_section() {
  local name="$1"
  printf '  %s%s%s\n' "${BOLD}${BLUE}" "$name" "${NC}"
  echo ""
}

draw_menu() {
  draw_section "VALIDATION & TESTING"
  menu_row "1" "Validate Sigma rules"            "sigma check"
  menu_row "2" "Run full test suite"             "26 checks"
  menu_row "3" "Rule effectiveness"              "matched vs 34,870 events"
  echo ""

  draw_section "COVERAGE & ANALYSIS"
  menu_row "4" "ATT&CK coverage matrix"          "40 techniques"
  menu_row "5" "Rebuild Navigator layer"         "visual heatmap"
  echo ""

  draw_section "REPORTS"
  menu_row "6" "Threat hunt reports"             "2 confirmed hunts"
  menu_row "7" "Incident case reports"           "2 true positives"
  menu_row "8" "Executive summary"               "MD / PDF / HTML / DOCX"
  echo ""

  draw_section "OPERATIONS"
  menu_row "9"  "Convert to Splunk/Lucene/EQL"   "108 query files"
  menu_row "10" "Git history"                    "commit log"
  menu_row "11" "Project statistics"             "project snapshot"
  menu_row "12" "Presentation"                   "PPTX / PDF / HTML / DOCX"
  echo ""

  draw_section "SESSION"
  menu_row "0"  "Exit"                           "quit console"
  echo ""
}

# ---------- Footer ----------
draw_footer() {
  draw_hline_light
  printf '  %sENTER%s number   %s│%s   %sq%s quit   %s│%s   %s?%s help\n' \
    "${BOLD}${WHITE}" "${NC}" "${GREY}" "${NC}" \
    "${BOLD}${WHITE}" "${NC}" "${GREY}" "${NC}" \
    "${BOLD}${WHITE}" "${NC}"
  draw_hline_light
}

# ---------- Spinner ----------
spin_cmd() {
  local msg="$1" cmd="$2"
  local frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
  local i=0
  ( eval "$cmd" ) > /tmp/spin_out.txt 2>&1 &
  local pid=$!
  printf '  %s⠋%s %s' "${SKY}" "${NC}" "$msg"
  while kill -0 "$pid" 2>/dev/null; do
    printf '\r  %s%s%s %s' "${SKY}" "${frames[$i]}" "${NC}" "$msg"
    i=$(( (i + 1) % ${#frames[@]} ))
    sleep 0.08
  done
  wait "$pid" 2>/dev/null
  local rc=$?
  if [ $rc -eq 0 ]; then
    printf '\r  %s✓%s %s%s\n' "${GREEN}" "${NC}" "$msg" "                              "
  else
    printf '\r  %s✗%s %s%s\n' "${RED}" "${NC}" "$msg" "                              "
  fi
  cat /tmp/spin_out.txt
}

# ---------- Open file ----------
open_file() {
  local f="$1"
  [ -f "$f" ] || { echo "  ${RED}File not found: $f${NC}"; return 1; }
  local ext="${f##*.}"
  local opener=""
  case "$ext" in
    md|txt|log|json|yml|yaml) opener="${PAGER:-less}" ;;
    pdf)     command -v xdg-open >/dev/null 2>&1 && opener="xdg-open" || opener="firefox" ;;
    html|htm) command -v firefox >/dev/null 2>&1 && opener="firefox" || opener="xdg-open" ;;
    docx|doc|pptx|ppt|xlsx|xls|odt|ods)
      command -v libreoffice >/dev/null 2>&1 && opener="libreoffice --norestore" || opener="xdg-open" ;;
    *)       opener="xdg-open" ;;
  esac
  echo "  ${SKY}→  opening with $opener${NC}"
  # shellcheck disable=SC2086
  $opener "$f" &
}

ask_open() {
  local f="$1"
  [ -f "$f" ] || return 1
  echo ""
  printf '  %sOpen the file now?%s %s[y/N]:%s ' "${BOLD}${WHITE}" "${NC}" "${GREY}" "${NC}"
  read -r ans
  case "$ans" in y|Y|yes|YES) open_file "$f" ;; esac
}

# ============================================================
# ACTION HANDLERS
# ============================================================

action_1() {
  echo ""
  echo "  ${BOLD}${WHITE}Sigma Rule Validation${NC}"
  draw_hline_light
  echo ""
  spin_cmd "Parsing and checking 33 Sigma rules" "sigma check rules/sigma 2>&1 | grep -v '^Parsing\|^Checking'"
  pause
}

action_2() {
  echo ""
  echo "  ${BOLD}${WHITE}Full Test Suite${NC}"
  draw_hline_light
  echo ""
  ./tests/run_all_tests.sh
  pause
}

action_3() {
  echo ""
  echo "  ${BOLD}${WHITE}Rule Effectiveness — vs 34,870 real events${NC}"
  draw_hline_light
  echo ""
  python3 - <<'PY'
import json
from pathlib import Path

G="\033[38;5;41m"; R="\033[38;5;203m"; Y="\033[38;5;220m"
B="\033[1m"; NC="\033[0m"; D="\033[2m"; GREY="\033[38;5;244m"
SKY="\033[38;5;45m"

d = json.loads(Path("tests/results/effectiveness.json").read_text())
matched = sum(1 for v in d.values() if v > 0)
total = len(d)

print(f"  {GREY}{'─'*72}{NC}")
print(f"  {B}{'Rule':<56s}{'Matches':>10s}{NC}")
print(f"  {GREY}{'─'*72}{NC}")
for k, v in d.items():
    if v > 0:
        badge = f"{G}● {v:>3d}{NC}"
    else:
        badge = f"{R}●   0{NC}"
    name = k[:54]
    print(f"  {name:<56s} {badge}")
print(f"  {GREY}{'─'*72}{NC}")
print()
pct = matched/total*100 if total else 0
print(f"  {B}Success:{NC}  {G}{B}{matched}/{total}{NC}  {D}({pct:.0f}%){NC}")
PY
  pause
}

action_4() {
  echo ""
  echo "  ${BOLD}${WHITE}ATT&CK Coverage Matrix${NC}"
  draw_hline_light
  echo ""
  python3 - <<'PY'
import csv
from pathlib import Path

B="\033[1m"; NC="\033[0m"; D="\033[2m"
G="\033[38;5;41m"; Y="\033[38;5;220m"; R="\033[38;5;203m"
GREY="\033[38;5;244m"

rows = list(csv.DictReader(open("coverage/attack_coverage.csv")))
covered = sum(1 for r in rows if r["Status"] == "Covered")
partial = sum(1 for r in rows if "Partially" in r["Status"])
notcov  = sum(1 for r in rows if r["Status"] == "Not Covered")

print(f"  {B}Total assessed:{NC} {len(rows)} techniques")
print(f"  {G}●{NC} Covered:            {B}{G}{covered}{NC}")
print(f"  {Y}●{NC} Partially Covered:  {B}{Y}{partial}{NC}")
print(f"  {R}●{NC} Not Covered:        {B}{R}{notcov}{NC}")
print()
print(f"  {GREY}{'─'*90}{NC}")
print(f"  {B}{'Tactic':<22s} {'Technique':<12s} {'Name':<40s} {'Status'}{NC}")
print(f"  {GREY}{'─'*90}{NC}")
for r in rows:
    st = r["Status"]
    if st == "Covered":       color = G
    elif "Partially" in st:   color = Y
    else:                      color = R
    name = r["Technique Name"][:38]
    print(f"  {r['Tactic']:<22s} {r['Technique ID']:<12s} {name:<40s} {color}{st}{NC}")
PY
  pause
}

action_5() {
  echo ""
  echo "  ${BOLD}${WHITE}ATT&CK Navigator Layer${NC}"
  draw_hline_light
  echo ""
  python scripts/csv_to_navigator.py
  echo ""
  echo "  ${GREEN}✓${NC}  Generated: ${LGREY}coverage/attack_coverage_layer.json${NC}"
  echo ""
  echo "  ${BOLD}How to view the heatmap${NC}"
  echo "  ${SKY}1.${NC} Open: ${SKY}https://mitre-attack.github.io/attack-navigator/${NC}"
  echo "  ${SKY}2.${NC} Click ${BOLD}Open Existing Layer${NC} → ${BOLD}Upload from local${NC}"
  echo "  ${SKY}3.${NC} Select: ${DIM}$(pwd)/coverage/attack_coverage_layer.json${NC}"
  pause
}

action_6() {
  while true; do
    draw_header
    echo "  ${BOLD}${WHITE}Threat Hunt Reports${NC}"
    draw_hline_light
    echo ""
    echo "    ${SKY}[1]${NC}  ${LGREY}Hunt 001 — Suspicious Process Chains${NC}"
    echo "    ${SKY}[2]${NC}  ${LGREY}Hunt 002 — C2 Beaconing Candidates${NC}"
    echo "    ${SKY}[3]${NC}  ${DIM}Back to main menu${NC}"
    echo ""
    printf '  %sChoose [1-3]:%s ' "${BOLD}" "${NC}"
    read -r sub
    case "$sub" in
      1) less hunts/hunt_001_suspicious_process_chains.md ;;
      2) less hunts/hunt_002_c2_beaconing.md ;;
      *) return ;;
    esac
  done
}

action_7() {
  while true; do
    draw_header
    echo "  ${BOLD}${WHITE}Incident Case Reports${NC}"
    draw_hline_light
    echo ""
    echo "    ${ORANGE}[1]${NC}  ${LGREY}Incident 001 — LSASS Dump + Cobalt Strike${NC}"
    echo "    ${ORANGE}[2]${NC}  ${LGREY}Incident 002 — Masqueraded Office Dropper${NC}"
    echo "    ${ORANGE}[3]${NC}  ${DIM}Back to main menu${NC}"
    echo ""
    printf '  %sChoose [1-3]:%s ' "${BOLD}" "${NC}"
    read -r sub
    case "$sub" in
      1) less incidents/incident_001_lsass_dump_and_cobalt_strike.md ;;
      2) less incidents/incident_002_masqueraded_office_macro.md ;;
      *) return ;;
    esac
  done
}

action_8() {
  while true; do
    draw_header
    echo "  ${BOLD}${WHITE}Executive Summary — Export${NC}"
    draw_hline_light
    echo ""
    echo "    ${DIM}Source:${NC} reports/executive_summary.md  ${DIM}($(wc -l < reports/executive_summary.md) lines)${NC}"
    echo ""
    echo "    ${SKY}[1]${NC}  View on screen"
    echo "    ${SKY}[2]${NC}  Export Markdown                ${DIM}.md${NC}"
    echo "    ${SKY}[3]${NC}  Export PDF                     ${DIM}.pdf${NC}"
    echo "    ${SKY}[4]${NC}  Export HTML                    ${DIM}.html${NC}"
    echo "    ${SKY}[5]${NC}  Export Word                    ${DIM}.docx${NC}"
    echo "    ${SKY}[6]${NC}  Export PowerPoint              ${DIM}.pptx${NC}"
    echo "    ${SKY}[7]${NC}  Export ALL formats"
    echo "    ${SKY}[0]${NC}  Back"
    echo ""
    printf '  %sChoose [0-7]:%s ' "${BOLD}" "${NC}"
    read -r fmt

    mkdir -p reports/exports
    local out=""

    case "$fmt" in
      1) less reports/executive_summary.md; continue ;;
      2) out="reports/exports/executive_summary.md"; cp reports/executive_summary.md "$out"
         echo "  ${GREEN}✓${NC} $out"; ask_open "$out"; pause ;;
      3) out="reports/exports/executive_summary.pdf"
         if pandoc reports/executive_summary.md -o "$out" --pdf-engine=weasyprint 2>/dev/null; then
           echo "  ${GREEN}✓${NC} $out"; ask_open "$out"
         else
           echo "  ${YELLOW}PDF engine unavailable${NC}"
         fi; pause ;;
      4) out="reports/exports/executive_summary.html"
         pandoc reports/executive_summary.md -o "$out" --standalone --metadata title="Executive Summary" 2>/dev/null
         echo "  ${GREEN}✓${NC} $out"; ask_open "$out"; pause ;;
      5) out="reports/exports/executive_summary.docx"
         pandoc reports/executive_summary.md -o "$out" 2>/dev/null
         echo "  ${GREEN}✓${NC} $out"; ask_open "$out"; pause ;;
      6) out="reports/exports/final_presentation.pptx"
         pandoc reports/final_presentation.md -o "$out" 2>/dev/null
         echo "  ${GREEN}✓${NC} $out"; ask_open "$out"; pause ;;
      7) local gen=()
         cp reports/executive_summary.md reports/exports/executive_summary.md
         gen+=("reports/exports/executive_summary.md"); echo "  ${GREEN}✓${NC} Markdown"
         pandoc reports/executive_summary.md -o reports/exports/executive_summary.html --standalone 2>/dev/null && { gen+=("reports/exports/executive_summary.html"); echo "  ${GREEN}✓${NC} HTML"; }
         pandoc reports/executive_summary.md -o reports/exports/executive_summary.docx 2>/dev/null && { gen+=("reports/exports/executive_summary.docx"); echo "  ${GREEN}✓${NC} DOCX"; }
         pandoc reports/executive_summary.md -o reports/exports/executive_summary.pdf --pdf-engine=weasyprint 2>/dev/null && { gen+=("reports/exports/executive_summary.pdf"); echo "  ${GREEN}✓${NC} PDF"; }
         pandoc reports/final_presentation.md -o reports/exports/final_presentation.pptx 2>/dev/null && { gen+=("reports/exports/final_presentation.pptx"); echo "  ${GREEN}✓${NC} PPTX"; }
         echo ""
         local i=1
         for g in "${gen[@]}"; do echo "    ${BOLD}$i)${NC} $g"; i=$((i+1)); done
         printf '  %sOpen which? [1-%s, 0=skip]:%s ' "${BOLD}" "${#gen[@]}" "${NC}"
         read -r pick
         if [[ "$pick" =~ ^[0-9]+$ ]] && [ "$pick" -ge 1 ] && [ "$pick" -le "${#gen[@]}" ]; then
           ask_open "${gen[$((pick-1))]}"
         fi
         pause ;;
      0|"") return ;;
      *) echo "  ${RED}Invalid.${NC}"; sleep 1 ;;
    esac
  done
}

action_9() {
  echo ""
  echo "  ${BOLD}${WHITE}Converting Rules to Backend Queries${NC}"
  draw_hline_light
  echo ""
  mkdir -p rules/converted/splunk rules/converted/elastic
  local total
  total=$(ls rules/sigma/*.yml 2>/dev/null | wc -l | tr -d ' ')
  local n=0
  for f in rules/sigma/*.yml; do
    base=$(basename "$f" .yml)
    sigma convert -t splunk --without-pipeline "$f" > "rules/converted/splunk/${base}.spl" 2>/dev/null || true
    sigma convert -t lucene -p ecs_windows "$f" > "rules/converted/elastic/${base}.lucene" 2>/dev/null || true
    sigma convert -t eql -p ecs_windows "$f" > "rules/converted/elastic/${base}.eql" 2>/dev/null || true
    n=$((n+1))
    printf '\r  %s⠋%s Converting %d/%d...' "${SKY}" "${NC}" "$n" "$total"
  done
  printf '\r  %s✓%s Converted %d rules          \n' "${GREEN}${BOLD}" "${NC}" "$total"
  echo ""
  printf '  %s%-20s%s %s%d files%s\n' "${GREY}" "Splunk SPL" "${NC}" "${BOLD}${SKY}" "$(ls rules/converted/splunk/*.spl 2>/dev/null | wc -l)" "${NC}"
  printf '  %s%-20s%s %s%d files%s\n' "${GREY}" "Elastic Lucene" "${NC}" "${BOLD}${SKY}" "$(ls rules/converted/elastic/*.lucene 2>/dev/null | wc -l)" "${NC}"
  printf '  %s%-20s%s %s%d files%s\n' "${GREY}" "Elastic EQL" "${NC}" "${BOLD}${SKY}" "$(ls rules/converted/elastic/*.eql 2>/dev/null | wc -l)" "${NC}"
  pause
}

action_10() {
  echo ""
  echo "  ${BOLD}${WHITE}Git History${NC}"
  draw_hline_light
  echo ""
  git log --oneline --decorate --color=always | head -30
  echo ""
  printf '  %sTotal commits: %s%s%s\n' "${GREY}" "${BOLD}${SKY}" "$(git rev-list --count HEAD)" "${NC}"
  pause
}

action_11() {
  echo ""
  echo "  ${BOLD}${WHITE}Project Statistics${NC}"
  draw_hline_light
  echo ""
  printf '  %-28s %s\n' "Sigma detection rules"   "$(count_rules)"
  printf '  %-28s %s\n' "Correlation rules"       "$(count_correlations)"
  printf '  %-28s %s\n' "Base rules (primitives)" "$(ls rules/sigma/base_*.yml 2>/dev/null | wc -l)"
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
    draw_header
    echo "  ${BOLD}${WHITE}Presentation — Export${NC}"
    draw_hline_light
    echo ""
    echo "    ${DIM}Source:${NC} reports/final_presentation.md  ${DIM}($(grep -c '^## Slide' reports/final_presentation.md 2>/dev/null || echo 0) slides)${NC}"
    echo ""
    echo "    ${MAGENTA}[1]${NC}  View slide outline"
    echo "    ${MAGENTA}[2]${NC}  Export PowerPoint               ${DIM}.pptx${NC}"
    echo "    ${MAGENTA}[3]${NC}  Export PDF                      ${DIM}.pdf${NC}"
    echo "    ${MAGENTA}[4]${NC}  Export HTML                     ${DIM}.html${NC}"
    echo "    ${MAGENTA}[5]${NC}  Export Word                     ${DIM}.docx${NC}"
    echo "    ${MAGENTA}[6]${NC}  Export Markdown                 ${DIM}.md${NC}"
    echo "    ${MAGENTA}[7]${NC}  Export ALL formats"
    echo "    ${MAGENTA}[8]${NC}  Open existing PPTX"
    echo "    ${MAGENTA}[0]${NC}  Back"
    echo ""
    printf '  %sChoose [0-8]:%s ' "${BOLD}" "${NC}"
    read -r fmt

    mkdir -p reports/exports
    local out=""

    case "$fmt" in
      1) less reports/final_presentation.md; continue ;;
      2) out="reports/exports/final_presentation.pptx"
         pandoc reports/final_presentation.md -o "$out" 2>/dev/null
         echo "  ${GREEN}✓${NC} $out"; ask_open "$out"; pause ;;
      3) out="reports/exports/final_presentation.pdf"
         if pandoc reports/final_presentation.md -o "$out" --pdf-engine=weasyprint 2>/dev/null; then
           echo "  ${GREEN}✓${NC} $out"; ask_open "$out"
         else echo "  ${YELLOW}PDF engine unavailable${NC}"; fi; pause ;;
      4) out="reports/exports/final_presentation.html"
         pandoc reports/final_presentation.md -o "$out" --standalone 2>/dev/null
         echo "  ${GREEN}✓${NC} $out"; ask_open "$out"; pause ;;
      5) out="reports/exports/final_presentation.docx"
         pandoc reports/final_presentation.md -o "$out" 2>/dev/null
         echo "  ${GREEN}✓${NC} $out"; ask_open "$out"; pause ;;
      6) out="reports/exports/final_presentation.md"
         cp reports/final_presentation.md "$out"
         echo "  ${GREEN}✓${NC} $out"; ask_open "$out"; pause ;;
      7) local gen=()
         cp reports/final_presentation.md reports/exports/final_presentation.md
         gen+=("reports/exports/final_presentation.md"); echo "  ${GREEN}✓${NC} Markdown"
         pandoc reports/final_presentation.md -o reports/exports/final_presentation.html --standalone 2>/dev/null && { gen+=("reports/exports/final_presentation.html"); echo "  ${GREEN}✓${NC} HTML"; }
         pandoc reports/final_presentation.md -o reports/exports/final_presentation.docx 2>/dev/null && { gen+=("reports/exports/final_presentation.docx"); echo "  ${GREEN}✓${NC} DOCX"; }
         pandoc reports/final_presentation.md -o reports/exports/final_presentation.pptx 2>/dev/null && { gen+=("reports/exports/final_presentation.pptx"); echo "  ${GREEN}✓${NC} PPTX"; }
         pandoc reports/final_presentation.md -o reports/exports/final_presentation.pdf --pdf-engine=weasyprint 2>/dev/null && { gen+=("reports/exports/final_presentation.pdf"); echo "  ${GREEN}✓${NC} PDF"; }
         echo ""
         local i=1
         for g in "${gen[@]}"; do echo "    ${BOLD}$i)${NC} $g"; i=$((i+1)); done
         printf '  %sOpen which? [1-%s, 0=skip]:%s ' "${BOLD}" "${#gen[@]}" "${NC}"
         read -r pick
         if [[ "$pick" =~ ^[0-9]+$ ]] && [ "$pick" -ge 1 ] && [ "$pick" -le "${#gen[@]}" ]; then
           ask_open "${gen[$((pick-1))]}"
         fi
         pause ;;
      8) ask_open reports/exports/final_presentation.pptx 2>/dev/null || ask_open reports/final_presentation.pptx; pause ;;
      0|"") return ;;
      *) echo "  ${RED}Invalid.${NC}"; sleep 1 ;;
    esac
  done
}

# ============================================================
# MAIN
# ============================================================

trap 'echo ""; echo "  ${DIM}Session ended.${NC}"; rm -f "$start_ts_file"; exit 130' INT

while true; do
  draw_header
  draw_status_box
  draw_menu
  draw_footer
  echo ""
  printf '  %s%s❯%s Enter selection %s[0-12]%s: ' "${BOLD}" "${SKY}" "${NC}" "${GREY}" "${NC}"
  read -r choice
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
    0|q|Q|exit)
      clear
      echo ""
      echo "  ${SKY}${BOLD}Cyberion Detection Engineering Console${NC}"
      echo "  ${GREY}Session closed.${NC}"
      echo ""
      rm -f "$start_ts_file"
      exit 0 ;;
    "?")
      clear
      echo ""
      echo "  ${BOLD}${WHITE}Help${NC}"
      draw_hline_light
      echo ""
      echo "  ${SKY}Enter${NC}  a number 0-12 to run that action"
      echo "  ${SKY}q${NC}      quit the console"
      echo "  ${SKY}?${NC}      show this help"
      echo ""
      echo "  ${GREY}Inside 'less' views:${NC} space=page down, q=quit"
      echo ""
      pause ;;
    *) echo "  ${RED}Invalid selection.${NC}"; sleep 1 ;;
  esac
done
