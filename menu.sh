#!/usr/bin/env bash
# ============================================================
# Cyberion Detection Engineering - Interactive Terminal
# Rich TUI menu with live dashboard, icons, colors.
# ============================================================

set -uo pipefail
cd "$(dirname "$0")"

if [ -d ".venv" ]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate 2>/dev/null || true
fi

# ---------- Color palette ----------
if [ -t 1 ]; then
  BOLD=$'\033[1m'; DIM=$'\033[2m'; ITALIC=$'\033[3m'
  NC=$'\033[0m'
  RED=$'\033[38;5;196m'; GREEN=$'\033[38;5;46m'; YELLOW=$'\033[38;5;226m'
  BLUE=$'\033[38;5;39m'; CYAN=$'\033[38;5;51m'; MAGENTA=$'\033[38;5;201m'
  ORANGE=$'\033[38;5;208m'; PURPLE=$'\033[38;5;129m'
  GREY=$'\033[38;5;240m'; WHITE=$'\033[38;5;255m'
  BG_HEAD=$'\033[48;5;17m'; BG_ROW=$'\033[48;5;234m'
else
  BOLD=""; DIM=""; ITALIC=""; NC=""
  RED=""; GREEN=""; YELLOW=""; BLUE=""; CYAN=""; MAGENTA=""
  ORANGE=""; PURPLE=""; GREY=""; WHITE=""; BG_HEAD=""; BG_ROW=""
fi

# ---------- Terminal size ----------
term_cols() { tput cols 2>/dev/null || echo 100; }
term_rows() { tput lines 2>/dev/null || echo 30; }

# ---------- Box drawing ----------
hr() {
  local n=$(($(term_cols) - 2))
  printf '%s' "${GREY}"
  printf '─%.0s' $(seq 1 "$n")
  printf '%s\n' "${NC}"
}

hr_double() {
  local n=$(($(term_cols) - 2))
  printf '%s' "${CYAN}${BOLD}"
  printf '═%.0s' $(seq 1 "$n")
  printf '%s\n' "${NC}"
}

# ---------- Spinner ----------
spin() {
  local msg="$1"
  local cmd="$2"
  local frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
  local i=0
  local pid

  # Start command in background, capture output
  ( eval "$cmd" ) > /tmp/spin_out.txt 2>&1 &
  pid=$!

  printf '  %s ' "${CYAN}"
  while kill -0 "$pid" 2>/dev/null; do
    printf '\r  %s%s%s %s' "${CYAN}" "${frames[$i]}" "${NC}" "$msg"
    i=$(( (i + 1) % ${#frames[@]} ))
    sleep 0.08
  done
  wait "$pid" 2>/dev/null
  local rc=$?

  if [ $rc -eq 0 ]; then
    printf '\r  %s✓%s %s          \n' "${GREEN}${BOLD}" "${NC}" "$msg"
  else
    printf '\r  %s✗%s %s          \n' "${RED}${BOLD}" "${NC}" "$msg"
  fi
  cat /tmp/spin_out.txt
  return $rc
}

# ---------- Pause ----------
pause() {
  echo ""
  printf '%s' "${DIM}  ↵ Press Enter to continue...${NC}"
  read -r _
}

# ---------- Open file helper ----------
open_file() {
  local f="$1"
  [ -f "$f" ] || { echo "  ${RED}File not found: $f${NC}"; return 1; }
  local ext="${f##*.}"
  local opener=""
  case "$ext" in
    md|txt|log|json|yml|yaml) opener="${PAGER:-less}" ;;
    pdf)
      if   command -v xdg-open >/dev/null 2>&1; then opener="xdg-open"
      elif command -v firefox  >/dev/null 2>&1; then opener="firefox"
      fi ;;
    html|htm)
      if   command -v firefox  >/dev/null 2>&1; then opener="firefox"
      elif command -v xdg-open >/dev/null 2>&1; then opener="xdg-open"
      fi ;;
    docx|doc|pptx|ppt|xlsx|xls|odt|ods)
      if   command -v libreoffice >/dev/null 2>&1; then opener="libreoffice --norestore"
      elif command -v xdg-open    >/dev/null 2>&1; then opener="xdg-open"
      fi ;;
    *) [ -n "${XDG_CURRENT_DESKTOP:-}" ] && opener="xdg-open" ;;
  esac
  if [ -z "$opener" ]; then
    echo "  ${YELLOW}No opener for .$ext — file: $f${NC}"
    return 1
  fi
  echo "  ${CYAN}→ opening with $opener${NC}"
  # shellcheck disable=SC2086
  $opener "$f" &
}

ask_open() {
  local f="$1"
  [ -f "$f" ] || return 1
  echo ""
  printf '%s' "${BOLD}  Open the file now? [y/N]: ${NC}"
  read -r ans
  case "$ans" in y|Y|yes|YES) open_file "$f" ;; esac
}

# ---------- Live stats helpers ----------
count_rules()         { ls rules/sigma/*.yml 2>/dev/null | wc -l; }
count_correlations()  { grep -l '^correlation:' rules/sigma/*.yml 2>/dev/null | wc -l; }
count_hunts()         { ls hunts/*.md 2>/dev/null | grep -v template | wc -l; }
count_incidents()     { ls incidents/*.md 2>/dev/null | grep -v template | wc -l; }
count_playbooks()     { ls playbooks/*.md 2>/dev/null | grep -v template | wc -l; }
count_coverage()      { tail -n +2 coverage/attack_coverage.csv 2>/dev/null | wc -l; }
count_commits()       { git rev-list --count HEAD 2>/dev/null || echo 0; }
last_commit_msg()     { git log -1 --format='%s' 2>/dev/null | cut -c1-50; }

# ---------- Header banner ----------
draw_banner() {
  clear
  local w=$(term_cols)
  local pad=$(( (w - 60) / 2 ))
  [ "$pad" -lt 0 ] && pad=0
  local p=""
  for _ in $(seq 1 $pad); do p+=" "; done

  echo ""
  echo "${p}${CYAN}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
  echo "${p}${CYAN}${BOLD}║${NC}   ${MAGENTA}${BOLD}◆ CYBERION DEFENSE LABS${NC}  ${GREY}│${NC}  ${WHITE}Detection Engineering${NC}   ${CYAN}${BOLD}║${NC}"
  echo "${p}${CYAN}${BOLD}║${NC}   ${GREY}Threat Hunting & Detection Content Engagement${NC}        ${CYAN}${BOLD}║${NC}"
  echo "${p}${CYAN}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
  echo ""
}

# ---------- Live dashboard ----------
draw_dashboard() {
  local rules=$(count_rules)
  local corr=$(count_correlations)
  local hunts=$(count_hunts)
  local incs=$(count_incidents)
  local pb=$(count_playbooks)
  local cov=$(count_coverage)
  local commits=$(count_commits)
  local last=$(last_commit_msg)

  local R="${BOLD}${GREEN}${rules}${NC}"
  local C="${BOLD}${MAGENTA}${corr}${NC}"
  local H="${BOLD}${CYAN}${hunts}${NC}"
  local I="${BOLD}${ORANGE}${incs}${NC}"
  local P="${BOLD}${PURPLE}${pb}${NC}"
  local V="${BOLD}${YELLOW}${cov}${NC}"
  local G="${BOLD}${BLUE}${commits}${NC}"

  hr
  printf "  ${GREY}│${NC} %s rules  ${GREY}│${NC} %s correlations  ${GREY}│${NC} %s hunts  ${GREY}│${NC} %s incidents\n" "$R" "$C" "$H" "$I"
  printf "  ${GREY}│${NC} %s playbooks  ${GREY}│${NC} %s ATT&CK rows  ${GREY}│${NC} %s commits\n" "$P" "$V" "$G"
  printf "  ${GREY}│${NC} ${DIM}last: %s${NC}\n" "$last"
  hr
  echo ""
}

# ---------- Menu items ----------
draw_menu() {
  echo "  ${BOLD}${WHITE}VALIDATION & TESTS${NC}"
  printf "    ${GREEN}▸${NC} ${BOLD}%2s${NC}  %s %s\n" "1" "🔍  Validate all Sigma rules"      "${DIM}sigma check${NC}"
  printf "    ${GREEN}▸${NC} ${BOLD}%2s${NC}  %s %s\n" "2" "🧪  Run full test suite"            "${DIM}26 checks${NC}"
  printf "    ${GREEN}▸${NC} ${BOLD}%2s${NC}  %s %s\n" "3" "🎯  Rule effectiveness"            "${DIM}matches vs real data${NC}"
  echo ""
  echo "  ${BOLD}${WHITE}COVERAGE & ANALYSIS${NC}"
  printf "    ${CYAN}▸${NC} ${BOLD}%2s${NC}  %s %s\n" "4" "📊  ATT&CK coverage matrix"          "${DIM}40 techniques${NC}"
  printf "    ${CYAN}▸${NC} ${BOLD}%2s${NC}  %s %s\n" "5" "🗺️   Rebuild Navigator layer"         "${DIM}visual heatmap${NC}"
  echo ""
  echo "  ${BOLD}${WHITE}REPORTS${NC}"
  printf "    ${MAGENTA}▸${NC} ${BOLD}%2s${NC}  %s\n" "6" "🎣  Threat hunt reports"
  printf "    ${MAGENTA}▸${NC} ${BOLD}%2s${NC}  %s\n" "7" "🚨  Incident case reports"
  printf "    ${MAGENTA}▸${NC} ${BOLD}%2s${NC}  %s %s\n" "8" "📄  Executive summary"              "${DIM}MD/PDF/HTML/DOCX${NC}"
  echo ""
  echo "  ${BOLD}${WHITE}OPERATIONS${NC}"
  printf "    ${YELLOW}▸${NC} ${BOLD}%2s${NC}  %s %s\n" "9"  "🔄  Convert to Splunk/Lucene/EQL"    "${DIM}36 × 3 backends${NC}"
  printf "    ${YELLOW}▸${NC} ${BOLD}%2s${NC}  %s\n" "10" "📜  Git history"
  printf "    ${YELLOW}▸${NC} ${BOLD}%2s${NC}  %s\n" "11" "📈  Project statistics"
  printf "    ${YELLOW}▸${NC} ${BOLD}%2s${NC}  %s %s\n" "12" "🎬  Presentation"                    "${DIM}PPTX/PDF/HTML/DOCX${NC}"
  echo ""
  echo "  ${BOLD}${WHITE}EXIT${NC}"
  printf "    ${RED}▸${NC} ${BOLD}%2s${NC}  %s\n" "0" "⏻   Exit"
  echo ""
}

# ============================================================
# ACTIONS
# ============================================================

action_1() {
  echo "  ${BOLD}${CYAN}▶ Validating all Sigma rules...${NC}"
  echo ""
  spin "Parsing and checking rules" "sigma check rules/sigma 2>&1 | grep -v '^Parsing\|^Checking'"
  pause
}

action_2() {
  echo "  ${BOLD}${CYAN}▶ Running full test suite (26 checks)...${NC}"
  echo ""
  ./tests/run_all_tests.sh
  pause
}

action_3() {
  echo "  ${BOLD}${CYAN}▶ Rule effectiveness — matched against 34,870 real events${NC}"
  echo ""
  if [ -f tests/results/effectiveness.json ]; then
    python3 - <<'PY'
import json
from pathlib import Path

G="\033[38;5;46m"; R="\033[38;5;196m"; Y="\033[38;5;226m"
B="\033[1m"; NC="\033[0m"; D="\033[2m"

d = json.loads(Path("tests/results/effectiveness.json").read_text())
matched = sum(1 for v in d.values() if v > 0)
total = len(d)

bar = "─" * 68
print(f"  {D}{bar}{NC}")
print(f"  {B}{'Rule':<52s}{'Matches':>10s}{NC}")
print(f"  {D}{bar}{NC}")
for k, v in d.items():
    if v > 0:
        badge = f"{G}● {v:>3d}{NC}"
    else:
        badge = f"{R}●   0{NC}"
    name = k[:50]
    print(f"  {name:<52s} {badge}")
print(f"  {D}{bar}{NC}")
print()
print(f"  {B}Success: {G}{matched}/{total}{NC}  {D}({matched/total*100:.0f}%){NC}")
PY
  else
    echo "  ${RED}No results file found. Run option 2 first.${NC}"
  fi
  pause
}

action_4() {
  echo "  ${BOLD}${CYAN}▶ ATT&CK Coverage Matrix${NC}"
  echo ""
  python3 - <<'PY'
import csv
from pathlib import Path

B="\033[1m"; NC="\033[0m"; D="\033[2m"
G="\033[38;5;46m"; Y="\033[38;5;226m"; R="\033[38;5;196m"

rows = list(csv.DictReader(open("coverage/attack_coverage.csv")))
covered = sum(1 for r in rows if r["Status"] == "Covered")
partial = sum(1 for r in rows if "Partially" in r["Status"])
notcov  = sum(1 for r in rows if r["Status"] == "Not Covered")

print(f"  {B}Total assessed: {len(rows)}{NC}")
print(f"  {G}● Covered:            {covered}{NC}")
print(f"  {Y}● Partially Covered:  {partial}{NC}")
print(f"  {R}● Not Covered:        {notcov}{NC}")
print()
print(f"  {B}{'Tactic':<22s} {'Technique':<12s} {'Name':<40s} {'Status'}{NC}")
print(f"  {D}{'─'*90}{NC}")

for r in rows:
    st = r["Status"]
    if st == "Covered":           color = G
    elif "Partially" in st:       color = Y
    else:                          color = R
    name = r["Technique Name"][:38]
    print(f"  {r['Tactic']:<22s} {r['Technique ID']:<12s} {name:<40s} {color}{st}{NC}")
PY
  pause
}

action_5() {
  echo "  ${BOLD}${CYAN}▶ Rebuilding ATT&CK Navigator layer${NC}"
  echo ""
  python scripts/csv_to_navigator.py
  echo ""
  echo "  ${GREEN}✓ coverage/attack_coverage_layer.json${NC}"
  echo ""
  echo "  ${BOLD}To view the heatmap:${NC}"
  echo "  ${DIM}1)${NC} Open: ${BLUE}https://mitre-attack.github.io/attack-navigator/${NC}"
  echo "  ${DIM}2)${NC} Click ${BOLD}Open Existing Layer${NC} → ${BOLD}Upload from local${NC}"
  echo "  ${DIM}3)${NC} Select: $(pwd)/coverage/attack_coverage_layer.json"
  pause
}

action_6() {
  while true; do
    clear; draw_banner
    echo "  ${BOLD}${WHITE}THREAT HUNT REPORTS${NC}"
    echo ""
    echo "    ${GREEN}▸${NC} ${BOLD}1)${NC}  🎣  Hunt 001 — Process Chains"
    echo "    ${GREEN}▸${NC} ${BOLD}2)${NC}  🎣  Hunt 002 — C2 Beaconing"
    echo "    ${GREEN}▸${NC} ${BOLD}3)${NC}  ↩   Back"
    echo ""
    printf '  %sChoose [1-3]: %s' "${BOLD}" "${NC}"
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
    clear; draw_banner
    echo "  ${BOLD}${WHITE}INCIDENT CASE REPORTS${NC}"
    echo ""
    echo "    ${ORANGE}▸${NC} ${BOLD}1)${NC}  🚨  Incident 001 — LSASS dump + Cobalt Strike"
    echo "    ${ORANGE}▸${NC} ${BOLD}2)${NC}  🚨  Incident 002 — Masqueraded Office dropper"
    echo "    ${ORANGE}▸${NC} ${BOLD}3)${NC}  ↩   Back"
    echo ""
    printf '  %sChoose [1-3]: %s' "${BOLD}" "${NC}"
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
    clear; draw_banner
    echo "  ${BOLD}${WHITE}EXECUTIVE SUMMARY — EXPORT${NC}"
    echo ""
    echo "  Source: ${DIM}reports/executive_summary.md${NC}  ($(wc -l < reports/executive_summary.md) lines)"
    echo ""
    echo "    ${GREEN}▸${NC} ${BOLD}1)${NC}  👁   View on screen"
    echo "    ${GREEN}▸${NC} ${BOLD}2)${NC}  📝  Markdown   ${DIM}(.md)${NC}"
    echo "    ${GREEN}▸${NC} ${BOLD}3)${NC}  📕  PDF        ${DIM}(.pdf)${NC}"
    echo "    ${GREEN}▸${NC} ${BOLD}4)${NC}  🌐  HTML       ${DIM}(.html)${NC}"
    echo "    ${GREEN}▸${NC} ${BOLD}5)${NC}  📘  Word       ${DIM}(.docx)${NC}"
    echo "    ${GREEN}▸${NC} ${BOLD}6)${NC}  🎬  PowerPoint ${DIM}(.pptx)${NC}"
    echo "    ${GREEN}▸${NC} ${BOLD}7)${NC}  📦  Export ALL formats"
    echo "    ${GREEN}▸${NC} ${BOLD}0)${NC}  ↩   Back"
    echo ""
    printf '  %sChoose [0-7]: %s' "${BOLD}" "${NC}"
    read -r fmt

    mkdir -p reports/exports
    local out=""

    case "$fmt" in
      1) less reports/executive_summary.md; continue ;;
      2) out="reports/exports/executive_summary.md"; cp reports/executive_summary.md "$out"
         echo "  ${GREEN}✓ $out${NC}"; ask_open "$out"; pause ;;
      3) out="reports/exports/executive_summary.pdf"
         if pandoc reports/executive_summary.md -o "$out" --pdf-engine=weasyprint 2>/tmp/pdf_err.txt; then
           echo "  ${GREEN}✓ $out${NC}"; ask_open "$out"
         else
           echo "  ${YELLOW}PDF engine unavailable — use option 4 (HTML) → Ctrl+P in browser${NC}"
         fi; pause ;;
      4) out="reports/exports/executive_summary.html"
         pandoc reports/executive_summary.md -o "$out" --standalone --metadata title="Executive Summary" 2>/dev/null
         echo "  ${GREEN}✓ $out${NC}"; ask_open "$out"; pause ;;
      5) out="reports/exports/executive_summary.docx"
         pandoc reports/executive_summary.md -o "$out" 2>/dev/null
         echo "  ${GREEN}✓ $out${NC}"; ask_open "$out"; pause ;;
      6) out="reports/exports/final_presentation.pptx"
         pandoc reports/final_presentation.md -o "$out" 2>/dev/null
         echo "  ${GREEN}✓ $out${NC}"; ask_open "$out"; pause ;;
      7)
         local gen=()
         cp reports/executive_summary.md reports/exports/executive_summary.md
         gen+=("reports/exports/executive_summary.md"); echo "  ${GREEN}✓${NC} Markdown"
         pandoc reports/executive_summary.md -o reports/exports/executive_summary.html --standalone --metadata title="Executive Summary" 2>/dev/null && { gen+=("reports/exports/executive_summary.html"); echo "  ${GREEN}✓${NC} HTML"; }
         pandoc reports/executive_summary.md -o reports/exports/executive_summary.docx 2>/dev/null && { gen+=("reports/exports/executive_summary.docx"); echo "  ${GREEN}✓${NC} DOCX"; }
         pandoc reports/executive_summary.md -o reports/exports/executive_summary.pdf --pdf-engine=weasyprint 2>/dev/null && { gen+=("reports/exports/executive_summary.pdf"); echo "  ${GREEN}✓${NC} PDF"; }
         pandoc reports/final_presentation.md -o reports/exports/final_presentation.pptx 2>/dev/null && { gen+=("reports/exports/final_presentation.pptx"); echo "  ${GREEN}✓${NC} PPTX"; }
         echo ""
         local i=1
         for g in "${gen[@]}"; do echo "    ${BOLD}$i)${NC} $g"; i=$((i+1)); done
         printf '  %sOpen which? [1-%s, 0=skip]: %s' "${BOLD}" "${#gen[@]}" "${NC}"
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
  echo "  ${BOLD}${CYAN}▶ Converting all rules to Splunk / Lucene / EQL${NC}"
  echo ""
  mkdir -p rules/converted/splunk rules/converted/elastic
  local total=$(ls rules/sigma/*.yml 2>/dev/null | wc -l)
  local n=0
  for f in rules/sigma/*.yml; do
    base=$(basename "$f" .yml)
    sigma convert -t splunk --without-pipeline "$f" > "rules/converted/splunk/${base}.spl" 2>/dev/null || true
    sigma convert -t lucene -p ecs_windows "$f" > "rules/converted/elastic/${base}.lucene" 2>/dev/null || true
    sigma convert -t eql -p ecs_windows "$f" > "rules/converted/elastic/${base}.eql" 2>/dev/null || true
    n=$((n+1))
    printf '\r  %s⠋%s converting %d/%d...' "${CYAN}" "${NC}" "$n" "$total"
  done
  printf '\r  %s✓%s converted %d rules          \n' "${GREEN}${BOLD}" "${NC}" "$total"
  echo ""
  echo "  ${GREEN}●${NC} Splunk:  $(ls rules/converted/splunk/*.spl 2>/dev/null | wc -l) files"
  echo "  ${GREEN}●${NC} Lucene:  $(ls rules/converted/elastic/*.lucene 2>/dev/null | wc -l) files"
  echo "  ${GREEN}●${NC} EQL:     $(ls rules/converted/elastic/*.eql 2>/dev/null | wc -l) files"
  pause
}

action_10() {
  echo "  ${BOLD}${CYAN}▶ Git history${NC}"
  echo ""
  git log --oneline --decorate --color=always | head -30
  echo ""
  echo "  ${DIM}Total commits: $(git rev-list --count HEAD)${NC}"
  pause
}

action_11() {
  echo "  ${BOLD}${CYAN}▶ Project statistics${NC}"
  echo ""
  printf "  %-30s %s\n" "Sigma rules"              "$(count_rules)"
  printf "  %-30s %s\n" "Correlation rules"        "$(count_correlations)"
  printf "  %-30s %s\n" "Base rules (correlations)" "$(ls rules/sigma/base_*.yml 2>/dev/null | wc -l)"
  printf "  %-30s %s\n" "Converted backends (total)" "$(ls rules/converted/splunk/*.spl rules/converted/elastic/*.lucene rules/converted/elastic/*.eql 2>/dev/null | wc -l)"
  printf "  %-30s %s\n" "Coverage rows"            "$(count_coverage)"
  printf "  %-30s %s\n" "Threat hunts"             "$(count_hunts)"
  printf "  %-30s %s\n" "Incident reports"         "$(count_incidents)"
  printf "  %-30s %s\n" "IR playbooks"             "$(count_playbooks)"
  printf "  %-30s %s\n" "Git-tracked files"        "$(git ls-files | wc -l)"
  printf "  %-30s %s\n" "Git commits"              "$(count_commits)"
  pause
}

action_12() {
  while true; do
    clear; draw_banner
    echo "  ${BOLD}${WHITE}PRESENTATION — EXPORT${NC}"
    echo ""
    echo "  Source: ${DIM}reports/final_presentation.md${NC}  ($(grep -c '^## Slide' reports/final_presentation.md 2>/dev/null) slides)"
    echo ""
    echo "    ${PURPLE}▸${NC} ${BOLD}1)${NC}  👁   View outline"
    echo "    ${PURPLE}▸${NC} ${BOLD}2)${NC}  🎬  PowerPoint  ${DIM}(.pptx)${NC}"
    echo "    ${PURPLE}▸${NC} ${BOLD}3)${NC}  📕  PDF         ${DIM}(.pdf)${NC}"
    echo "    ${PURPLE}▸${NC} ${BOLD}4)${NC}  🌐  HTML        ${DIM}(.html)${NC}"
    echo "    ${PURPLE}▸${NC} ${BOLD}5)${NC}  📘  Word        ${DIM}(.docx)${NC}"
    echo "    ${PURPLE}▸${NC} ${BOLD}6)${NC}  📝  Markdown    ${DIM}(.md)${NC}"
    echo "    ${PURPLE}▸${NC} ${BOLD}7)${NC}  📦  Export ALL"
    echo "    ${PURPLE}▸${NC} ${BOLD}8)${NC}  🔓  Open existing PPTX"
    echo "    ${PURPLE}▸${NC} ${BOLD}0)${NC}  ↩   Back"
    echo ""
    printf '  %sChoose [0-8]: %s' "${BOLD}" "${NC}"
    read -r fmt

    mkdir -p reports/exports
    local out=""

    case "$fmt" in
      1) less reports/final_presentation.md; continue ;;
      2) out="reports/exports/final_presentation.pptx"
         pandoc reports/final_presentation.md -o "$out" 2>/dev/null
         echo "  ${GREEN}✓ $out${NC}"; ask_open "$out"; pause ;;
      3) out="reports/exports/final_presentation.pdf"
         if pandoc reports/final_presentation.md -o "$out" --pdf-engine=weasyprint 2>/dev/null; then
           echo "  ${GREEN}✓ $out${NC}"; ask_open "$out"
         else
           echo "  ${YELLOW}PDF engine unavailable — use option 4 (HTML)${NC}"
         fi; pause ;;
      4) out="reports/exports/final_presentation.html"
         pandoc reports/final_presentation.md -o "$out" --standalone --metadata title="Presentation" 2>/dev/null
         echo "  ${GREEN}✓ $out${NC}"; ask_open "$out"; pause ;;
      5) out="reports/exports/final_presentation.docx"
         pandoc reports/final_presentation.md -o "$out" 2>/dev/null
         echo "  ${GREEN}✓ $out${NC}"; ask_open "$out"; pause ;;
      6) out="reports/exports/final_presentation.md"
         cp reports/final_presentation.md "$out"
         echo "  ${GREEN}✓ $out${NC}"; ask_open "$out"; pause ;;
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
         printf '  %sOpen which? [1-%s, 0=skip]: %s' "${BOLD}" "${#gen[@]}" "${NC}"
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
# MAIN LOOP
# ============================================================

trap 'echo ""; echo "${DIM}Interrupted.${NC}"; exit 130' INT

while true; do
  draw_banner
  draw_dashboard
  draw_menu
  printf '  %s%s❯%s Choose %s[0-12]%s: ' "${BOLD}" "${CYAN}" "${NC}" "${GREY}" "${NC}"
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
    0|q|Q|exit) clear; echo ""; echo "  ${CYAN}${BOLD}See you next time.${NC}"; echo ""; exit 0 ;;
    *) echo "  ${RED}Invalid choice.${NC}"; sleep 1 ;;
  esac
done
