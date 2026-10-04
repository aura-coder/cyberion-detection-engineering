#!/usr/bin/env bash
# Cyberion Detection Engineering - Split-pane console
# Menu on left, action output on right.

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

# Layout
COLS=$(tput cols); ROWS=$(tput lines)
LEFT_W=46
RIGHT_COL=$((LEFT_W + 2))
RIGHT_W=$((COLS - RIGHT_COL - 1))

if [ "$COLS" -lt 90 ] || [ "$ROWS" -lt 26 ]; then
  echo "Terminal too small. Need at least 90x26 (you have ${COLS}x${ROWS})."
  echo "Resize the window or reduce font size."
  exit 1
fi

# Position cursor
at() { tput cup "$1" "$2"; }

# Print plain text, truncate+pad to width
pl() {
  local r=$1 c=$2 w=$3; shift 3
  at "$r" "$c"
  printf '%-*.*s' "$w" "$w" "$*"
}

# Print colored text with visible-length padding
scol() {
  local r=$1 c=$2 text="$3" w=$4
  at "$r" "$c"
  printf '%s' "$text"
  local stripped
  stripped=$(printf '%s' "$text" | sed $'s/\033\\[[0-9;]*m//g')
  local pad=$(( w - ${#stripped} ))
  [ "$pad" -gt 0 ] && printf '%*s' "$pad" ""
}

# Data
c_rules()   { ls rules/sigma/*.yml 2>/dev/null | wc -l | tr -d ' '; }
c_corr()    { grep -l '^correlation:' rules/sigma/*.yml 2>/dev/null | wc -l | tr -d ' '; }
c_hunts()   { ls hunts/*.md 2>/dev/null | grep -v template | wc -l | tr -d ' '; }
c_inc()     { ls incidents/*.md 2>/dev/null | grep -v template | wc -l | tr -d ' '; }
c_cov()     { tail -n +2 coverage/attack_coverage.csv 2>/dev/null | wc -l | tr -d ' '; }
c_commits() { git rev-list --count HEAD 2>/dev/null || echo 0; }
c_conv()    { ls rules/converted/splunk/*.spl rules/converted/elastic/*.lucene rules/converted/elastic/*.eql 2>/dev/null | wc -l | tr -d ' '; }

# --- Draw left column ---
draw_left() {
  # Header
  scol 0 1 "  ${BOLD}${SKY}◆${NC} ${BOLD}${WHITE}CYBERION DEFENSE${NC}" $((LEFT_W - 2))
  scol 1 1 "  ${GREEN}●${NC} ${WHITE}OPERATIONAL${NC}    ${GREY}v1.0.0${NC}" $((LEFT_W - 2))

  at 2 0
  printf '%s%s%s' "${BLUE}" "$(printf '━%.0s' $(seq 1 $LEFT_W))" "${NC}"

  # Stats
  scol 3 1 "  ${GREY}Rules${NC} ${BOLD}${GREEN}$(c_rules)${NC}   ${GREY}Corr${NC} ${BOLD}${MAGENTA}$(c_corr)${NC}   ${GREY}Hunts${NC} ${BOLD}${SKY}$(c_hunts)${NC}" $((LEFT_W - 2))
  scol 4 1 "  ${GREY}Cov${NC} ${BOLD}${YELLOW}$(c_cov)${NC}    ${GREY}Conv${NC} ${BOLD}${TEAL}$(c_conv)${NC}   ${GREY}Commits${NC} ${BOLD}${BLUE}$(c_commits)${NC}" $((LEFT_W - 2))

  at 5 0
  printf '%s%s%s' "${BLUE}" "$(printf '━%.0s' $(seq 1 $LEFT_W))" "${NC}"

  # Menu items
  local r=7
  sec() { scol $r 1 "  ${BOLD}${BLUE}$1${NC}" $((LEFT_W - 2)); r=$((r+1)); }
  itm() {
    scol $r 1 "   ${SKY}[$1]${NC} $2" $((LEFT_W - 2))
    r=$((r+1))
  }

  sec "VALIDATION"
  itm "1"  "Validate Sigma rules"
  itm "2"  "Full test suite"
  itm "3"  "Rule effectiveness"
  r=$((r+1))

  sec "COVERAGE"
  itm "4"  "ATT&CK coverage matrix"
  itm "5"  "Rebuild Navigator layer"
  r=$((r+1))

  sec "REPORTS"
  itm "6"  "Threat hunt reports"
  itm "7"  "Incident case reports"
  itm "8"  "Executive summary"
  r=$((r+1))

  sec "OPERATIONS"
  itm "9"  "Convert to Splunk/Lucene/EQL"
  itm "10" "Git history"
  itm "11" "Project statistics"
  itm "12" "Presentation export"
  r=$((r+1))

  sec "SESSION"
  itm "0"  "Exit"

  # Vertical divider
  local i
  for ((i=0; i<ROWS; i++)); do
    at "$i" "$LEFT_W"
    printf '%s│%s' "${GREY}" "${NC}"
  done

  # Prompt
  scol $((ROWS - 2)) 1 "  ${BOLD}${SKY}❯${NC} Select ${GREY}[0-12]${NC}: " $((LEFT_W - 4))
}

# --- Right pane helpers ---
rstatus() {
  scol 0 "$RIGHT_COL" "  ${BOLD}${SKY}$1${NC}" "$RIGHT_W"
}
pr() {
  local r=$1; shift
  pl "$r" "$RIGHT_COL" "$RIGHT_W" "$*"
}

# Clear right pane (rows 0..ROWS-1)
clr_right() {
  local i
  for ((i=0; i<ROWS; i++)); do
    at "$i" "$RIGHT_COL"
    printf '%*s' "$RIGHT_W" ""
  done
}

# Run command, stream output to right pane
run_cmd() {
  local n="$1" label="$2"; shift 2
  clr_right
  rstatus "▶ [$n] $label"
  pr 2 ""
  pr 3 "  Running: $label"
  pr 4 "  ────────────────────────────────────────────"
  "$@" > /tmp/cyb_out.txt 2>&1
  local r=6
  while IFS= read -r line; do
    [ $r -ge $((ROWS - 2)) ] && break
    pr "$r" "$line"
    r=$((r + 1))
  done < /tmp/cyb_out.txt
  at $((ROWS - 1)) "$RIGHT_COL"
  printf '%s↵ Press Enter to continue%s' "${DIM}" "${NC}"
  read -r _ || return
}

# Run shell string
run_sh() {
  local n="$1" label="$2" cmd="$3"
  clr_right
  rstatus "▶ [$n] $label"
  pr 2 ""
  pr 3 "  Running: $label"
  pr 4 "  ────────────────────────────────────────────"
  eval "$cmd" > /tmp/cyb_out.txt 2>&1
  local r=6
  while IFS= read -r line; do
    [ $r -ge $((ROWS - 2)) ] && break
    pr "$r" "$line"
    r=$((r + 1))
  done < /tmp/cyb_out.txt
  at $((ROWS - 1)) "$RIGHT_COL"
  printf '%s↵ Press Enter to continue%s' "${DIM}" "${NC}"
  read -r _ || return
}

# ============================================================
# MAIN LOOP
# ============================================================
tput civis
trap 'tput cnorm; clear; exit 130' INT

while true; do
  clear
  draw_left

  at $((ROWS - 2)) 20
  tput cnorm
  if ! IFS= read -r choice; then
    tput cnorm; clear; exit 0
  fi
  tput civis

  case "$choice" in
    1) run_cmd "1" "Validate Sigma rules" sigma check rules/sigma ;;
    2) run_cmd "2" "Full test suite" ./tests/run_all_tests.sh ;;
    3) run_cmd "3" "Rule effectiveness" python3 scripts/menu_helpers/effectiveness.py ;;
    4) run_cmd "4" "ATT&CK coverage matrix" python3 scripts/menu_helpers/coverage.py ;;
    5) run_cmd "5" "Rebuild Navigator layer" python3 scripts/csv_to_navigator.py ;;
    6) run_sh "6" "Threat hunt reports" 'ls -1 hunts/*.md | grep -v template | while read f; do
  [ "$(basename "$f")" = "hunt_template.md" ] && continue
  echo "  • $(basename "$f")"
done
echo
echo "  Open:  less hunts/hunt_001_suspicious_process_chains.md"
echo "         less hunts/hunt_002_c2_beaconing.md"' ;;
    7) run_sh "7" "Incident case reports" 'ls -1 incidents/*.md | grep -v template | while read f; do
  [ "$(basename "$f")" = "incident_template.md" ] && continue
  echo "  • $(basename "$f")"
done
echo
echo "  Open:  less incidents/incident_001_lsass_dump_and_cobalt_strike.md"
echo "         less incidents/incident_002_masqueraded_office_macro.md"' ;;
    8) run_sh "8" "Executive summary" 'head -50 reports/executive_summary.md' ;;
    9) run_sh "9" "Convert to Splunk/Lucene/EQL" 'mkdir -p rules/converted/splunk rules/converted/elastic
n=0; total=$(ls rules/sigma/*.yml 2>/dev/null | wc -l)
for f in rules/sigma/*.yml; do
  b=$(basename "$f" .yml)
  sigma convert -t splunk --without-pipeline "$f" > "rules/converted/splunk/${b}.spl" 2>/dev/null
  sigma convert -t lucene -p ecs_windows "$f" > "rules/converted/elastic/${b}.lucene" 2>/dev/null
  sigma convert -t eql -p ecs_windows "$f" > "rules/converted/elastic/${b}.eql" 2>/dev/null
  n=$((n+1))
done
echo "  Converted $n rules"
echo
echo "    Splunk SPL:     $(ls rules/converted/splunk/*.spl | wc -l) files"
echo "    Elastic Lucene: $(ls rules/converted/elastic/*.lucene | wc -l) files"
echo "    Elastic EQL:    $(ls rules/converted/elastic/*.eql | wc -l) files"' ;;
    10) run_cmd "10" "Git history" git log --oneline --decorate ;;
    11) run_cmd "11" "Project statistics" python3 scripts/menu_helpers/stats.py ;;
    12) run_sh "12" "Presentation files" 'ls -la reports/final_presentation.* 2>/dev/null' ;;
    0|q|Q) tput cnorm; clear; echo "Bye."; exit 0 ;;
    *)
      clr_right
      rstatus "✗ Invalid selection"
      pr 2 ""
      pr 3 "  You entered: \"$choice\""
      pr 4 "  Please enter a number between 0 and 12."
      pr 5 ""
      at 6 "$RIGHT_COL"
      printf '%s↵ Press Enter to try again%s' "${DIM}" "${NC}"
      read -r _ ;;
  esac
done
