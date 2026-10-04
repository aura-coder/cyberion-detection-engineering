#!/usr/bin/env bash
# ============================================================
# Cyberion Detection Engineering - Interactive Menu
# Wraps all project commands in a numbered menu.
# ============================================================

set -uo pipefail

# Always run from the repo root
cd "$(dirname "$0")"

# Activate venv if present
if [ -d ".venv" ]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate 2>/dev/null || true
fi

# Color support
if [ -t 1 ]; then
  BOLD=$'\033[1m'; DIM=$'\033[2m'; NC=$'\033[0m'
  GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'; CYAN=$'\033[36m'
else
  BOLD=""; DIM=""; NC=""; GREEN=""; YELLOW=""; RED=""; CYAN=""
fi

pause() {
  echo ""
  read -rp "${DIM}Press Enter to return to menu...${NC}" _
}

open_file() {
  local f="$1"
  [ -f "$f" ] || { echo "${RED}File not found: $f${NC}"; return 1; }

  local ext="${f##*.}"
  local opener=""

  case "$ext" in
    md|txt|log|json|yml|yaml)
      opener="${PAGER:-less}"
      ;;
    pdf)
      if   command -v xdg-open >/dev/null 2>&1; then opener="xdg-open"
      elif command -v firefox  >/dev/null 2>&1; then opener="firefox"
      elif command -v evince   >/dev/null 2>&1; then opener="evince"
      fi
      ;;
    html|htm)
      if   command -v firefox  >/dev/null 2>&1; then opener="firefox"
      elif command -v xdg-open >/dev/null 2>&1; then opener="xdg-open"
      fi
      ;;
    docx|doc|pptx|ppt|xlsx|xls|odt|ods)
      if   command -v libreoffice >/dev/null 2>&1; then opener="libreoffice --norestore"
      elif command -v xdg-open    >/dev/null 2>&1; then opener="xdg-open"
      fi
      ;;
    *)
      if command -v xdg-open >/dev/null 2>&1; then opener="xdg-open"; fi
      ;;
  esac

  if [ -z "$opener" ]; then
    echo "${YELLOW}No opener found for .$ext - open manually: $f${NC}"
    return 1
  fi

  echo "${CYAN}Opening with: $opener${NC}"
  # shellcheck disable=SC2086
  $opener "$f" &
}

ask_open() {
  local f="$1"
  [ -f "$f" ] || return 1
  echo ""
  read -rp "${BOLD}Open the file now? [y/N]: ${NC}" ans
  case "$ans" in
    y|Y|yes|YES) open_file "$f" ;;
    *) echo "${DIM}Not opened. File location: $f${NC}" ;;
  esac
}

header() {
  clear
  echo "${BOLD}${CYAN}============================================================${NC}"
  echo "${BOLD}${CYAN}   CYBERION DETECTION ENGINEERING - CONTROL MENU${NC}"
  echo "${BOLD}${CYAN}============================================================${NC}"
  echo "${DIM}   Repo: $(pwd)${NC}"
  echo ""
}

show_menu() {
  header
  echo "  ${BOLD}1)${NC}  Validate all Sigma rules              ${DIM}(sigma check)${NC}"
  echo "  ${BOLD}2)${NC}  Run full test suite                    ${DIM}(26 checks)${NC}"
  echo "  ${BOLD}3)${NC}  Show rule effectiveness               ${DIM}(which rules matched real data)${NC}"
  echo "  ${BOLD}4)${NC}  Show coverage matrix (CSV)             ${DIM}(40 rows)${NC}"
  echo "  ${BOLD}5)${NC}  Rebuild ATT&CK Navigator layer         ${DIM}(upload to mitre-attack.github.io)${NC}"
  echo "  ${BOLD}6)${NC}  Show a threat hunt report"
  echo "  ${BOLD}7)${NC}  Show an incident case report"
  echo "  ${BOLD}8)${NC}  Show executive summary"
  echo "  ${BOLD}9)${NC}  Convert rules to Splunk/Lucene/EQL"
  echo "  ${BOLD}10)${NC} Show git history"
  echo "  ${BOLD}11)${NC} Show project statistics"
  echo "  ${BOLD}12)${NC} Regenerate presentation PPTX"
  echo ""
  echo "  ${BOLD}0)${NC}  Exit"
  echo ""
}

# ============================================================
# Menu actions
# ============================================================

action_1() {
  echo "${BOLD}==> Validating all Sigma rules...${NC}"
  echo ""
  sigma check rules/sigma
  pause
}

action_2() {
  echo "${BOLD}==> Running full test suite...${NC}"
  echo ""
  ./tests/run_all_tests.sh
  pause
}

action_3() {
  echo "${BOLD}==> Rule effectiveness (matched against 34,870 real events)${NC}"
  echo ""
  if [ -f tests/results/effectiveness.json ]; then
    python3 - <<'PY'
import json
from pathlib import Path
d = json.loads(Path("tests/results/effectiveness.json").read_text())
print(f"{'Rule':<55s} {'Matches':>8s}")
print("-" * 68)
for k, v in d.items():
    status = "OK" if v > 0 else "NO MATCH"
    print(f"{k:<55s} {v:>8d}  {status}")
matched = sum(1 for v in d.values() if v > 0)
print()
print(f"Rules tested:  {len(d)}")
print(f"Rules matched: {matched}")
print(f"Success rate:  {matched/len(d)*100:.1f}%")
PY
  else
    echo "${YELLOW}tests/results/effectiveness.json not found.${NC}"
  fi
  pause
}

action_4() {
  echo "${BOLD}==> ATT&CK Coverage Matrix${NC}"
  echo ""
  python3 - <<'PY'
import csv
from pathlib import Path

rows = list(csv.DictReader(open("coverage/attack_coverage.csv")))
covered = sum(1 for r in rows if r["Status"] == "Covered")
partial = sum(1 for r in rows if "Partially" in r["Status"])
notcov = sum(1 for r in rows if r["Status"] == "Not Covered")

print(f"Total techniques assessed: {len(rows)}")
print(f"  Covered:           {covered}")
print(f"  Partially Covered: {partial}")
print(f"  Not Covered:       {notcov}")
print()
print(f"{'Tactic':<22s} {'Technique':<12s} {'Name':<42s} {'Status':<18s}")
print("-" * 96)
for r in rows:
    print(f"{r['Tactic']:<22s} {r['Technique ID']:<12s} {r['Technique Name'][:40]:<42s} {r['Status']:<18s}")
PY
  pause
}

action_5() {
  echo "${BOLD}==> Rebuilding ATT&CK Navigator layer...${NC}"
  echo ""
  python scripts/csv_to_navigator.py
  echo ""
  echo "${GREEN}Layer written: coverage/attack_coverage_layer.json${NC}"
  echo ""
  echo "To view it:"
  echo "  1. Open https://mitre-attack.github.io/attack-navigator/"
  echo "  2. Click 'Open Existing Layer' -> 'Upload from local'"
  echo "  3. Select: $(pwd)/coverage/attack_coverage_layer.json"
  pause
}

action_6() {
  echo "${BOLD}==> Threat hunt reports${NC}"
  echo ""
  echo "  1) Hunt 001 - Process chains"
  echo "  2) Hunt 002 - C2 beaconing"
  echo "  3) Back"
  echo ""
  read -rp "Choose [1-3]: " sub
  case "$sub" in
    1) less hunts/hunt_001_suspicious_process_chains.md ;;
    2) less hunts/hunt_002_c2_beaconing.md ;;
    *) return ;;
  esac
}

action_7() {
  echo "${BOLD}==> Incident case reports${NC}"
  echo ""
  echo "  1) Incident 001 - LSASS dump + Cobalt Strike"
  echo "  2) Incident 002 - Masqueraded Office dropper"
  echo "  3) Back"
  echo ""
  read -rp "Choose [1-3]: " sub
  case "$sub" in
    1) less incidents/incident_001_lsass_dump_and_cobalt_strike.md ;;
    2) less incidents/incident_002_masqueraded_office_macro.md ;;
    *) return ;;
  esac
}

action_8() {
  while true; do
    clear
    echo "${BOLD}${CYAN}============================================================${NC}"
    echo "${BOLD}${CYAN}   EXECUTIVE SUMMARY - CHOOSE OUTPUT FORMAT${NC}"
    echo "${BOLD}${CYAN}============================================================${NC}"
    echo ""
    echo "  Source file: reports/executive_summary.md"
    echo "  Size: $(wc -l < reports/executive_summary.md) lines"
    echo ""
    echo "  ${BOLD}1)${NC}  View on screen              ${DIM}(less)${NC}"
    echo "  ${BOLD}2)${NC}  Export as Markdown          ${DIM}(.md)${NC}"
    echo "  ${BOLD}3)${NC}  Export as PDF               ${DIM}(.pdf)${NC}"
    echo "  ${BOLD}4)${NC}  Export as HTML              ${DIM}(.html)${NC}"
    echo "  ${BOLD}5)${NC}  Export as Word document     ${DIM}(.docx)${NC}"
    echo "  ${BOLD}6)${NC}  Export as PowerPoint        ${DIM}(.pptx)${NC}"
    echo "  ${BOLD}7)${NC}  Export ALL formats          ${DIM}(everything at once)${NC}"
    echo ""
    echo "  ${BOLD}0)${NC}  Back to main menu"
    echo ""
    read -rp "${BOLD}Choose [0-7]: ${NC}" fmt

    mkdir -p reports/exports
    local out=""

    case "$fmt" in
      1)
        less reports/executive_summary.md
        continue
        ;;

      2)
        out="reports/exports/executive_summary.md"
        cp reports/executive_summary.md "$out"
        echo "${GREEN}Saved: $out${NC}"
        ask_open "$out"
        pause
        ;;

      3)
        out="reports/exports/executive_summary.pdf"
        if command -v pandoc >/dev/null 2>&1; then
          if pandoc reports/executive_summary.md -o "$out" --pdf-engine=weasyprint 2>/tmp/pdf_err.txt; then
            echo "${GREEN}Saved: $out${NC}"
            ls -lh "$out"
            ask_open "$out"
          else
            echo "${YELLOW}PDF engine (weasyprint) unavailable.${NC}"
            echo "${DIM}Try option 4 (HTML) and Ctrl+P in browser to save as PDF.${NC}"
            head -3 /tmp/pdf_err.txt
          fi
        fi
        pause
        ;;

      4)
        out="reports/exports/executive_summary.html"
        pandoc reports/executive_summary.md -o "$out" --standalone \
          --metadata title="Executive Summary - Detection Engineering" 2>/dev/null
        echo "${GREEN}Saved: $out${NC}"
        ask_open "$out"
        pause
        ;;

      5)
        out="reports/exports/executive_summary.docx"
        pandoc reports/executive_summary.md -o "$out" 2>/dev/null
        echo "${GREEN}Saved: $out${NC}"
        ls -lh "$out"
        ask_open "$out"
        pause
        ;;

      6)
        out="reports/exports/final_presentation.pptx"
        pandoc reports/final_presentation.md -o "$out" 2>/dev/null
        echo "${GREEN}Saved: $out${NC}"
        ls -lh "$out"
        ask_open "$out"
        pause
        ;;

      7)
        echo "${DIM}Exporting ALL formats...${NC}"
        echo ""
        local generated=()

        cp reports/executive_summary.md reports/exports/executive_summary.md
        generated+=("reports/exports/executive_summary.md")
        echo "  [OK] Markdown"

        pandoc reports/executive_summary.md -o reports/exports/executive_summary.html \
          --standalone --metadata title="Executive Summary" 2>/dev/null && \
          { echo "  [OK] HTML"; generated+=("reports/exports/executive_summary.html"); }

        pandoc reports/executive_summary.md -o reports/exports/executive_summary.docx 2>/dev/null && \
          { echo "  [OK] DOCX"; generated+=("reports/exports/executive_summary.docx"); }

        if pandoc reports/executive_summary.md -o reports/exports/executive_summary.pdf --pdf-engine=weasyprint 2>/dev/null; then
          echo "  [OK] PDF"
          generated+=("reports/exports/executive_summary.pdf")
        else
          echo "  [SKIP] PDF (weasyprint not installed)"
        fi

        pandoc reports/final_presentation.md -o reports/exports/final_presentation.pptx 2>/dev/null && \
          { echo "  [OK] PPTX"; generated+=("reports/exports/final_presentation.pptx"); }

        echo ""
        echo "${GREEN}All exports saved to: reports/exports/${NC}"
        ls -lh reports/exports/
        echo ""
        echo "${BOLD}Generated files:${NC}"
        local i=1
        for g in "${generated[@]}"; do
          echo "  $i) $g"
          i=$((i+1))
        done
        echo ""
        read -rp "${BOLD}Open which file? [1-${#generated[@]}, or 0 to skip]: ${NC}" pick
        if [[ "$pick" =~ ^[0-9]+$ ]] && [ "$pick" -ge 1 ] && [ "$pick" -le "${#generated[@]}" ]; then
          ask_open "${generated[$((pick-1))]}"
        fi
        pause
        ;;

      0|"")
        return
        ;;

      *)
        echo "${RED}Invalid choice.${NC}"
        sleep 1
        ;;
    esac
  done
}

action_9() {
  echo "${BOLD}==> Converting all rules to Splunk, Lucene, EQL...${NC}"
  echo ""
  mkdir -p rules/converted/splunk rules/converted/elastic
  for f in rules/sigma/*.yml; do
    base=$(basename "$f" .yml)
    sigma convert -t splunk --without-pipeline "$f" > "rules/converted/splunk/${base}.spl" 2>/dev/null || true
    sigma convert -t lucene -p ecs_windows "$f" > "rules/converted/elastic/${base}.lucene" 2>/dev/null || true
    sigma convert -t eql -p ecs_windows "$f" > "rules/converted/elastic/${base}.eql" 2>/dev/null || true
  done
  echo "${GREEN}Done.${NC}"
  echo "  Splunk:   $(ls rules/converted/splunk/*.spl 2>/dev/null | wc -l) files"
  echo "  Lucene:   $(ls rules/converted/elastic/*.lucene 2>/dev/null | wc -l) files"
  echo "  EQL:      $(ls rules/converted/elastic/*.eql 2>/dev/null | wc -l) files"
  pause
}

action_10() {
  echo "${BOLD}==> Git history${NC}"
  echo ""
  git log --oneline --decorate
  echo ""
  echo "${DIM}Total commits: $(git rev-list --count HEAD)${NC}"
  pause
}

action_11() {
  echo "${BOLD}==> Project statistics${NC}"
  echo ""
  printf "%-32s %s\n" "Sigma rules:" "$(ls rules/sigma/*.yml 2>/dev/null | wc -l)"
  printf "%-32s %s\n" "Correlation rules:" "$(grep -l '^correlation:' rules/sigma/*.yml 2>/dev/null | wc -l)"
  printf "%-32s %s\n" "Base rules:" "$(ls rules/sigma/base_*.yml 2>/dev/null | wc -l)"
  printf "%-32s %s\n" "Converted backends:" "$(ls rules/converted/splunk/*.spl rules/converted/elastic/*.lucene rules/converted/elastic/*.eql 2>/dev/null | wc -l)"
  printf "%-32s %s\n" "Coverage rows:" "$(tail -n +2 coverage/attack_coverage.csv 2>/dev/null | wc -l)"
  printf "%-32s %s\n" "Threat hunts:" "$(ls hunts/*.md 2>/dev/null | grep -v template | wc -l)"
  printf "%-32s %s\n" "Incident reports:" "$(ls incidents/*.md 2>/dev/null | grep -v template | wc -l)"
  printf "%-32s %s\n" "IR playbooks:" "$(ls playbooks/*.md 2>/dev/null | grep -v template | wc -l)"
  printf "%-32s %s\n" "Git-tracked files:" "$(git ls-files | wc -l)"
  printf "%-32s %s\n" "Git commits:" "$(git rev-list --count HEAD 2>/dev/null || echo 0)"
  echo ""
  pause
}

action_12() {
  echo "${BOLD}==> Regenerating presentation...${NC}"
  echo ""
  if command -v pandoc >/dev/null 2>&1; then
    pandoc reports/final_presentation.md -o reports/final_presentation.pptx 2>/dev/null && \
      echo "${GREEN}Wrote reports/final_presentation.pptx${NC}" || \
      echo "${YELLOW}pandoc failed - install pandoc to regenerate PPTX${NC}"
  else
    echo "${YELLOW}pandoc not installed. Run: sudo dnf install -y pandoc${NC}"
  fi
  pause
}

# ============================================================
# Main loop
# ============================================================

trap 'echo ""; echo "Interrupted."; exit 130' INT

while true; do
  show_menu
  read -rp "${BOLD}Choose [0-12]: ${NC}" choice
  case "$choice" in
    1)  action_1 ;;
    2)  action_2 ;;
    3)  action_3 ;;
    4)  action_4 ;;
    5)  action_5 ;;
    6)  action_6 ;;
    7)  action_7 ;;
    8)  action_8 ;;
    9)  action_9 ;;
    10) action_10 ;;
    11) action_11 ;;
    12) action_12 ;;
    0|q|Q|exit) echo "Bye."; exit 0 ;;
    *) echo "${RED}Invalid choice.${NC}"; sleep 1 ;;
  esac
done
