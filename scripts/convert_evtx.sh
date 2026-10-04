#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

SRC="data/raw/EVTX-ATTACK-SAMPLES"
OUT="data/processed/evtx-json"
mkdir -p "$OUT"

if [ -x "$HOME/.cargo/bin/evtx_dump" ]; then
  DUMP="$HOME/.cargo/bin/evtx_dump"
elif command -v evtx_dump >/dev/null 2>&1; then
  DUMP="$(command -v evtx_dump)"
else
  echo "[-] evtx_dump not found. Run: cargo install evtx"
  exit 1
fi

echo "[+] using parser: $DUMP"
echo "[+] source: $SRC"
echo "[+] dest:   $OUT"

total=0
ok=0
skip=0
fail=0

while IFS= read -r -d '' f; do
  total=$((total+1))
  rel="${f#$SRC/}"
  out="${OUT}/${rel%.evtx}.jsonl"
  mkdir -p "$(dirname "$out")"

  if [ -s "$out" ]; then
    skip=$((skip+1))
    continue
  fi

  # jsonl = pure JSON lines, no "Record N" headers, no indentation
  if "$DUMP" -o jsonl "$f" > "$out" 2>/dev/null; then
    ok=$((ok+1))
  else
    fail=$((fail+1))
    rm -f "$out"
  fi
done < <(find "$SRC" -name '*.evtx' -print0)

echo "[+] total evtx: $total"
echo "[+] converted:  $ok"
echo "[+] skipped:    $skip"
echo "[+] failed:     $fail"
echo "[+] jsonl files under $OUT:"
find "$OUT" -name '*.jsonl' | wc -l
