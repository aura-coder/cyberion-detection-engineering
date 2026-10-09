#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source .venv/bin/activate

echo "[+] sigma check"
sigma check rules/sigma

echo "[+] rebuilding ATT&CK navigator layer"
python scripts/csv_to_navigator.py

echo "[+] converting rules"
mkdir -p rules/converted/splunk rules/converted/elastic

# Detect available pipelines once
SPLUNK_PIPE=""
if sigma list pipelines splunk 2>/dev/null | grep -q '^sysmon$'; then
  SPLUNK_PIPE="-p sysmon"
fi

for f in rules/sigma/*.yml; do
  base=$(basename "$f" .yml)

  # Splunk
  sigma convert -t splunk $SPLUNK_PIPE --without-pipeline "$f" \
    > "rules/converted/splunk/${base}.spl" 2>/dev/null || echo "  [!] conversion failed: ${base}"

  # Lucene (ECS)
  sigma convert -t lucene -p ecs_windows "$f" \
    > "rules/converted/elastic/${base}.lucene" 2>/dev/null || \
  sigma convert -t lucene --without-pipeline "$f" \
    > "rules/converted/elastic/${base}.lucene" 2>/dev/null || echo "  [!] conversion failed: ${base}"

  # EQL (ECS)
  sigma convert -t eql -p ecs_windows "$f" \
    > "rules/converted/elastic/${base}.eql" 2>/dev/null || \
  sigma convert -t eql --without-pipeline "$f" \
    > "rules/converted/elastic/${base}.eql" 2>/dev/null || echo "  [!] conversion failed: ${base}"
done

echo "[+] removing empty conversions (e.g. temporal correlation rules)"
find rules/converted -type f -size -3c -print -delete | sed 's/^/  empty conversion removed: /'

echo "[+] yaml lint"
python - <<'PY'
import glob, sys, yaml
ok = True
for f in glob.glob('rules/sigma/*.yml'):
    try:
        list(yaml.safe_load_all(open(f)))
        print('  OK  ', f)
    except Exception as e:
        ok = False
        print('  FAIL', f, e)
sys.exit(0 if ok else 1)
PY

echo "[+] done"
