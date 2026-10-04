#!/usr/bin/env bash
set -euo pipefail
mkdir -p data/raw
cd data/raw

clone() {
local url="$1"
local dir="$2"
if [ -d "dir/.git"];thenecho"[+]dir/.git"];thenecho"[+]dir already exists, pulling..."
git -C "dir"pull−−ff−only∣∣trueelseecho"[+]cloningdir"pull−−ff−only∣∣trueelseecho"[+]cloningurl -> dir"gitclone−−depth1"dir"gitclone−−depth1"url" "$dir"
fi
}

clone https://github.com/OTRF/Security-Datasets.git Security-Datasets
clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git EVTX-ATTACK-SAMPLES
clone https://github.com/redcanaryco/atomic-red-team.git atomic-red-team
Optional large BOTS datasets

clone https://github.com/splunk/botsv3.git botsv3 || true
clone https://github.com/splunk/botsv2.git botsv2 || true

echo "[+] datasets fetched"
