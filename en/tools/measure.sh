#!/bin/bash
# Run a full detection against the honeypot, save to reports/<label>.json and print a summary
# Usage: ./tools/measure.sh step02_osrelease
set -e
LABEL="${1:?Usage: measure.sh <label>}"
HOST="${HOST:-192.168.122.252}"
PORT="${PORT:-2222}"
DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$DIR/reports/${LABEL}.json"

python3 -I "$DIR/tools/honeypot_detect.py" --host "$HOST" --port "$PORT" \
    --json --verbose > "$OUT" 2>&1 || true

python3 -I - "$OUT" "$LABEL" <<'PY'
import json, sys
path, label = sys.argv[1], sys.argv[2]
d = json.load(open(path))
print(f"[{label}]  index={d['score']}  raw={d['raw_score']}  "
      f"D={d['summary']['decisive_hits']} S={d['summary']['strong_hits']} W={d['summary']['weak_hits']}")
print("  By layer: " + "  ".join(f"{k}={v}" for k, v in d["by_layer"].items()))
hits = [f for f in d["findings"] if f["hit"]]
print(f"  {len(hits)} hits: " + ", ".join(f["id"] for f in hits))
PY
