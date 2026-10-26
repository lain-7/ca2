#!/bin/bash
# 对蜜罐跑一次完整检测，结果存到 reports/<标签>.json，并打印摘要
# 用法：./tools/measure.sh step02_osrelease
set -e
LABEL="${1:?用法: measure.sh <标签>}"
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
print("  分项: " + "  ".join(f"{k}={v}" for k, v in d["by_layer"].items()))
hits = [f for f in d["findings"] if f["hit"]]
print(f"  命中 {len(hits)} 项: " + ", ".join(f["id"] for f in hits))
PY
