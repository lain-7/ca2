#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Add an import line to a given file (if not already present).

Usage: add_import.py <file path> "<import statement>" [anchor line]
"""
import sys
from pathlib import Path

path = Path(sys.argv[1])
stmt = sys.argv[2]
anchor = sys.argv[3] if len(sys.argv) > 3 else None

src = path.read_text(encoding="utf-8")
if stmt in src:
    print("Already present, skipping")
    sys.exit(0)

if anchor and anchor in src:
    src = src.replace(anchor, stmt + "\n" + anchor, 1)
else:
    # Insert after the first 'from cowrie' line
    lines = src.split("\n")
    idx = next((i for i, ln in enumerate(lines) if ln.startswith("from cowrie")), None)
    if idx is None:
        sys.exit("Insertion point not found")
    lines.insert(idx, stmt)
    src = "\n".join(lines)

path.write_text(src, encoding="utf-8")
print(f"Added: {stmt}")
