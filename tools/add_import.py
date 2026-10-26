#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""给指定文件补一行 import（若不存在）。

用法: add_import.py <文件路径> "<import 语句>" [锚点行]
"""
import sys
from pathlib import Path

path = Path(sys.argv[1])
stmt = sys.argv[2]
anchor = sys.argv[3] if len(sys.argv) > 3 else None

src = path.read_text(encoding="utf-8")
if stmt in src:
    print("已存在，跳过")
    sys.exit(0)

if anchor and anchor in src:
    src = src.replace(anchor, stmt + "\n" + anchor, 1)
else:
    # 插在第一个 from cowrie 之后
    lines = src.split("\n")
    idx = next((i for i, ln in enumerate(lines) if ln.startswith("from cowrie")), None)
    if idx is None:
        sys.exit("找不到插入位置")
    lines.insert(idx, stmt)
    src = "\n".join(lines)

path.write_text(src, encoding="utf-8")
print(f"已添加: {stmt}")
