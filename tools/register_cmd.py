#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把新命令模块注册进 Cowrie 的 command_modules 列表。

用法:
    register_cmd.py <模块名>         # 例如 df、sed、ss
"""
import re
import sys
from pathlib import Path

SITE = Path(
    "/home/cowrie/cowrie-honeypot/cowrie-env/lib/python3.14/site-packages/cowrie"
)
INIT = SITE / "commands" / "__init__.py"

if len(sys.argv) != 2:
    sys.exit("用法: register_cmd.py <模块名>")
name = sys.argv[1]

src = INIT.read_text(encoding="utf-8")

if re.search(rf'^    "{re.escape(name)}",$', src, re.MULTILINE):
    print(f"模块 {name} 已注册，跳过。")
    sys.exit(0)

# 在 command_modules 列表里按字母序插入
m = re.search(r"command_modules = \[\n(.*?)\n\]", src, re.DOTALL)
if not m:
    sys.exit("找不到 command_modules 列表")

lines = m.group(1).split("\n")
entries = [ln.strip().strip('",') for ln in lines if ln.strip().startswith('"')]
entries.append(name)
entries = sorted(set(entries))

new_body = "\n".join(f'    "{e}",' for e in entries)
new_src = src[: m.start(1)] + new_body + src[m.end(1):]
INIT.write_text(new_src, encoding="utf-8")
print(f"已注册模块 {name}，当前共 {len(entries)} 个模块")
