#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Register a new command module in Cowrie's command_modules list.

Usage:
    register_cmd.py <module name>     # e.g. df, sed, ss
"""
import re
import sys
from pathlib import Path

SITE = Path(
    "/home/cowrie/cowrie-honeypot/cowrie-env/lib/python3.14/site-packages/cowrie"
)
INIT = SITE / "commands" / "__init__.py"

if len(sys.argv) != 2:
    sys.exit("Usage: register_cmd.py <module name>")
name = sys.argv[1]

src = INIT.read_text(encoding="utf-8")

if re.search(rf'^    "{re.escape(name)}",$', src, re.MULTILINE):
    print(f"Module {name} already registered, skipping.")
    sys.exit(0)

# Insert into the command_modules list in alphabetical order
m = re.search(r"command_modules = \[\n(.*?)\n\]", src, re.DOTALL)
if not m:
    sys.exit("command_modules list not found")

lines = m.group(1).split("\n")
entries = [ln.strip().strip('",') for ln in lines if ln.strip().startswith('"')]
entries.append(name)
entries = sorted(set(entries))

new_body = "\n".join(f'    "{e}",' for e in entries)
new_src = src[: m.start(1)] + new_body + src[m.end(1):]
INIT.write_text(new_src, encoding="utf-8")
print(f"Registered module {name}; {len(entries)} modules in total")
