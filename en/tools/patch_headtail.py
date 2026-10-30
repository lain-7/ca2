#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Modification 4: add POSIX numeric shorthand to Cowrie's head / tail.

Problem
-------
Real GNU coreutils head/tail accept three forms:

    head -3 file        numeric shorthand (supported by POSIX and GNU)
    head -n 3 file      explicit option
    head -n3 file       option and argument joined

Cowrie's commands/fs.py parses with getopt.getopt(args, "n:"),
which only understands the second form. The first is treated as an invalid option:

    head: invalid option -- '3'

This is a strong honeypot signal -- a real head binary would never reject -3.

Fix
---
Before parsing arguments, rewrite ``-N`` (N all digits) as ``-n N``.
This leaves the original getopt logic untouched and keeps the change minimal.

Also handle ``-n3`` (joined form), since GNU accepts it too.

Usage
-----
    python3 patch_headtail.py            # apply the patch
    python3 patch_headtail.py --revert   # roll back
"""

from __future__ import annotations

import re
import shutil
import sys
from pathlib import Path

TARGET = Path(
    "/home/cowrie/cowrie-honeypot/cowrie-env/lib/python3.14/site-packages"
    "/cowrie/commands/fs.py"
)
BACKUP = TARGET.with_suffix(".py.bak-headtail")
MARKER = "[Mod 4]"

# Insert a module-level helper shared by both commands
HELPER = '''
# ----------------------------------------------------------------------
# [Mod 4] Normalise numeric shorthand for head / tail
#
# GNU coreutils accepts both "-3" and "-n 3". Cowrie's original getopt only
# understands the latter, so "head -3 file" reports invalid option. Rewrite before parsing.
# ----------------------------------------------------------------------
def _normalize_numeric_shorthand(args):
    """Rewrite ["-3", "file"] as ["-n", "3", "file"]; "-n3" as ["-n", "3"]."""
    out = []
    for arg in args:
        if len(arg) > 1 and arg[0] == "-" and arg[1:].isdigit():
            # -3 → -n 3
            out.extend(["-n", arg[1:]])
        elif arg.startswith("-n") and len(arg) > 2 and arg[2:].isdigit():
            # -n3 → -n 3
            out.extend(["-n", arg[2:]])
        else:
            out.append(arg)
    return out
'''


def main() -> int:
    args = set(sys.argv[1:])

    if not TARGET.exists():
        print(f"Target file not found: {TARGET}")
        return 2

    if "--revert" in args:
        if not BACKUP.exists():
            print("No backup file, cannot roll back.")
            return 1
        shutil.copy2(BACKUP, TARGET)
        print(f"Rolled back: {TARGET}")
        return 0

    src = TARGET.read_text(encoding="utf-8")

    if MARKER in src:
        print("Patch already applied, skipping.")
        return 0

    # ---- 1) Insert the helper at the top of the file (before the first class definition) ----
    m = re.search(r"^class \w+", src, re.MULTILINE)
    if m is None:
        print("Class definition not found, patch failed.")
        return 1
    insert_at = m.start()

    # ---- 2) Make the getopt calls in both start() methods normalise first ----
    # tail: optlist, args = getopt.getopt(self.args, "n:")
    src_new = src[:insert_at] + HELPER.lstrip("\n") + "\n\n" + src[insert_at:]

    replacements = [
        (
            'optlist, args = getopt.getopt(self.args, "n:")',
            'optlist, args = getopt.getopt(_normalize_numeric_shorthand(self.args), "n:")',
        ),
        (
            'optlist, args = getopt.getopt(self.args, "c:n:")',
            'optlist, args = getopt.getopt(_normalize_numeric_shorthand(self.args), "c:n:")',
        ),
    ]

    applied = 0
    for old, new in replacements:
        if old in src_new:
            src_new = src_new.replace(old, new, 1)
            applied += 1

    if applied == 0:
        print("getopt call site not found, patch failed.")
        return 1

    if "--check" in args:
        print(f"Patch can be applied; {applied} getopt call(s) will be replaced.")
        return 0

    shutil.copy2(TARGET, BACKUP)
    TARGET.write_text(src_new, encoding="utf-8")

    print(f"Patch applied: {TARGET}")
    print(f"Backup file: {BACKUP}")
    print(f"Rewrote {applied} getopt call(s) (head / tail)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
