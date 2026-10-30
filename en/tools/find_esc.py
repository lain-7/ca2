#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Search site-packages byte-wise for a given escape sequence to locate where it is defined.

Usage: find_esc.py <root dir> <bytes literal>
     find_esc.py /path/to/site-packages "\x1b[4l"
"""
import os
import sys

root = sys.argv[1]
needle = sys.argv[2].encode().decode("unicode_escape").encode("latin1")

for dirpath, _dirnames, files in os.walk(root):
    for fn in files:
        if not fn.endswith((".py", ".pyc")):
            continue
        path = os.path.join(dirpath, fn)
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError:
            continue
        if needle in data:
            print(path.replace(root, ""))
