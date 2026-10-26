#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""在 site-packages 里按字节搜索指定的转义序列，定位其定义位置。

用法: find_esc.py <根目录> <bytes字面量>
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
