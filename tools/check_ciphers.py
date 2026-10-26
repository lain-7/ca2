#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""列出当前 Twisted 支持的 SSH 密码学算法。"""
from twisted.conch.ssh import transport

c = transport._getSupportedCiphers()
print("=== 支持的 cipher ===")
for item in c:
    print(" ", item)

print("\n=== SSHFactory 默认 ciphers 顺序（从 transport 源码）===")
import inspect, re
src = inspect.getsource(transport)
for pat in [r'ciphers\s*=\s*\((.*?)\)', r'macs\s*=\s*\((.*?)\)']:
    m = re.search(pat, src, re.DOTALL)
    if m:
        print(pat.split("\\")[0], ":", " ".join(m.group(1).split()))
