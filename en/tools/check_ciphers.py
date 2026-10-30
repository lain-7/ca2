#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""List the SSH cryptographic algorithms supported by the installed Twisted."""
from twisted.conch.ssh import transport

c = transport._getSupportedCiphers()
print("=== Supported ciphers ===")
for item in c:
    print(" ", item)

print("\n=== SSHFactory default cipher order (from transport source) ===")
import inspect, re
src = inspect.getsource(transport)
for pat in [r'ciphers\s*=\s*\((.*?)\)', r'macs\s*=\s*\((.*?)\)']:
    m = re.search(pat, src, re.DOTALL)
    if m:
        print(pat.split("\\")[0], ":", " ".join(m.group(1).split()))
