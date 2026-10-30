#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Run commands one after another in a single interactive SSH session and print raw output.

Used to manually inspect the honeypot's emulated behaviour. Only sends commands; does not judge results.

Usage:
    probe.py <host> <port> <user> <password> "cmd1" "cmd2" ...
"""
import sys
import time

import paramiko

if len(sys.argv) < 5:
    sys.exit(__doc__)

host, port, user, password = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
cmds = sys.argv[5:]

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect(host, port=port, username=user, password=password,
               look_for_keys=False, allow_agent=False, timeout=15)

chan = client.invoke_shell(term="xterm", width=200, height=50)
time.sleep(1.5)
while chan.recv_ready():
    chan.recv(65535)

for cmd in cmds:
    chan.sendall(cmd + "\n")
    time.sleep(1.0)
    buf = b""
    while chan.recv_ready():
        buf += chan.recv(65535)
    print(f"\n$$$ {cmd}")
    print(buf.decode("utf-8", errors="replace").replace("\r\n", "\n")[:1200])

chan.close()
client.close()
