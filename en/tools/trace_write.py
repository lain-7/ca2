#!/usr/bin/env python3
"""Trace exactly who writes ESC[4h/l into the SSH channel.

Approach: intercept writes at Cowrie's SSH session/channel layer and print the call stack,
to tell whether the sequence comes from Cowrie itself or from Twisted's terminal rendering layer.
"""
import sys, traceback

SITE = "/home/cowrie/cowrie-honeypot/cowrie-env/lib/python3.14/site-packages"
sys.path.insert(0, SITE)

from twisted.conch.ssh import session as ssh_session

_orig = ssh_session.SSHSession.write

def _traced(self, data):
    raw = data if isinstance(data, bytes) else str(data).encode()
    if b"\x1b[4h" in raw or b"\x1b[4l" in raw:
        print("\n=== SSHSession.write contains 4h/4l ===", file=sys.stderr, flush=True)
        print("data:", repr(raw), file=sys.stderr, flush=True)
        traceback.print_stack(file=sys.stderr)
        sys.stderr.flush()
    return _orig(self, data)

ssh_session.SSHSession.write = _traced

from twisted.scripts.twistd import run
sys.argv = ["twistd", "--nodaemon", "--pidfile=", "cowrie"]
run()
