#!/usr/bin/env python3
"""Trace who calls setModes/resetModes to emit ESC[4h/l.

How: monkey-patch the four mode methods of insults.ServerProtocol and
print the call stack on each call. Runs the twistd plugin directly, not via the cowrie command.
"""
import sys, traceback

SITE = "/home/cowrie/cowrie-honeypot/cowrie-env/lib/python3.14/site-packages"
sys.path.insert(0, SITE)

from twisted.conch.insults import insults


def _wrap(orig, name):
    def wrapper(self, *a, **kw):
        print(f"\n=== CALL {name}{a} ===", file=sys.stderr, flush=True)
        traceback.print_stack(file=sys.stderr)
        sys.stderr.flush()
        return orig(self, *a, **kw)
    return wrapper


for meth in ("setModes", "resetModes", "setPrivateModes", "resetPrivateModes"):
    if hasattr(insults.ServerProtocol, meth):
        setattr(insults.ServerProtocol, meth,
                _wrap(getattr(insults.ServerProtocol, meth), meth))

print("patched. running twistd...", file=sys.stderr, flush=True)

from twisted.scripts.twistd import run
sys.argv = ["twistd", "--nodaemon", "--pidfile=", "cowrie"]
run()
