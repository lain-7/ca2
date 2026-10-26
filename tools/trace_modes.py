#!/usr/bin/env python3
"""追踪谁在调用 setModes/resetModes 生成 ESC[4h/l。

原理：给 insults.ServerProtocol 的四个模式方法打猴子补丁，
在调用时打印调用栈。直接跑 twistd 插件，不通过 cowrie 命令。
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
