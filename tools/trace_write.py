#!/usr/bin/env python3
"""追踪 ESC[4h/l 究竟由谁写进 SSH 通道。

思路：在 Cowrie 的 SSH session/channel 层拦截写入，打印调用栈，
判断序列是 Cowrie 自己产生的，还是 Twisted 终端渲染层产生的。
"""
import sys, traceback

SITE = "/home/cowrie/cowrie-honeypot/cowrie-env/lib/python3.14/site-packages"
sys.path.insert(0, SITE)

from twisted.conch.ssh import session as ssh_session

_orig = ssh_session.SSHSession.write

def _traced(self, data):
    raw = data if isinstance(data, bytes) else str(data).encode()
    if b"\x1b[4h" in raw or b"\x1b[4l" in raw:
        print("\n=== SSHSession.write 含 4h/4l ===", file=sys.stderr, flush=True)
        print("data:", repr(raw), file=sys.stderr, flush=True)
        traceback.print_stack(file=sys.stderr)
        sys.stderr.flush()
    return _orig(self, data)

ssh_session.SSHSession.write = _traced

from twisted.scripts.twistd import run
sys.argv = ["twistd", "--nodaemon", "--pidfile=", "cowrie"]
run()
