#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Modification 6: fix uptime and the network interface name.

Problem 1: uptime counts from process start
-------------------------------------------
uptime() in cowrie/shell/protocol.py returns:

    time.time() - pt.factory.starttime

factory.starttime is when the Cowrie process started, not when the "system" booted.
So every time the honeypot restarts, the attacker sees an uptime of "booted a few minutes ago".
Real production servers rarely reboot within an hour; this is an obvious suspicious signal.

Fix: push the service start time back by a fixed offset (47 days by default),
so uptime looks like a long-running server. The offset is adjustable in the config.

Problem 2: ifconfig hard-codes eth0
-----------------------------------
The interface name in cowrie/commands/ifconfig.py is hard-coded as "eth0".
systemd's net.ifnames has enabled predictable interface names by default since 2015
(enp0s3, ens33, ens192...); modern Debian/Ubuntu no longer use eth0.

Fix: read the interface name from config, defaulting to enp1s0 -- consistent with
the naming of the VM's real second NIC and with the style of /sys/class/net.

Usage
-----
    python3 patch_uptime_nic.py            # apply
    python3 patch_uptime_nic.py --revert   # roll back
"""

from __future__ import annotations

import re
import shutil
import sys
from pathlib import Path

SITE = Path(
    "/home/cowrie/cowrie-honeypot/cowrie-env/lib/python3.14/site-packages/cowrie"
)
PROTOCOL = SITE / "shell" / "protocol.py"
IFCONFIG = SITE / "commands" / "ifconfig.py"
CFG = Path("/home/cowrie/cowrie-honeypot/etc/cowrie.cfg")

MARKER = "[Mod 6]"

# Default "days running". Change this number to adjust the faked uptime.
DEFAULT_UPTIME_DAYS = 47


def patch_uptime(check_only: bool) -> int:
    """Change uptime() to a calculation based on a fixed offset."""
    src = PROTOCOL.read_text(encoding="utf-8")
    if MARKER + " uptime" in src:
        print("  uptime patch already applied, skipping")
        return 0

    old = '''    def uptime(self):
        """
        Uptime
        """
        pt = self.getProtoTransport()
        r = time.time() - pt.factory.starttime
        return r
'''

    new = f'''    def uptime(self):
        """
        Uptime

        {MARKER} On a real system uptime resets after a reboot, but a production
        server rarely reboots within an hour. Cowrie originally counted from process
        start, so every honeypot restart showed "booted a few minutes ago", an obvious giveaway.

        Changed to: push the service start time back by a fixed offset to simulate long uptime.
        The offset is set by [honeypot] uptime_offset_days, default {DEFAULT_UPTIME_DAYS} days.
        """
        pt = self.getProtoTransport()
        offset_days = CowrieConfig.getint(
            "honeypot", "uptime_offset_days", fallback={DEFAULT_UPTIME_DAYS}
        )
        boot_time = pt.factory.starttime - offset_days * 86400
        return time.time() - boot_time
'''

    if old not in src:
        print("  uptime anchor not found")
        return 1

    if check_only:
        print("  uptime anchor present")
        return 0

    PROTOCOL.write_text(src.replace(old, new, 1), encoding="utf-8")
    print(f"  Modified uptime(), offset {DEFAULT_UPTIME_DAYS} days")
    return 0


def patch_ifconfig(check_only: bool) -> int:
    """Replace ifconfig's hard-coded eth0 with a configurable modern interface name."""
    src = IFCONFIG.read_text(encoding="utf-8")
    if MARKER + " nic" in src:
        print("  ifconfig patch already applied, skipping")
        return 0

    # 1) Resolve the interface name at the start of call()
    anchor = "    def call(self) -> None:\n"
    if anchor not in src:
        print("  ifconfig anchor not found")
        return 1

    inject = f'''    def call(self) -> None:
        # {MARKER} nic name read from config, defaults to modern predictable naming (systemd net.ifnames)
        nic_name = CowrieConfig.get("honeypot", "nic_name", fallback="enp1s0")
'''

    if check_only:
        print("  ifconfig anchor present")
        return 0

    src = src.replace(anchor, inject, 1)

    # 2) Replace eth0 in the output template with the variable
    src = src.replace("result = f\"\"\"eth0      Link encap:Ethernet",
                      "result = f\"\"\"{nic_name:<9s} Link encap:Ethernet", 1)

    IFCONFIG.write_text(src, encoding="utf-8")
    print("  Changed ifconfig interface name -> enp1s0 (configurable)")
    return 0


def ensure_import(check_only: bool) -> int:
    """Make sure protocol.py imports CowrieConfig."""
    src = PROTOCOL.read_text(encoding="utf-8")
    if "from cowrie.core.config import CowrieConfig" in src:
        print("  CowrieConfig already imported")
        return 0
    if check_only:
        print("  CowrieConfig import missing")
        return 1
    # Add before the first 'from cowrie' import
    m = re.search(r"^from cowrie\.", src, re.MULTILINE)
    if m is None:
        print("  Import position not found")
        return 1
    src = (src[: m.start()]
           + "from cowrie.core.config import CowrieConfig\n"
           + src[m.start():])
    PROTOCOL.write_text(src, encoding="utf-8")
    print("  Added CowrieConfig import")
    return 0


def main() -> int:
    args = set(sys.argv[1:])
    check_only = "--check" in args

    if "--revert" in args:
        for p in (PROTOCOL, IFCONFIG):
            for bak in p.parent.glob(p.name + ".bak-*"):
                shutil.copy2(bak, p)
                print(f"Rolled back {p.name} <- {bak.name}")
        return 0

    if not check_only:
        # Back up
        for p in (PROTOCOL, IFCONFIG):
            bak = p.with_suffix(p.suffix + ".bak-uptime")
            if not bak.exists():
                shutil.copy2(p, bak)
                print(f"Backed up {p.name} -> {bak.name}")

    rc = 0
    rc |= ensure_import(check_only)
    rc |= patch_uptime(check_only)
    rc |= patch_ifconfig(check_only)

    if not check_only:
        print("\nDone. Remember to clear pycache and restart Cowrie.")
    return rc


if __name__ == "__main__":
    sys.exit(main())
