#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Modification 3: remove the ESC[4h / ESC[4l terminal sequences from Cowrie's output.

Problem
-------
Before and after every command, Cowrie sends ESC[4h (enable insert mode) and
ESC[4l (disable insert mode) to the client. Real bash never sends these two
sequences on its own, so this is a reliable strong feature for identifying a honeypot.

Source (measured call stack)
----------------------------
After a command finishes:

  cowrie/shell/honeypot.py:947  HoneyPotShell.resume()
    -> self.protocol.setInsertMode()
      -> twisted/conch/recvline.py:406  terminal.setModes([insults.modes.IRM])
        -> twisted/conch/insults/insults.py:713  write(b"\\x1b[4h")

Before each command starts:

  cowrie/shell/protocol.py:513  HoneyPotBaseProtocol.call_command()
    -> self.setTypeoverMode()
      -> twisted/conch/recvline.py:410  terminal.resetModes([IRM])
        -> twisted/conch/insults/insults.py:723  write(b"\\x1b[4l")

Both methods are defined on Twisted's recvline.HistoricRecvLine.
Cowrie's HoneyPotInteractiveProtocol also inherits from it, so the Twisted
version is the one that actually runs.

Fix
---
Override setInsertMode / setTypeoverMode as no-ops in the
HoneyPotInteractiveProtocol class of cowrie/shell/protocol.py.

Why not change Twisted:
  Changes to site-packages/twisted are lost when Twisted is upgraded, and the blast radius is too large.
  Overriding in Cowrie's subclass is narrower and more durable.

Usage
-----
    python3 patch_underline.py            # apply the patch
    python3 patch_underline.py --check    # check only
    python3 patch_underline.py --revert   # roll back
"""

from __future__ import annotations

import re
import shutil
import sys
from pathlib import Path

TARGET = Path(
    "/home/cowrie/cowrie-honeypot/cowrie-env/lib/python3.14/site-packages"
    "/cowrie/shell/protocol.py"
)

BACKUP = TARGET.with_suffix(".py.bak-underline")
MARKER = "[Mod 3]"

# Method block to insert. 4-space indent = class method level.
#
# Key point: in Twisted these two methods do two things --
#   1. maintain the self.mode state ("insert" / "typeover")
#   2. send ESC[4h / ESC[4l to the client
# We only need to drop thing 2; thing 1 must be kept --
# Cowrie's characterReceived() relies on self.mode to decide whether to insert or overwrite.
# Overriding the whole method as a no-op would lose the state and cause AttributeError.
PATCH_BLOCK = '''
    # ------------------------------------------------------------------
    # [Mod 3] Suppress terminal mode switch sequences
    #
    # Real bash does not send ESC[4l / ESC[4h around every command. Through
    # Twisted recvline's insert/typeover mode switching, Cowrie inserts one
    # sequence when the shell resumes and one when a command starts, forming
    # an identifiable fingerprint.
    #
    # Note: only the sequences are removed; self.mode is kept. characterReceived()
    # relies on this state to decide insert vs. overwrite; dropping it crashes.
    # ------------------------------------------------------------------
    def setInsertMode(self) -> None:
        """Equivalent to Twisted's implementation, but does not send ESC[4h."""
        self.mode = "insert"

    def setTypeoverMode(self) -> None:
        """Equivalent to Twisted's implementation, but does not send ESC[4l."""
        self.mode = "typeover"

'''

# Target class: the real interactive shell goes through here
TARGET_CLASS = "class HoneyPotInteractiveProtocol(HoneyPotBaseProtocol, recvline.HistoricRecvLine):"


def find_class_body_anchor(src: str, class_decl: str):
    """Find an insertion anchor in the target class: just before the first 'def ' of the class body.

    Returns the insertion position (character index).
    """
    start = src.find(class_decl)
    if start < 0:
        return None

    # Find the first method definition in this class body
    m = re.search(r"\n    def \w+\(", src[start:])
    if m is None:
        return None
    return start + m.start() + 1  # +1 skips the newline, insert before def


def main() -> int:
    args = set(sys.argv[1:])

    if not TARGET.exists():
        print(f"Target file not found: {TARGET}")
        return 2

    # ---- Roll back ----
    if "--revert" in args:
        if not BACKUP.exists():
            print("No backup file found, cannot roll back.")
            return 1
        shutil.copy2(BACKUP, TARGET)
        print(f"Rolled back: {TARGET}")
        return 0

    src = TARGET.read_text(encoding="utf-8")

    if MARKER in src:
        print("Patch already applied, skipping.")
        return 0

    anchor = find_class_body_anchor(src, TARGET_CLASS)
    if anchor is None:
        print(f"Target class not found: {TARGET_CLASS}")
        return 1

    if "--check" in args:
        print(f"Target class exists, insertion point {anchor}; patch can be applied.")
        return 0

    # ---- Back up and apply ----
    shutil.copy2(TARGET, BACKUP)
    new_src = src[:anchor] + PATCH_BLOCK.lstrip("\n") + "\n" + src[anchor:]
    TARGET.write_text(new_src, encoding="utf-8")

    # ---- Verify the insertion point is correct ----
    check = TARGET.read_text(encoding="utf-8")
    idx = check.find(MARKER)
    before = check[:idx]
    last_class = None
    for m in re.finditer(r"^class (\w+)", before, re.MULTILINE):
        last_class = m.group(1)

    print(f"Patch applied: {TARGET}")
    print(f"Backup file: {BACKUP}")
    print(f"Insertion point belongs to class: {last_class}")
    if last_class != "HoneyPotInteractiveProtocol":
        print("Warning: insertion point may be wrong, please check.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
