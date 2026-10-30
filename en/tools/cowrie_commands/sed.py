# SPDX-License-Identifier: BSD-3-Clause
# -*- coding: utf-8 -*-
"""Modification 7: an implementation of sed for Cowrie (common subset).

Background
----------
Cowrie originally had no commands/sed.py, so running sed falls into the "generic binary" fallback:

    -bash: /usr/bin/sed: cannot execute binary file: Exec format error

sed is an essential POSIX tool; a real system can never fail to run it. This is a decisive fingerprint.

Scope
-----
Only the part attackers type most often in a honeypot (not a full sed):

    sed -n 1p file          print line 1
    sed -n 1,5p file        print lines 1-5
    sed 's/a/b/' file       replace first match per line
    sed 's/a/b/g' file      replace all
    sed -n '/pat/p' file    print matching lines
    sed 'N d' file          delete a given line
    sed '1,3d' file         delete lines 1-3
    sed -e ... -e ...       multiple expressions
    piped input             echo x | sed 's/x/y/'

Not supported (reports an explicit error rather than failing silently):
    branch commands b/t, hold space h/H/g/G/x, combined address ranges, advanced regex syntax

Why not use the real sed: the whole design of the honeypot is "never execute real binaries".
Calling /usr/bin/sed would expose the host's sed to the attacker
and lose all logging capability.
"""

from __future__ import annotations

import re

from cowrie.shell.command import HoneyPotCommand

commands = {}


class Command_sed(HoneyPotCommand):
    """sed -- stream editor (common subset)."""

    def _parse_script(self, script: str) -> dict:
        """Parse a sed script into a simple operation description.

        Supports multiple commands separated by ; or newlines, executed in order.
        """
        ops = []

        for part in re.split(r"[;\n]", script):
            part = part.strip()
            if not part:
                continue

            # ---- s/// substitution ----
            m = re.match(r"^s(.)(.*?)\1(.*?)\1([gGiI0-9]*)$", part)
            if m:
                _delim, pattern, repl, flags = m.groups()
                ops.append({
                    "type": "sub",
                    "pattern": pattern,
                    "repl": repl,
                    "global": "g" in flags.lower(),
                    "ignorecase": "i" in flags.lower(),
                })
                continue

            # ---- [addr]d delete ----
            m = re.match(r"^(?:(\d+)(?:,(\d+))?)?d$", part)
            if m:
                ops.append({
                    "type": "delete",
                    "start": int(m.group(1)) if m.group(1) else None,
                    "end": int(m.group(2)) if m.group(2) else
                           (int(m.group(1)) if m.group(1) else None),
                })
                continue

            # ---- [addr]p print ----
            m = re.match(r"^(?:(\d+)(?:,(\d+))?)?p$", part)
            if m:
                ops.append({
                    "type": "print",
                    "start": int(m.group(1)) if m.group(1) else None,
                    "end": int(m.group(2)) if m.group(2) else
                           (int(m.group(1)) if m.group(1) else None),
                })
                continue

            # ---- /pattern/p print matching lines ----
            m = re.match(r"^/(.*?)/p$", part)
            if m:
                ops.append({"type": "print_match", "pattern": m.group(1)})
                continue

            # ---- /pattern/d delete matching lines ----
            m = re.match(r"^/(.*?)/d$", part)
            if m:
                ops.append({"type": "delete_match", "pattern": m.group(1)})
                continue

            # Unrecognised -> record it and report an error at run time
            ops.append({"type": "unknown", "raw": part})

        return {"ops": ops}

    def _line_in_range(self, lineno: int, start, end) -> bool:
        """Check whether a line number falls within [start, end] (1-based)."""
        if start is None:
            return True
        if end is None:
            end = start
        return start <= lineno <= end

    def _apply(self, lines: list[str], script: dict) -> tuple[list[str], bool]:
        """Execute the script. Returns (output lines, whether printing was explicitly requested)."""
        ops = script["ops"]

        # -n mode: only p / print_match produce output
        auto_print = not self.quiet

        result: list[str] = []
        delete_all = False

        for lineno, line in enumerate(lines, start=1):
            current = line
            deleted = False
            printed = False

            for op in ops:
                t = op["type"]

                if t == "sub":
                    flags = re.IGNORECASE if op["ignorecase"] else 0
                    try:
                        pattern = re.compile(op["pattern"], flags)
                    except re.error:
                        continue
                    count = 0 if op["global"] else 1
                    current = pattern.sub(op["repl"], current, count=count)

                elif t == "delete":
                    if self._line_in_range(lineno, op["start"], op["end"]):
                        deleted = True

                elif t == "delete_match":
                    try:
                        if re.search(op["pattern"], current):
                            deleted = True
                    except re.error:
                        pass

                elif t == "print":
                    if self._line_in_range(lineno, op["start"], op["end"]):
                        printed = True

                elif t == "print_match":
                    try:
                        if re.search(op["pattern"], current):
                            printed = True
                    except re.error:
                        pass

                elif t == "unknown":
                    self.errorWrite(
                        f"sed: -e expression #1, char 1: unknown command: "
                        f"`{op['raw'][:1]}'\n"
                    )
                    deleted = True

            if deleted:
                continue

            if current != line or printed:
                # Substituted or explicitly asked to print: output this line
                result.append(current)
                if printed and auto_print:
                    pass  # Already added, avoid duplicates
            elif auto_print:
                result.append(current)

        return result, not auto_print

    def call(self) -> None:
        self.quiet = False          # -n
        self.extended = False       # -E / -r
        self.in_place = False       # -i
        scripts: list[str] = []
        files: list[str] = []

        args = list(self.args)

        # ---- Parse options ----
        i = 0
        while i < len(args):
            a = args[i]
            if a == "-n":
                self.quiet = True
            elif a in ("-E", "-r", "--regexp-extended"):
                self.extended = True
            elif a.startswith("-i"):
                self.in_place = True
            elif a == "-e":
                i += 1
                if i < len(args):
                    scripts.append(args[i])
            elif a.startswith("-e") and len(a) > 2:
                scripts.append(a[2:])
            elif a == "--":
                files.extend(args[i + 1:])
                break
            elif a.startswith("-") and len(a) > 1 and not a[1].isdigit():
                # Combined single-letter options, e.g. -ne
                for ch in a[1:]:
                    if ch == "n":
                        self.quiet = True
                    elif ch in ("E", "r"):
                        self.extended = True
                    elif ch == "i":
                        self.in_place = True
            else:
                files.append(a)
            i += 1

        # ---- The first non-option argument is the script (when no -e) ----
        if not scripts:
            if not files:
                self.errorWrite("Usage: sed [OPTION]... {script-only-if-no-other-script} "
                                "[input-file]...\n")
                self.exit(1)
                return
            scripts.append(files.pop(0))

        if self.in_place:
            self.errorWrite(
                "sed: -i: in-place editing is not supported on this system\n"
            )
            self.exit(1)
            return

        script = self._parse_script(";".join(scripts))

        # ---- Get input ----
        if files:
            for fname in files:
                path = self.fs.resolve_path(fname, self.cwd)
                if not self.fs.exists(path) or not self.fs.isfile(path):
                    self.errorWrite(
                        f"sed: can't read {fname}: No such file or directory\n"
                    )
                    self.exit(1)
                    return
                data = self.fs.file_contents(path)
                text = data.decode("utf-8", errors="replace")
                lines = text.split("\n")
                if lines and lines[-1] == "":
                    lines.pop()
                out, _ = self._apply(lines, script)
                for ln in out:
                    self.write(ln + "\n")
        elif self.input_data is not None:
            text = self.input_data.decode("utf-8", errors="replace")
            lines = text.split("\n")
            if lines and lines[-1] == "":
                lines.pop()
            out, _ = self._apply(lines, script)
            for ln in out:
                self.write(ln + "\n")
        else:
            self.errorWrite("sed: no input files\n")
            self.exit(1)
            return

        self.exit(0)

    def lineReceived(self, line) -> None:
        # Support feeding lines via pipe/stdin
        if not hasattr(self, "_stdin"):
            self._stdin = []
        self._stdin.append(line)

    def eofReceived(self) -> None:
        self.exit(0)


commands["/bin/sed"] = Command_sed
commands["/usr/bin/sed"] = Command_sed
commands["sed"] = Command_sed
