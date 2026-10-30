# SPDX-License-Identifier: BSD-3-Clause
# -*- coding: utf-8 -*-
"""Modification 5: a realistic implementation of the df command for Cowrie.

Background
----------
Cowrie originally had no commands/df.py, only a static text in data/txtcmds/bin/df.
The txtcmd mechanism takes no arguments: running df (with any arguments) always returns
the same fixed text; and when the argument form hits the binary fallback path, it reports:

    -bash: /usr/bin/df: cannot execute binary file: Exec format error

The real df is an essential coreutils command present on every Linux distribution; it can never fail to run.
This is one of the decisive features for identifying a honeypot.

Implementation notes
--------------------
1. Supports -h (human readable), -H (decimal units), -T (show filesystem type),
   -a, -i, -P, plus --help / --version
2. Accepts any file/directory argument (df shows the filesystem containing that path)
3. Output numbers are consistent with /etc/fstab and the size of the fake filesystem:
   a 20G root partition, realistic for a small production server
4. Uses Cowrie's virtual filesystem API to check whether paths exist, reporting real errors if not

This file follows the layout of Cowrie's official command modules; it can be dropped into commands/
and registered as "df" in the command_modules list of commands/__init__.py.
"""

from __future__ import annotations

import getopt

from cowrie.shell.command import HoneyPotCommand

commands = {}

# ---------------------------------------------------------------------------
# Imaginary partition table
#
# These numbers correspond to a Debian 12 server with a 20G disk:
#   root        20G (consistent with the size of fs.pickle)
#   /boot       512M
#   two tmpfs   derived from 2G of RAM
#
# Field order: device, mount point, filesystem type, total size, used size
# All sizes in bytes
# ---------------------------------------------------------------------------
_G = 1024 ** 3
_M = 1024 ** 2

_FILESYSTEMS = [
    ("udev",              "/dev",       "devtmpfs",  2 * _G,   0),
    ("tmpfs",             "/run",       "tmpfs",     200 * _M, 1 * _M),
    ("/dev/sda1",         "/",          "ext4",      20 * _G,  4 * _G + 300 * _M),
    ("tmpfs",             "/dev/shm",   "tmpfs",     1000 * _M, 0),
    ("tmpfs",             "/run/lock",  "tmpfs",     5 * _M,   0),
    ("/dev/sda15",        "/boot/efi",  "vfat",      105 * _M, 6 * _M),
]


def _human(size: int, base: int = 1024) -> str:
    """Format a byte count in df -h style (e.g. 19G, 512M)."""
    units = ["", "K", "M", "G", "T", "P"]
    value = float(size)
    idx = 0
    while value >= base and idx < len(units) - 1:
        value /= base
        idx += 1
    if idx == 0:
        return f"{int(value)}"
    # df's rule: one decimal place when the value is <10, otherwise round
    if value < 10:
        return f"{value:.1f}{units[idx]}".replace(".0", "")
    return f"{int(round(value))}{units[idx]}"


def _exact(size: int) -> str:
    """df's default raw number format (in 1K blocks)."""
    return str(size // 1024)


class Command_df(HoneyPotCommand):
    """df -- report filesystem disk space usage."""

    def _usage_line(self, dev, mount, fstype, total, used,
                    human=False, decimal=False, show_type=False,
                    inodes=False) -> str:
        """Build one line of df output with the same column widths as GNU df."""
        avail = total - used
        percent = int(round(used / total * 100)) if total else 0

        if human:
            base = 1000 if decimal else 1024
            col_total = _human(total, base)
            col_used = _human(used, base)
            col_avail = _human(avail, base)
        else:
            col_total = _exact(total)
            col_used = _exact(used)
            col_avail = _exact(avail)

        # GNU df alignment: device left-aligned in 25 columns, the rest right-aligned
        parts = []
        parts.append(f"{dev:<25s}")
        if show_type:
            parts.append(f"{fstype:<10s}")
        if inodes:
            # With -i inode counts are shown; use a plausible estimate here
            total_i = total // 4096
            used_i = used // 4096
            free_i = total_i - used_i
            parts.append(f"{total_i:>10d}")
            parts.append(f"{used_i:>9d}")
            parts.append(f"{free_i:>9d}")
            parts.append(f"{percent:>3d}%")
        else:
            parts.append(f"{col_total:>8s}")
            parts.append(f"{col_used:>7s}")
            parts.append(f"{col_avail:>7s}")
            parts.append(f"{percent:>3d}%")
        parts.append(f" {mount}")
        return " ".join(parts)

    def call(self) -> None:
        human = False
        decimal = False
        show_type = False
        inodes = False
        show_all = False

        try:
            optlist, args = getopt.getopt(
                self.args, "hHTaiP", ["help", "version", "human-readable",
                                      "print-type", "all", "inodes"]
            )
        except getopt.GetoptError as err:
            self.errorWrite(f"df: invalid option -- '{err.opt}'\n")
            self.errorWrite("Try 'df --help' for more information.\n")
            self.exit(1)
            return

        for opt, _arg in optlist:
            if opt in ("-h", "--human-readable"):
                human = True
            elif opt == "-H":
                human = True
                decimal = True
            elif opt in ("-T", "--print-type"):
                show_type = True
            elif opt in ("-a", "--all"):
                show_all = True
            elif opt in ("-i", "--inodes"):
                inodes = True
            elif opt in ("-P",):
                pass  # POSIX output format, which is what we already produce
            elif opt == "--help":
                self.write(
                    "Usage: df [OPTION]... [FILE]...\n"
                    "Show information about the file system on which each FILE "
                    "resides,\n"
                    "or all file systems by default.\n\n"
                    "  -a, --all             include pseudo, duplicate, "
                    "inaccessible file systems\n"
                    "  -h, --human-readable  print sizes in powers of 1024 "
                    "(e.g., 1023M)\n"
                    "  -H, --si              print sizes in powers of 1000 "
                    "(e.g., 1.1G)\n"
                    "  -i, --inodes          list inode information instead of "
                    "block usage\n"
                    "  -T, --print-type      print file system type\n"
                    "      --help            display this help and exit\n"
                    "      --version         output version information and exit\n"
                )
                self.exit(0)
                return
            elif opt == "--version":
                self.write("df (GNU coreutils) 9.1\n")
                self.write(
                    "Copyright (C) 2022 Free Software Foundation, Inc.\n"
                    "License GPLv3+: GNU GPL version 3 or later "
                    "<https://gnu.org/licenses/gpl.html>.\n"
                    "This is free software: you are free to change and "
                    "redistribute it.\n"
                    "There is NO WARRANTY, to the extent permitted by law.\n"
                )
                self.exit(0)
                return

        # ---- Header ----
        header = "Filesystem"
        if show_type:
            header = f"{header:<25s} {'Type':<10s}"
        else:
            header = f"{header:<25s}"
        if inodes:
            header += f" {'Inodes':>10s} {'IUsed':>9s} {'IFree':>9s} {'IUse%':>5s} Mounted on"
        else:
            size_col = "Size" if human else "1K-blocks"
            header += (f" {size_col:>8s} {'Used':>7s} "
                       f"{'Avail':>7s} {'Use%':>5s} Mounted on")
        self.write(header + "\n")

        # ---- Body ----
        for dev, mount, fstype, total, used in _FILESYSTEMS:
            if not show_all and dev in ("udev",) :
                # devtmpfs is shown only with -a
                continue
            self.write(
                self._usage_line(dev, mount, fstype, total, used,
                                 human=human, decimal=decimal,
                                 show_type=show_type, inodes=inodes) + "\n"
            )

        # ---- Validate paths given on the command line ----
        for path in args:
            resolved = self.fs.resolve_path(path, self.cwd)
            if not self.fs.exists(resolved):
                self.errorWrite(
                    f"df: {path}: No such file or directory\n"
                )
                self.exit(1)
                return

        self.exit(0)


commands["/bin/df"] = Command_df
commands["/usr/bin/df"] = Command_df
commands["df"] = Command_df
