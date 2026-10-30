#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Modification 9: write the newly added/completed commands into the fake filesystem.

Problem
-------
which / whereis / ls /usr/bin all rely on the directory tree in fs.pickle.
We added Python implementations of df, sed, ss, ip and systemctl, but if these paths
are not in the fake filesystem, the following contradiction appears:

    $ which ss ip systemctl
    (no output)
    $ ss -tulnp
    Netid State ...        <- yet the command clearly runs

A real system can never have "the command runs but which cannot find it".

Fix
---
Add executable file nodes for these paths in fs.pickle, mode 0o100755,
owner root:root, with a plausible size.

Usage
-----
    python3 add_fs_paths.py <source pickle> <output pickle>
"""

from __future__ import annotations

import pickle
import sys

(A_NAME, A_TYPE, A_UID, A_GID, A_SIZE,
 A_MODE, A_CTIME, A_CONTENTS, A_TARGET, A_REALFILE) = range(10)
T_LINK, T_DIR, T_FILE = 0, 1, 2

# Executables that must exist: (path, size, mtime)
# Sizes follow the real binary sizes on Debian 12 amd64
#
# Note: keep only the actual location of each command on a real Debian 12.
# E.g. ip lives only in /usr/sbin (/sbin is a symlink to usr/sbin);
# putting another copy in /usr/bin would make which print two lines, which is less realistic.
EXECUTABLES = [
    # coreutils / basic tools (/bin is a symlink to usr/bin, so only /usr/bin)
    ("/usr/bin/df",          89296,  1680000000),
    ("/usr/bin/sed",         84208,  1680000000),
    ("/usr/bin/top",        188384,  1680000000),
    ("/usr/bin/head",        68368,  1680000000),
    ("/usr/bin/tail",        72784,  1680000000),
    # iproute2: Debian puts ip in /usr/sbin and ss in /usr/bin
    ("/usr/bin/ss",          389552, 1680000000),
    ("/usr/sbin/ip",         1170120, 1680000000),
    # systemd
    ("/usr/bin/systemctl",   1051800, 1680000000),
    # Other modern system tools
    ("/usr/bin/journalctl",  248304, 1680000000),
    ("/usr/bin/hostnamectl", 248304, 1680000000),
    ("/usr/bin/timedatectl", 248304, 1680000000),
    ("/usr/bin/loginctl",    248304, 1680000000),
    ("/usr/bin/localectl",   248304, 1680000000),
    ("/usr/bin/resolvectl",  248304, 1680000000),
    ("/usr/bin/networkctl",  248304, 1680000000),
    ("/usr/bin/coredumpctl", 248304, 1680000000),
    ("/usr/bin/busctl",      248304, 1680000000),
    ("/usr/bin/udevadm",     273736, 1680000000),
    ("/usr/bin/apt",         149456, 1680000000),
    ("/usr/bin/dpkg",        413024, 1680000000),
    ("/usr/bin/nc",          42960,  1680000000),
    ("/usr/bin/openssl",     1075344, 1680000000),
    ("/usr/bin/curl",        262040, 1680000000),
    ("/usr/bin/wget",        985208, 1680000000),
    ("/usr/bin/git",         3399896, 1680000000),
    ("/usr/bin/python3",     6799400, 1680000000),
    ("/usr/bin/perl",        2140656, 1680000000),
    ("/usr/bin/vim",         3442504, 1680000000),
    ("/usr/bin/nano",        281256, 1680000000),
    ("/usr/bin/less",        176832, 1680000000),
    ("/usr/bin/tree",        47480,  1680000000),
    ("/usr/bin/watch",       42960,  1680000000),
    ("/usr/bin/strace",      943800, 1680000000),
    ("/usr/bin/lsof",        179240, 1680000000),
    ("/usr/bin/fuser",       72320,  1680000000),
    ("/usr/bin/nsenter",     47480,  1680000000),
    ("/usr/bin/unshare",     47480,  1680000000),
    ("/usr/sbin/iptables",   120368, 1680000000),
    ("/usr/sbin/ufw",        192712, 1680000000),
    ("/usr/sbin/sshd",       1085712, 1680000000),
    ("/usr/bin/ssh",         785080, 1680000000),
    ("/usr/bin/scp",         137312, 1680000000),
    ("/usr/bin/sftp",        157360, 1680000000),
    ("/usr/bin/tar",         420984, 1680000000),
    ("/usr/bin/gzip",        101792, 1680000000),
    ("/usr/bin/xz",          99696,  1680000000),
    ("/usr/bin/rsync",       409520, 1680000000),
    ("/usr/bin/crontab",     42848,  1680000000),
    ("/usr/bin/at",          27256,  1680000000),
]

# Paths to remove from the fake filesystem.
# These are duplicate locations wrongly added by the previous add_fs_paths,
# and do not exist on a real Debian (/bin and /sbin are symlinks to their /usr counterparts).
REMOVE_PATHS = [
    "/bin/df",
    "/bin/sed",
    "/bin/systemctl",
    "/bin/ss",
    "/sbin/ip",
    "/usr/sbin/ss",
]


# Config files under /etc that should exist but are blank
EMPTY_CONFIGS = [
    "/etc/ssh/ssh_host_rsa_key.pub",
    "/etc/ssh/ssh_host_ecdsa_key.pub",
    "/etc/ssh/ssh_host_ed25519_key.pub",
]


def walk(node, path="/"):
    yield path, node
    if node[A_TYPE] == T_DIR and isinstance(node[A_CONTENTS], list):
        for c in node[A_CONTENTS]:
            yield from walk(c, path.rstrip("/") + "/" + c[A_NAME])


def find_parent(tree, path):
    parts = [p for p in path.split("/") if p]
    if not parts:
        return None, None
    node = tree
    for part in parts[:-1]:
        if node[A_TYPE] != T_DIR or not isinstance(node[A_CONTENTS], list):
            return None, None
        nxt = next((c for c in node[A_CONTENTS] if c[A_NAME] == part), None)
        if nxt is None:
            return None, None
        node = nxt
    return node, parts[-1]


def ensure_dir(tree, path, mode=0o40755):
    nodes = dict(walk(tree))
    if path in nodes:
        return True
    parent, name = find_parent(tree, path)
    if parent is None:
        return False
    parent[A_CONTENTS].append(
        [name, T_DIR, 0, 0, 4096, mode, 1690000000, [], None, None]
    )
    parent[A_CONTENTS].sort(key=lambda c: c[A_NAME])
    return True


def main() -> int:
    if len(sys.argv) != 3:
        sys.exit("Usage: add_fs_paths.py <source fs.pickle> <output fs.pickle>")

    src, dst = sys.argv[1], sys.argv[2]
    with open(src, "rb") as fh:
        tree = pickle.load(fh)

    existing = dict(walk(tree))

    # ---- First remove the wrongly added duplicate paths ----
    removed = 0
    for path in REMOVE_PATHS:
        parent, name = find_parent(tree, path)
        if parent is not None:
            before = len(parent[A_CONTENTS])
            parent[A_CONTENTS] = [
                c for c in parent[A_CONTENTS] if c[A_NAME] != name
            ]
            if len(parent[A_CONTENTS]) < before:
                removed += 1
                existing.pop(path, None)

    added = 0
    updated = 0
    for path, size, ctime in EXECUTABLES:
        if path in existing:
            # Already exists -> only fix size/time/mode, keep content unchanged
            node = existing[path]
            if node[A_TYPE] == T_FILE:
                node[A_MODE] = 0o100755
                node[A_UID] = 0
                node[A_GID] = 0
                if not node[A_SIZE]:
                    node[A_SIZE] = size
                updated += 1
            continue

        parent, name = find_parent(tree, path)
        if parent is None:
            # Parent directory missing -> create it first
            dir_path = path.rsplit("/", 1)[0]
            if not ensure_dir(tree, dir_path):
                continue
            parent, name = find_parent(tree, path)
            if parent is None:
                continue

        parent[A_CONTENTS].append(
            [name, T_FILE, 0, 0, size, 0o100755, ctime, b"", None, None]
        )
        parent[A_CONTENTS].sort(key=lambda c: c[A_NAME])
        added += 1

    for path in EMPTY_CONFIGS:
        if path in existing:
            continue
        parent, name = find_parent(tree, path)
        if parent is None:
            continue
        content = b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC8 example host key\n"
        parent[A_CONTENTS].append(
            [name, T_FILE, 0, 0, len(content), 0o100644,
             1680000000, content, None, None]
        )
        parent[A_CONTENTS].sort(key=lambda c: c[A_NAME])
        added += 1

    with open(dst, "wb") as fh:
        pickle.dump(tree, fh)

    print(f"Removed {removed} duplicate paths")
    print(f"Added {added} paths, fixed {updated} existing nodes")
    print(f"Total paths: {len(dict(walk(tree)))}")
    print(f"Output: {dst}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
