#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Check whether /bin and /sbin in the fake filesystem are directories or symlinks."""
import pickle
import sys

(A_NAME, A_TYPE, A_UID, A_GID, A_SIZE,
 A_MODE, A_CTIME, A_CONTENTS, A_TARGET, A_REALFILE) = range(10)
T_DIR = 1

with open(sys.argv[1], "rb") as fh:
    tree = pickle.load(fh)

for name in ("bin", "sbin", "lib", "lib64"):
    node = next((c for c in tree[A_CONTENTS] if c[A_NAME] == name), None)
    if node is None:
        print(f"/{name}: does not exist")
        continue
    kind = {0: "symlink", 1: "directory", 2: "regular file"}.get(node[A_TYPE], "?")
    print(f"/{name}: {kind}  type={node[A_TYPE]}  target={node[A_TARGET]}  "
          f"children={len(node[A_CONTENTS]) if isinstance(node[A_CONTENTS], list) else '-'}")

# List the first 20 entries under /bin
bin_node = next((c for c in tree[A_CONTENTS] if c[A_NAME] == "bin"), None)
if bin_node and bin_node[A_TYPE] == T_DIR:
    names = [c[A_NAME] for c in bin_node[A_CONTENTS]][:25]
    print(f"\n/bin first 25 entries: {names}")
    print(f"/bin total entries: {len(bin_node[A_CONTENTS])}")
