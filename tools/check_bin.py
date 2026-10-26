#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""检查假文件系统里 /bin 与 /sbin 是目录还是符号链接。"""
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
        print(f"/{name}: 不存在")
        continue
    kind = {0: "符号链接", 1: "目录", 2: "普通文件"}.get(node[A_TYPE], "?")
    print(f"/{name}: {kind}  类型={node[A_TYPE]}  目标={node[A_TARGET]}  "
          f"子项数={len(node[A_CONTENTS]) if isinstance(node[A_CONTENTS], list) else '-'}")

# 列出 /bin 下前 20 项
bin_node = next((c for c in tree[A_CONTENTS] if c[A_NAME] == "bin"), None)
if bin_node and bin_node[A_TYPE] == T_DIR:
    names = [c[A_NAME] for c in bin_node[A_CONTENTS]][:25]
    print(f"\n/bin 前 25 项: {names}")
    print(f"/bin 总项数: {len(bin_node[A_CONTENTS])}")
