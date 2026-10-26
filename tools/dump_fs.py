#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""导出 Cowrie fs.pickle 的内容，用于验证改造结果。

用法:
    dump_fs.py <fs.pickle>               # 列出全部路径
    dump_fs.py <fs.pickle> /etc/hostname # 查看指定文件内容
"""
import pickle, sys

(A_NAME, A_TYPE, A_UID, A_GID, A_SIZE,
 A_MODE, A_CTIME, A_CONTENTS, A_TARGET, A_REALFILE) = range(10)
T_DIR = 1

def walk(node, path="/"):
    yield path, node
    if node[A_TYPE] == T_DIR and isinstance(node[A_CONTENTS], list):
        for c in node[A_CONTENTS]:
            yield from walk(c, path.rstrip("/") + "/" + c[A_NAME])

with open(sys.argv[1], "rb") as fh:
    tree = pickle.load(fh)

nodes = dict(walk(tree))

if len(sys.argv) > 2:
    for target in sys.argv[2:]:
        n = nodes.get(target)
        if n is None:
            print(f"### {target}: 不存在\n")
            continue
        print(f"### {target}  type={n[A_TYPE]}  size={n[A_SIZE]}  mode={oct(n[A_MODE])}")
        c = n[A_CONTENTS]
        if isinstance(c, bytes):
            print(c.decode("utf-8", errors="replace"))
        elif isinstance(c, str):
            print(c)
        elif isinstance(c, list):
            print("<目录> " + "  ".join(x[A_NAME] for x in c[:60]))
        print()
else:
    print(f"{len(nodes)} 个路径")
    for p in sorted(nodes):
        print(p)
