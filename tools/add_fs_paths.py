#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""改造 9：把新增/补全的命令写进假文件系统。

问题
----
which / whereis / ls /usr/bin 都依赖 fs.pickle 里的目录树。
我们补上了 df、sed、ss、ip、systemctl 的 Python 实现，但如果这些路径
不在假文件系统里，会出现下面的矛盾：

    $ which ss ip systemctl
    （无输出）
    $ ss -tulnp
    Netid State ...        ← 命令明明能跑

真实系统不可能出现"命令能执行但 which 找不到"的情况。

修复
----
在 fs.pickle 里补上这些路径的可执行文件节点，权限设为 0o100755，
属主 root:root，大小填一个合理的值。

用法
----
    python3 add_fs_paths.py <源 pickle> <输出 pickle>
"""

from __future__ import annotations

import pickle
import sys

(A_NAME, A_TYPE, A_UID, A_GID, A_SIZE,
 A_MODE, A_CTIME, A_CONTENTS, A_TARGET, A_REALFILE) = range(10)
T_LINK, T_DIR, T_FILE = 0, 1, 2

# 需要确保存在的可执行文件：(路径, 大小, 修改时间)
# 大小参考 Debian 12 amd64 的真实二进制体积
#
# 注意：只保留每个命令在真实 Debian 12 上的实际位置。
# 例如 ip 只在 /usr/sbin（/sbin 是指向 usr/sbin 的符号链接），
# 如果在 /usr/bin 也放一份，which 会输出两行，反而不真实。
EXECUTABLES = [
    # coreutils / 基础工具（/bin 是 usr/bin 的符号链接，所以只放 /usr/bin）
    ("/usr/bin/df",          89296,  1680000000),
    ("/usr/bin/sed",         84208,  1680000000),
    ("/usr/bin/top",        188384,  1680000000),
    ("/usr/bin/head",        68368,  1680000000),
    ("/usr/bin/tail",        72784,  1680000000),
    # iproute2：Debian 把 ip 放在 /usr/sbin，ss 放在 /usr/bin
    ("/usr/bin/ss",          389552, 1680000000),
    ("/usr/sbin/ip",         1170120, 1680000000),
    # systemd
    ("/usr/bin/systemctl",   1051800, 1680000000),
    # 其他现代系统工具
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

# 需要从假文件系统里删除的路径。
# 这些都是上一版 add_fs_paths 误加的重复位置，
# 真实 Debian 上并不存在（/bin 与 /sbin 是指向 /usr 对应目录的符号链接）。
REMOVE_PATHS = [
    "/bin/df",
    "/bin/sed",
    "/bin/systemctl",
    "/bin/ss",
    "/sbin/ip",
    "/usr/sbin/ss",
]


# /etc 下应该存在但内容为空白的配置文件
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
        sys.exit("用法: add_fs_paths.py <源 fs.pickle> <输出 fs.pickle>")

    src, dst = sys.argv[1], sys.argv[2]
    with open(src, "rb") as fh:
        tree = pickle.load(fh)

    existing = dict(walk(tree))

    # ---- 先删除误加的重复路径 ----
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
            # 已存在 → 只修正大小/时间/权限，保持内容不动
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
            # 父目录不存在 → 先创建
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

    print(f"删除重复路径 {removed} 个")
    print(f"新增 {added} 个路径，修正 {updated} 个现有节点")
    print(f"总路径数：{len(dict(walk(tree)))}")
    print(f"输出：{dst}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
