#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
改造 2：重建 Cowrie 假文件系统（fs.pickle）
==========================================

背景
----
Cowrie 的假文件系统是一个 pickle 序列化的节点树，由 `bin/createfs` 从一个
真实系统（实际是一个 Docker 容器）快照生成。快照只保存元数据和少量文件内容，
且生成后不会再更新，因此存在三类破绽：

  1. 内容缺失  —— 只有路径没有内容（/etc/os-release 为空、sshd_config 为空）
  2. 数据不同步 —— 提示符主机名来自配置文件，/etc/hostname 来自 pickle
  3. 快照痕迹  —— 容器标记文件、批量条目共享同一个 mtime

本脚本直接操作 pickle 的节点树，把这些破绽逐个修掉。

节点格式
--------
每个节点是一个 10 元的位置列表：

    [name, type, uid, gid, size, mode, ctime, contents, target, realfile]
      0     1     2    3     4     5      6        7        8       9

  name      —— 文件名（不含路径）
  type      —— T_LINK=0 / T_DIR=1 / T_FILE=2 / T_BLK=3 / T_CHR=4 / T_SOCK=5 / T_FIFO=6
  uid/gid   —— 属主
  size      —— 文件大小（字节）
  mode      —— 完整的 st_mode，例如 0o100644 = 普通文件 rw-r--r--，0o40755 = 目录 rwxr-xr-x
  ctime     —— 修改时间（Unix 时间戳，整数）
  contents  —— 目录时为子节点列表；文件时为 bytes（没有内容时为空 bytes 或空列表）
  target    —— 符号链接的目标路径，其余为 None
  realfile  —— 真实文件路径（用于 A_REALFILE 后端），一般为 None

用法
----
    python3 rebuild_fs.py <源 fs.pickle> <输出 fs.pickle>

    示例（在蜜罐 VM 的 venv 里执行）：
    python3 rebuild_fs.py \
        cowrie-env/lib/python3.14/site-packages/cowrie/data/fs.pickle \
        /tmp/fs_new.pickle

注意
----
- 脚本不会覆盖源文件，必须显式指定输出路径
- 目标身份统一为：Debian 12 (bookworm) + 主机名 svr04
- 如需迁移到别的身份（如 Ubuntu 22.04），修改本文件顶部的常量即可
"""

from __future__ import annotations

import pickle
import random
import sys
import time

# ---------------------------------------------------------------------------
# 节点字段索引（与 cowrie/shell/fs.py 中的 A_* 常量保持一致）
# ---------------------------------------------------------------------------
(A_NAME, A_TYPE, A_UID, A_GID, A_SIZE,
 A_MODE, A_CTIME, A_CONTENTS, A_TARGET, A_REALFILE) = range(10)

T_LINK, T_DIR, T_FILE = 0, 1, 2

# ---------------------------------------------------------------------------
# 目标身份配置 —— 想换成别的发行版就改这里
# ---------------------------------------------------------------------------
HOSTNAME = "svr04"
KERNEL = "6.1.0-21-amd64"
BUILD_STRING = "#1 SMP PREEMPT_DYNAMIC Debian 6.1.90-1 (2024-05-03)"
DEBIAN_VER = "12.11"

# 时间基准：2023-01-01，用于给根目录条目分配"散布在一年多里"的 mtime
BASE_MTIME = 1672531200
MTIME_SPREAD_DAYS = 540

# ---------------------------------------------------------------------------
# 要写入的文件内容
# ---------------------------------------------------------------------------

OS_RELEASE = b"""PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
VERSION_CODENAME=bookworm
ID=debian
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"
"""

LSB_RELEASE = b"""DISTRIB_ID=Debian
DISTRIB_DESCRIPTION="Debian GNU/Linux 12 (bookworm)"
DISTRIB_RELEASE=12
DISTRIB_CODENAME=bookworm
"""

# 真实的 Debian 12 默认 sshd_config。
# 保留 PermitRootLogin prohibit-password，这让"root 能登录"看起来也合理
# （Cowrie 的认证层会放行 root，如果配置里写 no 就自相矛盾了）。
SSHD_CONFIG = b"""# This is the sshd server system-wide configuration file.
# See sshd_config(5) for more information.

Include /etc/ssh/sshd_config.d/*.conf

Port 22
AddressFamily any
ListenAddress 0.0.0.0

HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

PermitRootLogin prohibit-password
MaxAuthTries 6
PubkeyAuthentication yes
PasswordAuthentication yes
KbdInteractiveAuthentication no
UsePAM yes

X11Forwarding no
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
"""

# 干净的 Debian 12 /etc/passwd：去掉原快照里的 phil（以及 vboxsf 组）
# 保留一个可登录的管理员 deploy，让"有人能登进来"这件事在文件系统里也成立。
PASSWD = b"""root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
deploy:x:1000:1000:System Administrator,,,:/home/deploy:/bin/bash
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
"""

GROUP = b"""root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:
tty:x:5:
disk:x:6:
lp:x:7:
mail:x:8:
news:x:9:
uucp:x:10:
man:x:12:
proxy:x:13:
kmem:x:15:
dialout:x:20:
fax:x:21:
voice:x:22:
cdrom:x:24:
floppy:x:25:
tape:x:26:
sudo:x:27:deploy
audio:x:29:
dip:x:30:
www-data:x:33:
backup:x:34:
operator:x:37:
list:x:38:
irc:x:39:
src:x:40:
shadow:x:42:
utmp:x:43:
video:x:44:
sasl:x:45:
plugdev:x:46:
staff:x:50:
games:x:60:
users:x:100:
nogroup:x:65534:
systemd-network:x:998:
systemd-timesync:x:999:
deploy:x:1000:
sshd:x:105:
"""

# 一个看起来像生产服务器的 motd
MOTD_TEMPLATE = (
    "Linux {host} {kernel} {build} x86_64\n"
    "\n"
    "The programs included with the Debian GNU/Linux system are free software;\n"
    "the exact distribution terms for each program are described in the\n"
    "individual files in /usr/share/doc/*/copyright.\n"
    "\n"
    "Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent\n"
    "permitted by applicable law.\n"
)

HOSTS = (
    "127.0.0.1       localhost\n"
    "127.0.1.1       {host}\n"
    "\n"
    "# The following lines are desirable for IPv6 capable hosts\n"
    "::1     localhost ip6-localhost ip6-loopback\n"
    "ff02::1 ip6-allnodes\n"
    "ff02::2 ip6-allrouters\n"
)

RESOLV_CONF = (
    "# Generated by resolvconf\n"
    "nameserver 8.8.8.8\n"
    "nameserver 1.1.1.1\n"
)


# ---------------------------------------------------------------------------
# 树操作工具
# ---------------------------------------------------------------------------

def index_tree(node, path="/"):
    """遍历整棵树，返回 {绝对路径: 节点} 映射。"""
    out = {path: node}
    if node[A_TYPE] == T_DIR and isinstance(node[A_CONTENTS], list):
        for child in node[A_CONTENTS]:
            child_path = path.rstrip("/") + "/" + child[A_NAME]
            out.update(index_tree(child, child_path))
    return out


def find_parent(tree, path):
    """返回 (父节点, 最后一段名字)。路径不存在时返回 (None, None)。"""
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


def remove_path(tree, path):
    """删除路径。返回是否真的删掉了东西。"""
    parent, name = find_parent(tree, path)
    if parent is None:
        return False
    before = len(parent[A_CONTENTS])
    parent[A_CONTENTS] = [c for c in parent[A_CONTENTS] if c[A_NAME] != name]
    return len(parent[A_CONTENTS]) < before


def ensure_dir(tree, path, mode=0o40755, uid=0, gid=0):
    """确保目录存在（不存在就创建，已存在就保留）。"""
    if path in index_tree(tree):
        return
    parent, name = find_parent(tree, path)
    if parent is None:
        raise RuntimeError(f"父目录不存在，无法建立: {path}")
    parent[A_CONTENTS].append(
        [name, T_DIR, uid, gid, 4096, mode, int(time.time()), [], None, None]
    )
    parent[A_CONTENTS].sort(key=lambda c: c[A_NAME])


def ensure_file(tree, path, content: bytes, mode=0o100644,
                uid=0, gid=0, ctime=None):
    """确保路径是一个内容为 content 的普通文件（已存在则整个替换）。"""
    parent, name = find_parent(tree, path)
    if parent is None:
        raise RuntimeError(f"父目录不存在，无法写入: {path}")

    # 先删掉同名条目（可能是个目录，或内容为空的占位）
    remove_path(tree, path)

    node = [
        name, T_FILE, uid, gid, len(content), mode,
        int(ctime if ctime is not None else time.time()),
        content, None, None,
    ]
    parent[A_CONTENTS].append(node)
    parent[A_CONTENTS].sort(key=lambda c: c[A_NAME])
    return node


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

def main() -> int:
    if len(sys.argv) != 3:
        sys.stderr.write("用法: rebuild_fs.py <源 fs.pickle> <输出 fs.pickle>\n")
        return 2

    src, dst = sys.argv[1], sys.argv[2]

    with open(src, "rb") as fh:
        tree = pickle.load(fh)

    actions: list[str] = []

    # ---- 1) /etc/os-release 等发行版标识 ----
    # 原状态：这个路径在 pickle 里的类型标记有误，cat 读不出内容，
    #         ls 却显示成一个 267 字节的普通文件。
    ensure_file(tree, "/etc/os-release", OS_RELEASE, ctime=BASE_MTIME)
    ensure_file(tree, "/etc/lsb-release", LSB_RELEASE, ctime=BASE_MTIME)
    ensure_file(tree, "/etc/debian_version",
                (DEBIAN_VER + "\n").encode(), ctime=BASE_MTIME)
    actions.append("修正 /etc/os-release（现为非空普通文件，267+ 字节）")
    actions.append("新增 /etc/lsb-release、/etc/debian_version")

    # ---- 2) 主机名统一 ----
    ensure_file(tree, "/etc/hostname", (HOSTNAME + "\n").encode(), ctime=BASE_MTIME)
    ensure_file(tree, "/etc/hosts",
                HOSTS.format(host=HOSTNAME).encode(), ctime=BASE_MTIME)
    ensure_file(tree, "/etc/motd",
                MOTD_TEMPLATE.format(host=HOSTNAME, kernel=KERNEL,
                                     build=BUILD_STRING).encode(),
                ctime=BASE_MTIME)
    ensure_file(tree, "/etc/resolv.conf", RESOLV_CONF.encode(), ctime=BASE_MTIME)
    actions.append(f"统一 /etc/hostname、/etc/hosts、/etc/motd = {HOSTNAME}")

    # ---- 3) 用户数据库 ----
    ensure_file(tree, "/etc/passwd", PASSWD, ctime=BASE_MTIME)
    ensure_file(tree, "/etc/group", GROUP, ctime=BASE_MTIME)
    # 创建 deploy 的家目录，让 /etc/passwd 里的条目有对应实体
    ensure_dir(tree, "/home/deploy", mode=0o40750, uid=1000, gid=1000)
    actions.append("替换 /etc/passwd 与 /etc/group（移除 phil / vboxsf）")
    actions.append("新增 /home/deploy 家目录")

    # ---- 4) sshd_config ----
    # 原状态：文件存在但内容为空，而系统却在跑 SSH 服务。
    ensure_dir(tree, "/etc/ssh")
    ensure_file(tree, "/etc/ssh/sshd_config", SSHD_CONFIG, ctime=BASE_MTIME)
    actions.append("填充 /etc/ssh/sshd_config（Debian 12 默认配置）")

    # ---- 5) 删除容器痕迹 ----
    # 原状态：这套文件系统是从 Docker 容器里抓的快照，
    #        把 /.dockerenv、/proc/docker、/var/log/runit 一起带了进来。
    container_markers = ["/.dockerenv", "/.dockerinit", "/proc/docker"]
    for path in container_markers:
        if remove_path(tree, path):
            actions.append(f"删除容器标记 {path}")

    removed_runit = 0
    for path in list(index_tree(tree)):
        if "/runit" in path:
            if remove_path(tree, path):
                removed_runit += 1
    if removed_runit:
        actions.append(f"删除 runit 相关路径 {removed_runit} 项")

    # ---- 6) 打散根目录时间戳 ----
    # 原状态：22 个条目只有 4 个不同的 mtime，去重率 18%。
    #        真实系统的 / 下，各目录的 mtime 分散在数年范围内。
    rng = random.Random(42)  # 固定种子 → 结果可复现
    span = MTIME_SPREAD_DAYS * 86400
    for child in tree[A_CONTENTS]:
        child[A_CTIME] = BASE_MTIME + rng.randint(0, span)
    actions.append(
        f"打散根目录 {len(tree[A_CONTENTS])} 个条目的 mtime"
        f"（{MTIME_SPREAD_DAYS} 天范围内随机，种子固定）"
    )

    # ---- 写回 ----
    with open(dst, "wb") as fh:
        pickle.dump(tree, fh)

    print("\n".join(f"  · {a}" for a in actions))
    print(f"\n节点总数: {len(index_tree(tree))}")
    print(f"输出文件: {dst}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
