# SPDX-License-Identifier: BSD-3-Clause
# -*- coding: utf-8 -*-
"""改造 5：为 Cowrie 补充 df 命令的真实实现。

背景
----
Cowrie 原本没有 commands/df.py，只在 data/txtcmds/bin/df 放了一段静态文本。
txtcmd 机制的特点是不接受参数：只要执行 df（无论带什么参数），都返回同一段
固定文本；而当参数形式触发到二进制回落路径时，还会报：

    -bash: /usr/bin/df: cannot execute binary file: Exec format error

真实的 df 是 coreutils 的必备命令，任何 Linux 发行版都有，不可能无法执行。
这是识别蜜罐的决定性特征之一。

实现要点
--------
1. 支持 -h（人类可读）、-H（十进制单位）、-T（显示文件系统类型）、
   -a、-i、-P，以及 --help / --version
2. 接受任意文件/目录参数（df 会显示该路径所在文件系统）
3. 输出的数值与 /etc/fstab、假文件系统的规模保持一致：
   根分区 20G，符合一台小型生产服务器的实际
4. 走 Cowrie 的虚拟文件系统接口判断路径是否存在，不存在时报真实错误

这个文件按 Cowrie 官方命令模块的写法组织，可以直接放进 commands/ 目录，
并在 commands/__init__.py 的 command_modules 列表里注册 "df"。
"""

from __future__ import annotations

import getopt

from cowrie.shell.command import HoneyPotCommand

commands = {}

# ---------------------------------------------------------------------------
# 假想的分区表
#
# 这些数值对应一台 20G 磁盘的 Debian 12 服务器：
#   根分区      20G（与 fs.pickle 的规模一致）
#   /boot       512M
#   两个 tmpfs  按内存 2G 推算
#
# 字段顺序：设备名、挂载点、文件系统类型、总大小、已用大小
# 大小单位都是字节
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
    """把字节数格式化成 df -h 的风格（如 19G、512M）。"""
    units = ["", "K", "M", "G", "T", "P"]
    value = float(size)
    idx = 0
    while value >= base and idx < len(units) - 1:
        value /= base
        idx += 1
    if idx == 0:
        return f"{int(value)}"
    # df 的规则：数值 <10 时保留一位小数，否则取整
    if value < 10:
        return f"{value:.1f}{units[idx]}".replace(".0", "")
    return f"{int(round(value))}{units[idx]}"


def _exact(size: int) -> str:
    """df 默认输出的裸字节数格式（按 1K 块）。"""
    return str(size // 1024)


class Command_df(HoneyPotCommand):
    """df —— 报告文件系统磁盘空间使用情况。"""

    def _usage_line(self, dev, mount, fstype, total, used,
                    human=False, decimal=False, show_type=False,
                    inodes=False) -> str:
        """生成一行 df 输出，列宽与 GNU df 保持一致。"""
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

        # GNU df 的对齐方式：设备名左对齐 25 列，其余右对齐
        parts = []
        parts.append(f"{dev:<25s}")
        if show_type:
            parts.append(f"{fstype:<10s}")
        if inodes:
            # -i 时显示的是 inode 数，这里用一个合理估算
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
                pass  # POSIX 输出格式，我们本来就是这种格式
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

        # ---- 头部 ----
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

        # ---- 内容 ----
        for dev, mount, fstype, total, used in _FILESYSTEMS:
            if not show_all and dev in ("udev",) :
                # -a 才显示 devtmpfs
                continue
            self.write(
                self._usage_line(dev, mount, fstype, total, used,
                                 human=human, decimal=decimal,
                                 show_type=show_type, inodes=inodes) + "\n"
            )

        # ---- 校验命令行给出的路径 ----
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
