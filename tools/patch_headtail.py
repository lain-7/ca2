#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""改造 4：给 Cowrie 的 head / tail 补上 POSIX 数字简写。

问题
----
真实 GNU coreutils 的 head/tail 支持三种写法：

    head -3 file        数字简写（POSIX 与 GNU 都支持）
    head -n 3 file      显式选项
    head -n3 file       选项与参数连写

Cowrie 的 commands/fs.py 用 getopt.getopt(args, "n:") 解析，
只认识第二种。第一种会被当成非法选项：

    head: invalid option -- '3'

这是识别蜜罐的强信号 —— 真实的 head 二进制不可能拒绝 -3。

修复方式
--------
在解析参数之前，先把 ``-N``（N 为纯数字）改写成 ``-n N``。
这样不用改动原有 getopt 逻辑，改动面最小。

同时补上 ``-n3``（连写）的处理，因为 GNU 也接受这种形式。

用法
----
    python3 patch_headtail.py            # 应用补丁
    python3 patch_headtail.py --revert   # 回滚
"""

from __future__ import annotations

import re
import shutil
import sys
from pathlib import Path

TARGET = Path(
    "/home/cowrie/cowrie-honeypot/cowrie-env/lib/python3.14/site-packages"
    "/cowrie/commands/fs.py"
)
BACKUP = TARGET.with_suffix(".py.bak-headtail")
MARKER = "[改造 4]"

# 插入一个模块级辅助函数，供两个命令共用
HELPER = '''
# ----------------------------------------------------------------------
# [改造 4] head / tail 的数字简写归一化
#
# GNU coreutils 接受 "-3" 与 "-n 3" 两种写法。Cowrie 原来的 getopt 只认
# 后者，导致 "head -3 file" 报 invalid option。这里在解析前统一改写。
# ----------------------------------------------------------------------
def _normalize_numeric_shorthand(args):
    """把 ["-3", "file"] 改写成 ["-n", "3", "file"]；"-n3" 改写成 ["-n", "3"]。"""
    out = []
    for arg in args:
        if len(arg) > 1 and arg[0] == "-" and arg[1:].isdigit():
            # -3 → -n 3
            out.extend(["-n", arg[1:]])
        elif arg.startswith("-n") and len(arg) > 2 and arg[2:].isdigit():
            # -n3 → -n 3
            out.extend(["-n", arg[2:]])
        else:
            out.append(arg)
    return out
'''


def main() -> int:
    args = set(sys.argv[1:])

    if not TARGET.exists():
        print(f"找不到目标文件：{TARGET}")
        return 2

    if "--revert" in args:
        if not BACKUP.exists():
            print("没有备份文件，无法回滚。")
            return 1
        shutil.copy2(BACKUP, TARGET)
        print(f"已回滚：{TARGET}")
        return 0

    src = TARGET.read_text(encoding="utf-8")

    if MARKER in src:
        print("补丁已存在，跳过。")
        return 0

    # ---- 1) 在文件顶部（第一个 class 定义前）插入辅助函数 ----
    m = re.search(r"^class \w+", src, re.MULTILINE)
    if m is None:
        print("找不到类定义，补丁失败。")
        return 1
    insert_at = m.start()

    # ---- 2) 把两个 start() 里的 getopt 调用改成先归一化 ----
    # tail: optlist, args = getopt.getopt(self.args, "n:")
    src_new = src[:insert_at] + HELPER.lstrip("\n") + "\n\n" + src[insert_at:]

    replacements = [
        (
            'optlist, args = getopt.getopt(self.args, "n:")',
            'optlist, args = getopt.getopt(_normalize_numeric_shorthand(self.args), "n:")',
        ),
        (
            'optlist, args = getopt.getopt(self.args, "c:n:")',
            'optlist, args = getopt.getopt(_normalize_numeric_shorthand(self.args), "c:n:")',
        ),
    ]

    applied = 0
    for old, new in replacements:
        if old in src_new:
            src_new = src_new.replace(old, new, 1)
            applied += 1

    if applied == 0:
        print("找不到 getopt 调用点，补丁失败。")
        return 1

    if "--check" in args:
        print(f"可以打补丁，将替换 {applied} 处 getopt 调用。")
        return 0

    shutil.copy2(TARGET, BACKUP)
    TARGET.write_text(src_new, encoding="utf-8")

    print(f"已应用补丁：{TARGET}")
    print(f"备份文件：{BACKUP}")
    print(f"已改写 {applied} 处 getopt 调用（head / tail）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
