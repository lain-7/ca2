#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""改造 3：去掉 Cowrie 输出里的 ESC[4h / ESC[4l 终端序列。

问题
----
Cowrie 在每条命令执行前后，会向客户端发送 ESC[4h（开启插入模式）和
ESC[4l（关闭插入模式）。真实 bash 不会主动发送这两个序列，因此这是
识别蜜罐的可靠强特征。

来源（实测调用栈）
-----------------
命令结束后：

  cowrie/shell/honeypot.py:947  HoneyPotShell.resume()
    → self.protocol.setInsertMode()
      → twisted/conch/recvline.py:406  terminal.setModes([insults.modes.IRM])
        → twisted/conch/insults/insults.py:713  write(b"\\x1b[4h")

每条命令开始前：

  cowrie/shell/protocol.py:513  HoneyPotBaseProtocol.call_command()
    → self.setTypeoverMode()
      → twisted/conch/recvline.py:410  terminal.resetModes([IRM])
        → twisted/conch/insults/insults.py:723  write(b"\\x1b[4l")

这两个方法定义在 Twisted 的 recvline.HistoricRecvLine 上，
Cowrie 的 HoneyPotInteractiveProtocol 同时继承它，所以实际生效的是
Twisted 的版本。

修复方式
--------
在 cowrie/shell/protocol.py 的 HoneyPotInteractiveProtocol 类里覆盖
setInsertMode / setTypeoverMode 为空操作。

为什么不改 Twisted：
  改 site-packages/twisted 会在升级 Twisted 时丢失，而且影响面过大。
  在 Cowrie 的子类里覆盖是更窄、更持久的做法。

用法
----
    python3 patch_underline.py            # 应用补丁
    python3 patch_underline.py --check    # 只检查
    python3 patch_underline.py --revert   # 回滚
"""

from __future__ import annotations

import re
import shutil
import sys
from pathlib import Path

TARGET = Path(
    "/home/cowrie/cowrie-honeypot/cowrie-env/lib/python3.14/site-packages"
    "/cowrie/shell/protocol.py"
)

BACKUP = TARGET.with_suffix(".py.bak-underline")
MARKER = "[改造 3]"

# 要插入的方法块。缩进 4 空格 = 类方法级别。
#
# 关键点：这两个方法在 Twisted 里做两件事 ——
#   1. 维护 self.mode 状态（"insert" / "typeover"）
#   2. 向客户端发送 ESC[4h / ESC[4l
# 我们只需要去掉第 2 件事，第 1 件事必须保留 ——
# Cowrie 的 characterReceived() 依赖 self.mode 决定是插入还是覆盖字符。
# 如果整个方法覆盖成空操作，会丢状态，导致 AttributeError。
PATCH_BLOCK = '''
    # ------------------------------------------------------------------
    # [改造 3] 抑制终端模式切换序列
    #
    # 真实 bash 不会在每条命令前后发送 ESC[4l / ESC[4h。Cowrie 通过
    # Twisted recvline 的插入/覆盖模式切换，在 shell 恢复和命令开始时
    # 各插入一个序列，构成可被识别的指纹。
    #
    # 注意：只去掉序列，保留 self.mode 状态。characterReceived() 依赖
    # 这个状态决定是插入还是覆盖字符，丢掉会直接崩溃。
    # ------------------------------------------------------------------
    def setInsertMode(self) -> None:
        """等价于 Twisted 的实现，但不发送 ESC[4h。"""
        self.mode = "insert"

    def setTypeoverMode(self) -> None:
        """等价于 Twisted 的实现，但不发送 ESC[4l。"""
        self.mode = "typeover"

'''

# 目标类：真正的交互式 shell 走这里
TARGET_CLASS = "class HoneyPotInteractiveProtocol(HoneyPotBaseProtocol, recvline.HistoricRecvLine):"


def find_class_body_anchor(src: str, class_decl: str):
    """在目标类里找一个可插入的锚点：类体第一处 'def ' 之前。

    返回插入位置（字符下标）。
    """
    start = src.find(class_decl)
    if start < 0:
        return None

    # 找这个类体里的第一个方法定义
    m = re.search(r"\n    def \w+\(", src[start:])
    if m is None:
        return None
    return start + m.start() + 1  # +1 跳过换行，插在 def 之前


def main() -> int:
    args = set(sys.argv[1:])

    if not TARGET.exists():
        print(f"找不到目标文件：{TARGET}")
        return 2

    # ---- 回滚 ----
    if "--revert" in args:
        if not BACKUP.exists():
            print("没有找到备份文件，无法回滚。")
            return 1
        shutil.copy2(BACKUP, TARGET)
        print(f"已回滚：{TARGET}")
        return 0

    src = TARGET.read_text(encoding="utf-8")

    if MARKER in src:
        print("补丁已存在，跳过。")
        return 0

    anchor = find_class_body_anchor(src, TARGET_CLASS)
    if anchor is None:
        print(f"找不到目标类：{TARGET_CLASS}")
        return 1

    if "--check" in args:
        print(f"目标类存在，插入位置 {anchor}，可以打补丁。")
        return 0

    # ---- 备份并应用 ----
    shutil.copy2(TARGET, BACKUP)
    new_src = src[:anchor] + PATCH_BLOCK.lstrip("\n") + "\n" + src[anchor:]
    TARGET.write_text(new_src, encoding="utf-8")

    # ---- 验证插入位置正确 ----
    check = TARGET.read_text(encoding="utf-8")
    idx = check.find(MARKER)
    before = check[:idx]
    last_class = None
    for m in re.finditer(r"^class (\w+)", before, re.MULTILINE):
        last_class = m.group(1)

    print(f"已应用补丁：{TARGET}")
    print(f"备份文件：{BACKUP}")
    print(f"插入位置所属类：{last_class}")
    if last_class != "HoneyPotInteractiveProtocol":
        print("警告：插入位置可能不正确，请检查。")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
