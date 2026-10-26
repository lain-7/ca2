#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""改造 6：修正 uptime 与网卡名。

问题 1：uptime 从进程启动算起
-----------------------------
cowrie/shell/protocol.py 的 uptime() 返回：

    time.time() - pt.factory.starttime

factory.starttime 是 Cowrie 进程启动的时刻，不是"系统启动"的时刻。
所以每次重启蜜罐，攻击者看到的 uptime 都会变成"刚开机几分钟"。
真实的生产服务器极少在 1 小时内重启，这是明显的可疑信号。

修复：把服务启动时刻往前推一个固定的随机偏移（默认 47 天），
让 uptime 看起来像一台长期运行的服务器。偏移量在配置里可以调整。

问题 2：ifconfig 硬编码 eth0
--------------------------
cowrie/commands/ifconfig.py 里网卡名是写死的 "eth0"。
systemd 的 net.ifnames 自 2015 年起默认启用可预测网卡名
（enp0s3、ens33、ens192…），现代 Debian/Ubuntu 不再用 eth0。

修复：让网卡名从配置读取，默认改成 enp1s0 —— 与 VM 上真实的
第二块网卡命名规则一致，也与 /sys/class/net 的风格吻合。

用法
----
    python3 patch_uptime_nic.py            # 应用
    python3 patch_uptime_nic.py --revert   # 回滚
"""

from __future__ import annotations

import re
import shutil
import sys
from pathlib import Path

SITE = Path(
    "/home/cowrie/cowrie-honeypot/cowrie-env/lib/python3.14/site-packages/cowrie"
)
PROTOCOL = SITE / "shell" / "protocol.py"
IFCONFIG = SITE / "commands" / "ifconfig.py"
CFG = Path("/home/cowrie/cowrie-honeypot/etc/cowrie.cfg")

MARKER = "[改造 6]"

# 默认的"已运行天数"。改这个数字就能调整伪装的运行时长。
DEFAULT_UPTIME_DAYS = 47


def patch_uptime(check_only: bool) -> int:
    """把 uptime() 改成基于固定偏移的计算。"""
    src = PROTOCOL.read_text(encoding="utf-8")
    if MARKER + " uptime" in src:
        print("  uptime 补丁已存在，跳过")
        return 0

    old = '''    def uptime(self):
        """
        Uptime
        """
        pt = self.getProtoTransport()
        r = time.time() - pt.factory.starttime
        return r
'''

    new = f'''    def uptime(self):
        """
        Uptime

        {MARKER} 真实系统重启后 uptime 归零，但一台生产服务器很少在
        一小时内重启。Cowrie 原本从进程启动算起，导致每次重启蜜罐都显示
        "刚开机几分钟"，这是明显的破绽。

        这里改为：服务启动时刻往前推一个固定偏移，模拟长期运行。
        偏移量由 [honeypot] uptime_offset_days 配置，默认 {DEFAULT_UPTIME_DAYS} 天。
        """
        pt = self.getProtoTransport()
        offset_days = CowrieConfig.getint(
            "honeypot", "uptime_offset_days", fallback={DEFAULT_UPTIME_DAYS}
        )
        boot_time = pt.factory.starttime - offset_days * 86400
        return time.time() - boot_time
'''

    if old not in src:
        print("  uptime 锚点未找到")
        return 1

    if check_only:
        print("  uptime 锚点存在")
        return 0

    PROTOCOL.write_text(src.replace(old, new, 1), encoding="utf-8")
    print(f"  已修改 uptime()，偏移 {DEFAULT_UPTIME_DAYS} 天")
    return 0


def patch_ifconfig(check_only: bool) -> int:
    """把 ifconfig 的硬编码 eth0 改成可配置的现代网卡名。"""
    src = IFCONFIG.read_text(encoding="utf-8")
    if MARKER + " nic" in src:
        print("  ifconfig 补丁已存在，跳过")
        return 0

    # 1) 在 call() 开头解析网卡名
    anchor = "    def call(self) -> None:\n"
    if anchor not in src:
        print("  ifconfig 锚点未找到")
        return 1

    inject = f'''    def call(self) -> None:
        # {MARKER} 网卡名从配置读取，默认使用现代可预测命名（systemd net.ifnames）
        nic_name = CowrieConfig.get("honeypot", "nic_name", fallback="enp1s0")
'''

    if check_only:
        print("  ifconfig 锚点存在")
        return 0

    src = src.replace(anchor, inject, 1)

    # 2) 把输出模板里的 eth0 换成变量
    src = src.replace("result = f\"\"\"eth0      Link encap:Ethernet",
                      "result = f\"\"\"{nic_name:<9s} Link encap:Ethernet", 1)

    IFCONFIG.write_text(src, encoding="utf-8")
    print("  已修改 ifconfig 网卡名 → enp1s0（可配置）")
    return 0


def ensure_import(check_only: bool) -> int:
    """确保 protocol.py 里导入了 CowrieConfig。"""
    src = PROTOCOL.read_text(encoding="utf-8")
    if "from cowrie.core.config import CowrieConfig" in src:
        print("  CowrieConfig 已导入")
        return 0
    if check_only:
        print("  缺少 CowrieConfig 导入")
        return 1
    # 加在第一个 from cowrie 导入之前
    m = re.search(r"^from cowrie\.", src, re.MULTILINE)
    if m is None:
        print("  找不到导入位置")
        return 1
    src = (src[: m.start()]
           + "from cowrie.core.config import CowrieConfig\n"
           + src[m.start():])
    PROTOCOL.write_text(src, encoding="utf-8")
    print("  已添加 CowrieConfig 导入")
    return 0


def main() -> int:
    args = set(sys.argv[1:])
    check_only = "--check" in args

    if "--revert" in args:
        for p in (PROTOCOL, IFCONFIG):
            for bak in p.parent.glob(p.name + ".bak-*"):
                shutil.copy2(bak, p)
                print(f"已回滚 {p.name} ← {bak.name}")
        return 0

    if not check_only:
        # 备份
        for p in (PROTOCOL, IFCONFIG):
            bak = p.with_suffix(p.suffix + ".bak-uptime")
            if not bak.exists():
                shutil.copy2(p, bak)
                print(f"备份 {p.name} → {bak.name}")

    rc = 0
    rc |= ensure_import(check_only)
    rc |= patch_uptime(check_only)
    rc |= patch_ifconfig(check_only)

    if not check_only:
        print("\n完成。别忘了清 pycache 并重启 Cowrie。")
    return rc


if __name__ == "__main__":
    sys.exit(main())
