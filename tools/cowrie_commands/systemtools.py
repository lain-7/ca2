# SPDX-License-Identifier: BSD-3-Clause
# -*- coding: utf-8 -*-
"""改造 8：补充 top / ss / ip / systemctl 的最小可用实现。

背景
----
三项独立问题：

1. top
   Cowrie 的 data/txtcmds/usr/bin/top 只有一行：
       E82: Cannot allocate any buffer, exiting...
   这是制作 txtcmd 时的占位残留，等于"top 永远崩溃"。
   真实的 top 是 procps 的核心工具，不可能无法启动。

2. ss / ip
   完全没有实现，which 找不到，执行报 command not found。
   iproute2 自 2001 年起就是 iputils/net-tools 的替代品，
   现代 Debian/Ubuntu 默认只装 iproute2。

3. systemctl
   完全没有实现。systemd 自 2015 年起是 Debian/Ubuntu 的默认 init，
   一个 2023 年的 Debian 12 不可能没有 systemctl。

这些命令的输出都与 /etc/os-release 声称的身份（Debian 12）保持一致：
systemctl 显示的是 systemd 服务，ss 显示的是 iproute2 的 socket 视图，
ip 显示的是可预测网卡名。

设计原则
--------
- 只实现攻击者最常用的参数组合，其余返回合理的错误
- 输出中的数字与 fs.pickle、ifconfig、df 的设定互相一致
- 不执行任何真实系统调用，全部是构造的文本
"""

from __future__ import annotations

import time

from cowrie.core.config import CowrieConfig
from cowrie.shell.command import HoneyPotCommand

commands = {}


# ---------------------------------------------------------------------------
# 公共：读取当前会话可见的网卡名与 IP
# ---------------------------------------------------------------------------
def _nic() -> str:
    return CowrieConfig.get("honeypot", "nic_name", fallback="enp1s0")


def _ip_of(protocol) -> str:
    return getattr(protocol, "kippoIP", "10.0.0.10")


def _hwaddr() -> str:
    # 与会话一致即可，不必与 ifconfig 的随机值严格相同
    return "52:54:00:6c:a0:fe"


# ===========================================================================
# top
# ===========================================================================
class Command_top(HoneyPotCommand):
    """top —— 动态查看进程（静态快照版）。"""

    def call(self) -> None:
        # 解析 -n（迭代次数）与 -b（批处理模式）；其余参数忽略
        iterations = 1
        args = list(self.args)
        i = 0
        while i < len(args):
            if args[i] == "-n" and i + 1 < len(args):
                try:
                    iterations = max(1, int(args[i + 1]))
                except ValueError:
                    self.errorWrite("top: bad iterations argument\n")
                    self.exit(1)
                    return
                i += 2
                continue
            if args[i] == "-d" and i + 1 < len(args):
                i += 2
                continue
            if args[i] in ("-b", "-H", "-c", "-o"):
                i += 1
                continue
            if args[i].startswith("-"):
                i += 1
                continue
            i += 1

        # 系统概况
        now = time.strftime("%H:%M:%S")
        offset_days = CowrieConfig.getint(
            "honeypot", "uptime_offset_days", fallback=47
        )
        up_days = offset_days

        tasks = 128
        running = 1
        sleeping = 127

        self.write(f"top - {now} up {up_days} days,  0:00,  1 user,  "
                   f"load average: 0.00, 0.01, 0.00\n")
        self.write(f"Tasks: {tasks} total,   {running} running, {sleeping} sleeping,"
                   f"   0 stopped,   0 zombie\n")
        self.write("%Cpu(s):  0.0 us,  0.1 sy,  0.0 ni, 99.9 id,  0.0 wa,  "
                   "0.0 hi,  0.0 si,  0.0 st\n")
        self.write("MiB Mem :   1979.3 total,    842.1 free,    291.5 used,    "
                   "845.7 buff/cache\n")
        self.write("MiB Swap :   1891.0 total,   1891.0 free,      0.0 used.   "
                   "1543.2 avail Mem \n\n")

        header = (f"{'PID':>7s} {'USER':<9s} {'PR':>2s} {'NI':>3s} "
                  f"{'VIRT':>8s} {'RES':>8s} {'SHR':>7s} {'S':>1s} "
                  f"{'%CPU':>4s} {'%MEM':>4s} {'TIME+':>8s} COMMAND")
        self.write(header + "\n")

        procs = [
            (1,    "root", "20", "0", "167420", "13284", "8864",  "Ss", "0.0", "0.7", "0:03.42", "/sbin/init"),
            (2,    "root", "20", "0", "0",      "0",     "0",     "S",  "0.0", "0.0", "0:00.01", "[kthreadd]"),
            (9,    "root", "20", "0", "0",      "0",     "0",     "S",  "0.0", "0.0", "0:00.00", "[rcu_sched]"),
            (412,  "root", "20", "0", "95216",  "6104",  "4208",  "Ss", "0.0", "0.3", "0:00.42", "/usr/lib/systemd/systemd-journald"),
            (458,  "root", "20", "0", "25816",  "4380",  "3180",  "Ss", "0.0", "0.2", "0:00.11", "/usr/sbin/cron -f"),
            (462,  "root", "20", "0", "88420",  "7328",  "5872",  "Ss", "0.0", "0.4", "0:00.18", "/usr/sbin/sshd -D"),
            (471,  "root", "20", "0", "12488",  "2864",  "2412",  "Ss", "0.0", "0.1", "0:00.03", "/usr/sbin/atd -f"),
            (612,  "root", "20", "0", "14288",  "3420",  "2904",  "Ss", "0.0", "0.2", "0:00.07", "/usr/sbin/rsyslogd -n"),
            (8841, "root", "20", "0", "32180",  "5120",  "3760",  "Ss", "0.0", "0.3", "0:00.02", "-bash"),
            (8903, "root", "20", "0", "42768",  "4152",  "3404",  "R+", "0.0", "0.2", "0:00.00", "top"),
        ]

        for pid, user, pr, ni, virt, res, shr, st, cpu, mem, t, cmd in procs:
            self.write(f"{pid:>7d} {user:<9s} {pr:>2s} {ni:>3s} {virt:>8s} "
                       f"{res:>8s} {shr:>7s} {st:>1s} {cpu:>4s} {mem:>4s} "
                       f"{t:>8s} {cmd}\n")

        self.exit(0)


commands["/usr/bin/top"] = Command_top
commands["top"] = Command_top


# ===========================================================================
# ss
# ===========================================================================
class Command_ss(HoneyPotCommand):
    """ss —— 查看套接字（iproute2）。"""

    def call(self) -> None:
        show_listen = False
        show_tcp = False
        show_udp = False
        show_proc = False
        numeric = False

        for a in self.args:
            if a.startswith("-"):
                for ch in a[1:]:
                    if ch == "l":
                        show_listen = True
                    elif ch == "t":
                        show_tcp = True
                    elif ch == "u":
                        show_udp = True
                    elif ch == "p":
                        show_proc = True
                    elif ch == "n":
                        numeric = True
                    elif ch == "a":
                        show_listen = False
            elif a in ("--tcp", "--listening", "--numeric", "--processes"):
                if a == "--tcp":
                    show_tcp = True
                elif a == "--listening":
                    show_listen = True
                elif a == "--numeric":
                    numeric = True
                elif a == "--processes":
                    show_proc = True

        if not show_tcp and not show_udp:
            show_tcp = True
            show_udp = True

        # 头部
        if show_proc:
            head = (f"{'Netid':<6s} {'State':<11s} {'Recv-Q':>7s} {'Send-Q':>7s} "
                    f"{'Local Address:Port':<23s} {'Peer Address:Port':<23s} Process")
        else:
            head = (f"{'Netid':<6s} {'State':<11s} {'Recv-Q':>7s} {'Send-Q':>7s} "
                    f"{'Local Address:Port':<23s} {'Peer Address:Port':<23s}")
        if show_listen:
            self.write(head + "\n")

        if show_listen and show_tcp:
            rows = [
                ("tcp", "LISTEN", "0", "128", "0.0.0.0:22", "0.0.0.0:*"),
            ]
            if show_proc:
                rows = [(t, s, rq, sq, la, pa, "users:((\"sshd\",pid=462,fd=3))")
                        for t, s, rq, sq, la, pa in rows]
            for row in rows:
                if show_proc:
                    t, s, rq, sq, la, pa, pr = row
                    self.write(f"{t:<6s} {s:<11s} {rq:>7s} {sq:>7s} "
                               f"{la:<23s} {pa:<23s} {pr}\n")
                else:
                    t, s, rq, sq, la, pa = row
                    self.write(f"{t:<6s} {s:<11s} {rq:>7s} {sq:>7s} "
                               f"{la:<23s} {pa:<23s}\n")

        if show_listen and show_udp:
            rows = [
                ("udp", "UNCONN", "0", "0", "127.0.0.53%lo:53", "0.0.0.0:*"),
            ]
            for t, s, rq, sq, la, pa in rows:
                line = (f"{t:<6s} {s:<11s} {rq:>7s} {sq:>7s} "
                        f"{la:<23s} {pa:<23s}")
                if show_proc:
                    line += " users:((\"systemd-resolve\",pid=421,fd=13))"
                self.write(line + "\n")

        self.exit(0)


commands["/usr/bin/ss"] = Command_ss
commands["/bin/ss"] = Command_ss
commands["ss"] = Command_ss


# ===========================================================================
# ip
# ===========================================================================
class Command_ip(HoneyPotCommand):
    """ip —— iproute2 的网络配置工具。"""

    def call(self) -> None:
        args = [a for a in self.args if not a.startswith("-")]
        obj = args[0] if args else None
        nic = _nic()
        ip = _ip_of(self.protocol)

        if obj in ("a", "addr", "address"):
            self.write(f"1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue "
                       f"state UNKNOWN group default qlen 1000\n")
            self.write(f"    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n")
            self.write(f"    inet 127.0.0.1/8 scope host lo\n")
            self.write(f"       valid_lft forever preferred_lft forever\n")
            self.write(f"    inet6 ::1/128 scope host \n")
            self.write(f"       valid_lft forever preferred_lft forever\n")
            self.write(f"2: {nic}: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 "
                       f"qdisc fq_codel state UP group default qlen 1000\n")
            self.write(f"    link/ether {_hwaddr()} brd ff:ff:ff:ff:ff:ff\n")
            self.write(f"    inet {ip}/24 brd "
                       f"{ip.rsplit('.', 1)[0]}.255 scope global dynamic {nic}\n")
            self.write(f"       valid_lft 84217sec preferred_lft 84217sec\n")
        elif obj in ("r", "route"):
            gw = ip.rsplit(".", 1)[0] + ".1"
            self.write("default via %s dev %s proto dhcp src %s metric 100 \n"
                       % (gw, nic, ip))
            prefix = ".".join(ip.split(".")[:3]) + ".0/24"
            self.write("%s dev %s proto kernel scope link src %s metric 100 \n"
                       % (prefix, nic, ip))
            self.write("%s dev %s proto dhcp scope link src %s metric 100 \n"
                       % (gw, nic, ip))
        elif obj in ("l", "link"):
            self.write(f"1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue "
                       f"state UNKNOWN mode DEFAULT group default qlen 1000\n")
            self.write(f"    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n")
            self.write(f"2: {nic}: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 "
                       f"qdisc fq_codel state UP mode DEFAULT group default qlen 1000\n")
            self.write(f"    link/ether {_hwaddr()} brd ff:ff:ff:ff:ff:ff\n")
        elif obj == "neigh":
            self.write(f"{ip.rsplit('.', 1)[0]}.1 dev {nic} lladdr "
                       f"52:54:00:eb:80:96 REACHABLE\n")
        elif obj is None:
            self.errorWrite(
                "Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }\n"
                "       ip [ -force ] -batch filename\n"
                "where  OBJECT := { address | addrlabel | fou | help | ila | "
                "ioam | l2tp | link |\n"
                "                   macsec | maddress | monitor | mptcp | mroute | "
                "mrule |\n"
                "                   neigh | netconf | netns | nexthop | ntable |\n"
                "                   ntbl | route | rule | sr | tap | tcpmetrics |\n"
                "                   token | tunnel | tuntap | vrf | xfrm }\n"
                "       OPTIONS := { -V[ersion] | -s[tatistics] | -d[etails] | "
                "-r[esolve] |\n"
                "                    -h[uman-readable] | -iec | -j[son] | "
                "-p[retty] |\n"
                "                    -f[amily] { inet | inet6 | mpls | bridge | "
                "link } |\n"
                "                    -4 | -6 | -I | -D | -M | -B | -0 |\n"
                "                    -l[oops] { maximum-addr-flush-attempts } | "
                "-echo |\n"
                "                    -rc[vbuf] [size] | -t[imestamp] | "
                "-ts[hort] | -n[etns] name |\n"
                "                    -N[umeric] | -a[ll] | -c[olor]}\n"
            )
            self.exit(1)
            return
        else:
            self.errorWrite(f'Object "{obj}" is unknown, try "ip help".\n')
            self.exit(1)
            return

        self.exit(0)


commands["/usr/bin/ip"] = Command_ip
commands["/sbin/ip"] = Command_ip
commands["ip"] = Command_ip


# ===========================================================================
# systemctl
# ===========================================================================
def _services() -> list[tuple[str, str, str]]:
    """返回 (单元名, 状态, 描述) 列表。"""
    return [
        ("atd.service", "loaded active running", "Deferred execution scheduler"),
        ("cron.service", "loaded active running", "Regular background program processing daemon"),
        ("dbus.service", "loaded active running", "D-Bus System Message Bus"),
        ("getty@tty1.service", "loaded active running", "Getty on tty1"),
        ("ssh.service", "loaded active running", "OpenBSD Secure Shell server"),
        ("systemd-journald.service", "loaded active running", "Journal Service"),
        ("systemd-logind.service", "loaded active running", "User Login Management"),
        ("systemd-networkd.service", "loaded active running", "Network Configuration"),
        ("systemd-resolved.service", "loaded active running", "Network Name Resolution"),
        ("systemd-timesyncd.service", "loaded active running", "Network Time Synchronization"),
        ("systemd-udevd.service", "loaded active running", "Rule-based Manager for Device Events"),
        ("rsyslog.service", "loaded active running", "System Logging Service"),
        ("unattended-upgrades.service", "loaded active running", "Unattended Upgrades Shutdown"),
        ("apt-daily.timer", "loaded active waiting", "Daily apt download activities"),
        ("apt-daily-upgrade.timer", "loaded active waiting", "Daily apt upgrade and clean activities"),
        ("logrotate.timer", "loaded active waiting", "Daily rotation of log files"),
        ("man-db.timer", "loaded active waiting", "Daily man-db regeneration"),
        ("ssh.socket", "loaded active listening", "OpenBSD Secure Shell server socket"),
    ]


class Command_systemctl(HoneyPotCommand):
    """systemctl —— systemd 控制工具（只读子集）。"""

    def call(self) -> None:
        args = [a for a in self.args if not a.startswith("-")]
        verb = args[0] if args else None
        unit = args[1] if len(args) > 1 else None

        if verb in ("status", None):
            if unit in (None, ""):
                # systemctl status（无参数）等价于查看整体状态
                self.write("● svr04\n")
                self.write("    State: running\n")
                self.write("     Jobs: 0 queued\n")
                self.write("   Failed: 0 units\n")
                self.write("    Since: Tue 2025-09-09 03:41:12 UTC; 47 days ago\n")
                self.write("   CGroup: /system.slice\n")
                self.exit(0)
                return

            name = unit if "." in unit else unit + ".service"
            if name in ("ssh.service", "sshd.service"):
                self.write("● ssh.service - OpenBSD Secure Shell server\n")
                self.write("     Loaded: loaded (/lib/systemd/system/ssh.service; "
                           "enabled; preset: enabled)\n")
                self.write("    Drop-In: /etc/systemd/system/ssh.service.d\n")
                self.write("             └─limits.conf, restart.conf\n")
                self.write("     Active: active (running) since Tue 2025-09-09 "
                           "03:41:15 UTC; 47 days ago\n")
                self.write("       Docs: man:sshd(8)\n")
                self.write("             man:sshd_config(5)\n")
                self.write("   Main PID: 462 (sshd)\n")
                self.write("      Tasks: 1 (limit: 2316)\n")
                self.write("     Memory: 5.2M\n")
                self.write("        CPU: 214ms\n")
                self.write("     CGroup: /system.slice/ssh.service\n")
                self.write("             └─462 \"sshd: /usr/sbin/sshd -D "
                           "[listener] Multiples\"\n")
                self.exit(0)
                return

            found = next((s for s in _services() if s[0] == name), None)
            if found:
                self.write(f"● {found[0]} - {found[2]}\n")
                self.write("     Loaded: loaded\n")
                self.write("     Active: active (running)\n")
                self.exit(0)
                return

            self.errorWrite(f"Unit {name} could not be found.\n")
            self.exit(3)
            return

        if verb == "list-units" or verb == "list-unit-files":
            self.write(f"{'UNIT':<30s} {'LOAD':<6s} {'ACTIVE':<8s} "
                       f"{'SUB':<8s} DESCRIPTION\n")
            for name, state, desc in _services():
                parts = state.split()
                load = parts[0] if len(parts) > 0 else "loaded"
                active = parts[1] if len(parts) > 1 else "active"
                sub = parts[2] if len(parts) > 2 else "running"
                self.write(f"{name:<30s} {load:<6s} {active:<8s} "
                           f"{sub:<8s} {desc}\n")
            self.write(f"\n{len(_services())} loaded units listed.\n")
            self.exit(0)
            return

        if verb == "is-active":
            name = unit if unit else ""
            name = name if "." in name else name + ".service"
            if name in [s[0] for s in _services()]:
                self.write("active\n")
                self.exit(0)
            else:
                self.write("inactive\n")
                self.exit(3)
            return

        if verb == "is-enabled":
            name = unit if unit else ""
            name = name if "." in name else name + ".service"
            if name in [s[0] for s in _services()]:
                self.write("enabled\n")
                self.exit(0)
            self.write("disabled\n")
            self.exit(1)
            return

        if verb in ("start", "stop", "restart", "reload", "enable", "disable"):
            # 蜜罐不真的改状态，但要给出真实系统上会有的反馈：
            # 非特权用户执行这些操作会被 polkit 拒绝
            if getattr(self.protocol.user, "uid", 0) != 0:
                self.errorWrite(
                    "Failed to " + verb + " " + (unit or "") +
                    ": Interactive authentication required.\n"
                    "See system logs and 'systemctl status " +
                    (unit or "") + "' for details.\n"
                )
                self.exit(1)
                return
            self.exit(0)
            return

        if verb == "daemon-reload":
            self.exit(0)
            return

        self.errorWrite(f"Unknown command verb {verb}.\n")
        self.exit(1)


commands["/usr/bin/systemctl"] = Command_systemctl
commands["/bin/systemctl"] = Command_systemctl
commands["systemctl"] = Command_systemctl
