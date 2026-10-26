#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cowrie SSH 蜜罐识别器（honeypot_detect.py）
================================================

用途
----
给定一个 SSH 服务地址，判断它是不是 Cowrie 蜜罐，并输出"暴露程度评分"。

这个脚本只做 **被动识别**：它像普通 SSH 客户端一样登录、执行只读命令、
观察返回结果。不包含任何利用、上传、提权、持久化、横向移动逻辑。

设计思路
--------
Cowrie 是"中等交互蜜罐"：它不执行真实命令，而是用 Python 模块模拟输出。
模拟必然和真实系统有偏差，偏差就是指纹。本项目把指纹分成四个层次：

  1. 协议层   —— SSH 握手阶段就能看到的东西（banner、算法集、通道能力）
  2. 认证层   —— 它接受什么密码
  3. 文件系统层 —— 假文件系统与真实系统的一致性
  4. 命令行为层 —— 模拟命令的输出与真实 GNU coreutils 的差异

每一层内部，检测项按"证据强度"分为三级：

  DECISIVE（决定性）  单条命中即可判定为蜜罐。这类特征在真实系统上不可能出现。
  STRONG  （强信号）  在真实系统上出现的概率极低，2 条以上命中即判定。
  WEAK    （弱信号）  单独看可能只是配置差异，需要多条同时命中才有说服力。

评分模型
--------
每个检测项有分值，命中则累加。满分 100，最终输出 0-100 的"暴露指数"：

    >= 60  确定是蜜罐（Cowrie）
    30-59  高度可疑
    10-29  存在异常，建议人工复核
    <  10  未发现明显蜜罐特征

注意：分值不是"漏洞严重性"，而是"被识破的容易程度"。指数越高越容易被识破。

用法
----
    # 基本用法（默认输出人类可读的报告）
    python3 honeypot_detect.py --host 192.168.122.252 --port 2222

    # 输出 JSON（便于自动化对比升级前后）
    python3 honeypot_detect.py --host 192.168.122.252 --port 2222 --json

    # 只用协议层和认证层，不登录（最快、最隐蔽）
    python3 honeypot_detect.py --host 192.168.122.252 --port 2222 --passive

    # 导出完整证据
    python3 honeypot_detect.py --host 192.168.122.252 --port 2222 --evidence evidence.json

    # 指定凭据（默认用 root/password，Cowrie 默认放行）
    python3 honeypot_detect.py --host X --port 2222 --user root --password password

依赖
----
    paramiko >= 3.0   （pip install paramiko）
    其余均为 Python 标准库。

退出码
------
    0  已识别为蜜罐（指数 >= 60）
    1  未识别（指数 < 60）
    2  连接失败或参数错误
"""

from __future__ import annotations

import argparse
import json
import random
import re
import socket
import string
import sys
import time
from dataclasses import dataclass, field
from typing import Optional

try:
    import paramiko
except ImportError:
    sys.stderr.write("错误：缺少 paramiko，请先执行 pip install paramiko\n")
    sys.exit(2)


# ============================================================================
# 一、检测项定义
# ============================================================================

# 证据强度
DECISIVE = "决定性"   # 单条命中即可判定
STRONG = "强信号"     # 需 2 条以上
WEAK = "弱信号"       # 需多条同时命中


@dataclass
class Finding:
    """一条检测结果。

    一条 Finding 描述"我检查了什么、看到了什么、这说明了什么"。
    即使没有命中也会被记录下来，便于报告里说明"这些项我查过了"。
    """
    id: str                  # 唯一标识，如 "fs.os_release_is_dir"
    name: str                # 人类可读名称
    strength: str            # DECISIVE / STRONG / WEAK
    weight: int              # 命中时贡献的分值
    hit: bool = False        # 是否命中（True = 发现蜜罐特征）
    evidence: str = ""       # 实际观测到的证据（原始输出摘录）
    explanation: str = ""    # 这条特征为什么能说明问题
    error: str = ""          # 检查过程中的错误（连接问题等，不算命中）


@dataclass
class Report:
    """整份检测报告。"""
    target: str = ""
    timestamp: str = ""
    findings: list[Finding] = field(default_factory=list)
    score: int = 0
    raw_score: int = 0          # 未裁剪的权重总和，用于观察改造进展
    by_layer: dict = field(default_factory=dict)   # 各层得分小计
    verdict: str = ""
    connection_ok: bool = False
    login_ok: bool = False

    def get(self, fid: str) -> Optional[Finding]:
        """按 id 取一条结果。"""
        for f in self.findings:
            if f.id == fid:
                return f
        return None


# ============================================================================
# 二、SSH 会话封装
# ============================================================================

class Session:
    """封装一个到目标的交互式 SSH 会话。

    为什么必须用交互式 shell 而不是 exec_command：
    这是本项目最先发现的指纹之一 —— Cowrie 不支持 SSH 的 exec 通道
    （`ssh host '命令'` 这种用法），而真实 OpenSSH 支持。所以我们的探测
    本身就必须走 invoke_shell，否则连不上。
    """

    # Cowrie 提示符类似 "root@ubuntu-server:~# "，真实 bash 可能是
    # "user@host:~$ " 或 "root@host:/path# "。这个正则覆盖常见形式。
    PROMPT_RE = re.compile(r"[\r\n]([^\r\n]{0,120}?[#$] )$")

    def __init__(self, host: str, port: int, user: str, password: str,
                 timeout: float = 15.0):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.timeout = timeout
        self.client: Optional[paramiko.SSHClient] = None
        self.chan = None
        self.hostname_from_prompt: Optional[str] = None
        self.prompt_user: Optional[str] = None

    # ---- 连接 ------------------------------------------------------

    def connect(self) -> None:
        """建立 SSH 连接并打开交互式 shell。"""
        self.client = paramiko.SSHClient()
        # 蜜罐的 host key 会变，不做校验
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(
            self.host,
            port=self.port,
            username=self.user,
            password=self.password,
            look_for_keys=False,
            allow_agent=False,
            timeout=self.timeout,
            auth_timeout=self.timeout,
            banner_timeout=self.timeout,
        )
        # term/width/height 影响服务端发来的终端控制序列，设置成常见值
        self.chan = self.client.invoke_shell(term="xterm", width=200, height=50)
        time.sleep(0.8)
        self._drain()

    def close(self) -> None:
        """关闭连接，忽略关闭过程中的异常。"""
        try:
            if self.chan is not None:
                self.chan.close()
        except Exception:
            pass
        try:
            if self.client is not None:
                self.client.close()
        except Exception:
            pass

    # ---- 底层收发 --------------------------------------------------

    def _drain(self) -> str:
        """把通道里当前所有可读数据读干净。"""
        buf = b""
        deadline = time.time() + 3.0
        while time.time() < deadline:
            if not self.chan.recv_ready():
                # 再等一小会儿，避免命令输出还没到就返回
                time.sleep(0.15)
                if not self.chan.recv_ready():
                    break
            buf += self.chan.recv(65535)
        return buf.decode("utf-8", errors="replace")

    def run(self, command: str, settle: float = 0.55) -> str:
        """执行一条命令，返回去掉回显和提示符之后的原始输出。

        settle 是发命令后等待服务端输出的时间。蜜罐的响应通常很快，
        但为了兼容真实系统的慢命令，给一个保守值。
        """
        if self.chan is None:
            raise RuntimeError("会话未建立")
        self.chan.sendall(command + "\n")
        time.sleep(settle)
        raw = self._drain()
        self._remember_prompt(raw)
        return self._clean(raw, command)

    # ---- 输出清洗 --------------------------------------------------

    def _remember_prompt(self, raw: str) -> None:
        """从提示符里解析出主机名，用于和 /etc/hostname 对比。

        注意：必须先剥掉 ANSI 序列再匹配。Cowrie 的提示符前会插一个
        ESC[4h（开启下划线），如果直接对原始字节做正则，会把提示符本身挡住。
        """
        text = re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", "", raw)
        # 形如 "root@ubuntu-server:~# " 或 "user@host:/var/www$ "
        matches = re.findall(r"([A-Za-z0-9_.-]+)@([A-Za-z0-9_.-]+):[^\r\n]*?[#$] ?", text)
        if matches:
            # 取最后一个匹配 —— 提示符在输出末尾
            self.hostname_from_prompt = matches[-1][1]
        # 同时记录用户名的来源，供报告使用
        self.prompt_user = matches[-1][0] if matches else None

    def _clean(self, raw: str, command: str) -> str:
        """去掉 ANSI 转义、命令回显、结尾提示符。

        Cowrie 会在每次输出前后插入 \\x1b[4l 和 \\x1b[4h（终端下划线开关），
        真实 shell 不会。这里先清掉，因为这条差异本身会被单独检测
        （见 proto.underline_escape），清洗只是为了让后续命令输出可读。
        """
        # 去掉所有 ANSI CSI / OSC 序列
        text = re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", "", raw)
        text = re.sub(r"\x1b\][^\x07\x1b]*(\x07|\x1b\\)", "", text)
        text = text.replace("\r\n", "\n").replace("\r", "\n")

        lines = text.split("\n")
        # 第一行通常是命令回显，去掉
        if lines and lines[0].strip().endswith(command.strip()):
            lines = lines[1:]
        # 最后一行通常是新的提示符，去掉
        while lines and re.search(r"[#$]\s*$", lines[-1]) and "@" in lines[-1]:
            lines = lines[:-1]
        return "\n".join(lines).strip("\n")


# ============================================================================
# 三、各层检测逻辑
# ============================================================================

def check_protocol(rep: Report, host: str, port: int, timeout: float,
                   user: str = "root", password: str = "password") -> None:
    """协议层检测：只看 SSH 握手，不登录。

    这一层最隐蔽 —— 不产生认证日志（虽然仍会留下连接记录）。
    user/password 仅用于 exec 通道探测，需要一次真实登录。
    """

    # ---- 1. 读取 SSH banner ----
    banner = ""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        banner = sock.recv(512).decode("utf-8", errors="replace").strip()
        sock.close()
    except Exception as exc:
        rep.findings.append(Finding(
            id="proto.connect", name="SSH 端口可达", strength=WEAK, weight=0,
            error=f"{type(exc).__name__}: {exc}",
        ))
        return

    rep.connection_ok = True
    rep.findings.append(Finding(
        id="proto.banner", name="SSH Banner", strength=WEAK, weight=0,
        evidence=banner, explanation="记录服务端声明的 SSH 版本字符串",
    ))

    # ---- 2. banner 版本字符串与真实发行版是否匹配 ----
    # Cowrie 的 banner 由 [ssh] version 配置项决定，和假文件系统里
    # /etc/os-release 的内容互相独立，容易出现矛盾。
    # 默认配置是 Debian 12，但假文件系统是 Debian 11 风格。
    if banner.startswith("SSH-2.0-"):
        ver = banner[len("SSH-2.0-"):]
        # 真实 OpenSSH 的 banner 一般带发行版后缀，如 "Debian-2+deb12u3"
        # Cowrie 也能伪造这个，所以单独看不是强信号；但格式异常就是强信号
        if not re.match(r"^OpenSSH_[\d.p]+", ver):
            rep.findings.append(Finding(
                id="proto.banner_nonstandard",
                name="Banner 版本字符串格式异常",
                strength=STRONG, weight=12, hit=True,
                evidence=ver,
                explanation="真实 OpenSSH 的版本字符串以 OpenSSH_x.y 开头",
            ))

    # ---- 3. 算法集指纹（这是最难伪造的一层）----
    #
    # 做法：直接读原始 TCP，自己解析 KEXINIT 包，不依赖 paramiko 内部实现。
    # 原因：paramiko 5.x 在一次握手后会清空 remote_kex_init，拿不到原始数据；
    # 而自己解析还有个好处 —— 不触发任何认证，日志里只留一条连接记录。
    #
    # SSH 握手流程：
    #   服务端先发 banner（"SSH-2.0-..." 一行）
    #   客户端回自己的 banner
    #   双方各发一个 SSH_MSG_KEXINIT（报文类型 20）声明支持的算法
    try:
        _banner2, algos = _grab_kexinit(host, port, timeout)

        if algos:
            kex_set = set(algos.get("kex", []))
            enc_set = set(algos.get("enc_c2s", [])) | set(algos.get("enc_s2c", []))
            mac_set = set(algos.get("mac_c2s", [])) | set(algos.get("mac_s2c", []))

            # (a) 现代 AEAD 密码：OpenSSH 7.3+ 默认启用
            #     Cowrie 的 Twisted 栈完全没有 AEAD 支持
            aead = {"chacha20-poly1305@openssh.com",
                    "aes128-gcm@openssh.com", "aes256-gcm@openssh.com"}
            has_aead = bool(enc_set & aead)
            rep.findings.append(Finding(
                id="proto.no_aead_cipher",
                name="未提供任何 AEAD 密码算法",
                strength=STRONG, weight=16, hit=not has_aead,
                evidence=f"enc = {sorted(enc_set)}",
                explanation=(
                    "OpenSSH 6.5 起提供 aes*-gcm，6.7 起提供 chacha20-poly1305，"
                    "现代版本默认启用。完全没有任何 AEAD 算法说明这不是 OpenSSH 的加密栈。"
                ),
            ))

            # (b) CBC 模式密码：OpenSSH 8.2 起默认不再提供
            legacy_enc = {"3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc",
                          "cast128-cbc", "blowfish-cbc", "arcfour"}
            enc_legacy = enc_set & legacy_enc
            rep.findings.append(Finding(
                id="proto.legacy_cbc",
                name="提供已废弃的 CBC/弱密码算法",
                strength=STRONG, weight=14, hit=bool(enc_legacy),
                evidence=f"命中 {sorted(enc_legacy)}",
                explanation=(
                    "OpenSSH 8.2（2020 年）起默认禁用全部 CBC 模式算法，"
                    "原因是 Padding Oracle 攻击（CVE-2008-5161 等）。"
                    "仍在宣告 3des-cbc / cast128-cbc 的服务端不可能是现代 OpenSSH。"
                ),
            ))

            # (c) 缺少 ETM（Encrypt-then-MAC）MAC
            #     OpenSSH 7.2+ 默认优先使用 *-etm@openssh.com
            has_etm = any("etm@openssh.com" in m for m in mac_set)
            rep.findings.append(Finding(
                id="proto.no_etm_mac",
                name="未提供 Encrypt-then-MAC 算法",
                strength=STRONG, weight=14, hit=not has_etm,
                evidence=f"mac = {sorted(mac_set)}",
                explanation=(
                    "OpenSSH 6.2 起支持、7.2 起默认启用 *-etm@openssh.com。"
                    "一个 ETM 算法都没有，说明 MAC 层也不是 OpenSSH 的实现。"
                ),
            ))

            # (d) 仍提供 hmac-md5 / hmac-sha1：OpenSSH 8.8 起默认移除 hmac-md5
            weak_mac = {m for m in mac_set if "md5" in m}
            rep.findings.append(Finding(
                id="proto.md5_mac",
                name="提供已被移除的 hmac-md5",
                strength=STRONG, weight=12, hit=bool(weak_mac),
                evidence=f"命中 {sorted(weak_mac)}",
                explanation=(
                    "OpenSSH 8.8（2021 年）从默认算法集中移除了 hmac-md5 与 hmac-ripemd160。"
                    "仍然宣告 md5 MAC 是老版本或非 OpenSSH 实现的标志。"
                ),
            ))

            # (e) host key 算法：现代 OpenSSH 用 rsa-sha2-512/256，不再用裸 ssh-rsa
            hostkey = set(algos.get("hostkey", []))
            only_legacy_rsa = ("ssh-rsa" in hostkey and
                               not ({"rsa-sha2-512", "rsa-sha2-256"} & hostkey))
            rep.findings.append(Finding(
                id="proto.legacy_rsa_hostkey",
                name="host key 仅提供旧式 ssh-rsa（无 rsa-sha2-*）",
                strength=WEAK, weight=8, hit=only_legacy_rsa,
                evidence=f"hostkey = {sorted(hostkey)}",
                explanation=(
                    "OpenSSH 7.2 起用 rsa-sha2-256/512 取代裸 ssh-rsa 的签名，"
                    "8.8 起默认禁用 ssh-rsa。只宣告 ssh-rsa 说明实现较旧。"
                ),
            ))
    except Exception as exc:
        rep.findings.append(Finding(
            id="proto.kex", name="SSH 算法集探测", strength=WEAK, weight=0,
            error=f"{type(exc).__name__}: {exc}",
        ))

    # ---- 4. 是否支持 exec 通道 ----
    # 真实 OpenSSH 支持 `ssh host 'command'`（exec 通道）。
    # Cowrie 只实现了交互式 shell，exec 通道会直接关闭。
    # 这是一个**非常强的指纹**，而且在协议层就能测出来。
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        # 这里必须用调用方提供的凭据 —— 用默认密码连真实 sshd 会认证失败，
        # 而认证失败会被误判成"通道被关闭"。认证失败的结论是不可信的。
        client.connect(host, port=port, username=user, password=password,
                       look_for_keys=False, allow_agent=False, timeout=timeout)
        try:
            _in, _out, _err = client.exec_command("true", timeout=timeout)
            _out.read()
            exec_ok = True
        except Exception:
            exec_ok = False
        client.close()

        rep.findings.append(Finding(
            id="proto.no_exec_channel",
            name="不支持 SSH exec 通道",
            strength=STRONG, weight=18, hit=not exec_ok,
            evidence=f"exec_command 结果：{'成功' if exec_ok else '通道被关闭'}",
            explanation=(
                "所有真实 OpenSSH 都支持 `ssh host '命令'` 的非交互模式。"
                "exec 通道不可用说明服务端是自行实现的最小 SSH 栈，"
                "这是 Cowrie（Twisted）最典型的结构性特征之一，且无法通过配置修复。"
            ),
        ))
    except paramiko.AuthenticationException:
        # 认证失败 → 无法验证 exec 通道，这一项记为"未测试"而不是"正常"
        rep.findings.append(Finding(
            id="proto.no_exec_channel",
            name="不支持 SSH exec 通道",
            strength=STRONG, weight=18, hit=False,
            error="认证失败，无法验证（此项未参与判定）",
            explanation="exec 通道需要成功登录才能测试",
        ))
    except Exception as exc:
        rep.findings.append(Finding(
            id="proto.no_exec_channel", name="不支持 SSH exec 通道",
            strength=STRONG, weight=18, hit=False,
            error=f"{type(exc).__name__}: {exc}（此项未参与判定）",
        ))


def _grab_kexinit(host: str, port: int, timeout: float = 8.0) -> tuple[str, dict]:
    """直接读原始 TCP 连接，取出服务端在 SSH_MSG_KEXINIT 里宣告的算法列表。

    为什么不用 paramiko 拿这个数据：
      - paramiko 5.x 在握手完成后会清空 remote_kex_init，拿不到；
      - 自己解析还能完全避开认证流程，日志里只留一条连接记录。

    SSH 传输层握手（RFC 4253 第 4.2 节）：
      服务端 → 客户端   版本字符串 "SSH-2.0-xxx\\r\\n"
      客户端 → 服务端   版本字符串
      双方各自发送 SSH_MSG_KEXINIT

    报文结构：
      uint32    packet_length        （不含自身 4 字节和 MAC）
      byte      padding_length
      byte[n]   payload
      byte[m]   padding
    payload 的第一字节就是消息类型，20 表示 KEXINIT。

    KEXINIT 载荷结构：
      byte      SSH_MSG_KEXINIT (20)
      byte[16]  cookie
      name-list kex algorithms
      name-list server host key algorithms
      name-list encryption algorithms client to server
      name-list encryption algorithms server to client
      name-list MAC algorithms client to server
      name-list MAC algorithms server to client
      name-list compression algorithms client to server
      name-list compression algorithms server to client
      ...
    每个 name-list 是 uint32 长度 + 逗号分隔的 ASCII 字符串。

    返回 (banner, {算法类别: [算法名, ...]})
    """
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    try:
        # ---- 读服务端 banner ----
        line = b""
        while not line.endswith(b"\n"):
            ch = sock.recv(1)
            if not ch:
                break
            line += ch
        banner = line.strip().decode("utf-8", errors="replace")

        # ---- 发我方 banner，触发服务端发 KEXINIT ----
        sock.sendall(b"SSH-2.0-Probe_1.0\r\n")

        # ---- 读一个完整 SSH 包 ----
        buf = b""
        sock.settimeout(4.0)
        try:
            while True:
                if len(buf) >= 4:
                    need = 4 + int.from_bytes(buf[:4], "big")
                    if len(buf) >= need:
                        break
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
        except socket.timeout:
            pass

        if len(buf) < 6:
            return banner, {}

        pkt_len = int.from_bytes(buf[:4], "big")
        pad_len = buf[4]
        payload = buf[5:4 + pkt_len - pad_len]

        if not payload or payload[0] != 20:
            return banner, {}

        # ---- 解析各 name-list ----
        names = ["kex", "hostkey", "enc_c2s", "enc_s2c",
                 "mac_c2s", "mac_s2c", "comp_c2s", "comp_s2c"]
        out: dict[str, list[str]] = {}
        pos = 17  # 跳过消息类型(1) + cookie(16)
        for name in names:
            if pos + 4 > len(payload):
                break
            length = int.from_bytes(payload[pos:pos + 4], "big")
            pos += 4
            if length == 0 or pos + length > len(payload):
                out[name] = []
                continue
            out[name] = payload[pos:pos + length].decode(
                "ascii", errors="replace").split(",")
            pos += length

        return banner, out
    finally:
        try:
            sock.close()
        except Exception:
            pass


def check_authentication(rep: Report, host: str, port: int, timeout: float) -> None:
    """认证层检测：看它接受什么密码。

    这是 Cowrie 最容易暴露的一层，但也是最"设计使然"的一层 ——
    蜜罐故意接受任意密码，否则攻击者进不来。所以这条命中率高但可修复性低
    （修了就不像蜜罐了）。
    """
    # 生成一个高熵随机密码，真实系统绝不可能接受
    rand_pw = "".join(random.choices(string.ascii_letters + string.digits + "!@#$%^&*", k=24))
    accepted_random = False
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, port=port, username="root", password=rand_pw,
                       look_for_keys=False, allow_agent=False, timeout=timeout)
        accepted_random = True
        client.close()
    except paramiko.AuthenticationException:
        accepted_random = False
    except Exception as exc:
        rep.findings.append(Finding(
            id="auth.rand", name="随机密码测试", strength=WEAK, weight=0,
            error=f"{type(exc).__name__}: {exc}",
        ))

    rep.findings.append(Finding(
        id="auth.accepts_random_password",
        name="接受任意随机密码",
        strength=DECISIVE, weight=30, hit=accepted_random,
        evidence=f"尝试密码 {rand_pw!r} → {'登录成功' if accepted_random else '被拒绝'}",
        explanation=(
            "真实系统不允许无意义的随机密码登录。"
            "接受任意密码是蜜罐 UserDB 的默认行为（root 除少数黑名单外全放行）。"
            "这一条几乎可以单独定案。"
        ),
    ))


# 需要在蜜罐内执行的探测命令 -> 对应的检测项
SHELL_PROBES = [
    # (命令, 说明)
    ("id", "当前用户"),
    ("hostname", "主机名命令输出"),
    ("cat /etc/hostname", "假文件系统里的主机名"),
    ("cat /etc/os-release", "发行版标识文件"),
    ("ls -ld /etc/os-release", "发行版标识文件的类型"),
    ("ls -la /", "根目录列表（看时间戳和隐藏文件）"),
    ("ls -la /.dockerenv", "容器标记文件"),
    ("ls -la /proc/docker", "容器标记目录"),
    ("head -3 /etc/passwd", "数字简写形式的 head"),
    ("tail -2 /etc/passwd", "数字简写形式的 tail"),
    ("df -h", "磁盘使用情况"),
    ("sed -n 1p /etc/passwd", "sed 流编辑器"),
    ("top -n 1", "top 进程查看器"),
    ("which ss ip systemctl", "现代系统工具是否存在"),
    ("cat /etc/lsb-release", "Ubuntu/Debian 系发行版标识"),
    ("cat /etc/debian_version", "Debian 版本号"),
    ("ifconfig", "网卡信息"),
    ("uname -a", "内核信息"),
    ("uptime", "运行时长"),
    ("cat /etc/ssh/sshd_config", "SSH 服务端配置"),
]


def check_filesystem_and_shell(rep: Report, session: Session) -> None:
    """文件系统层 + 命令行为层检测。

    这两层合在一起做，因为都依赖登录后的 shell。
    """
    out: dict[str, str] = {}
    for cmd, _desc in SHELL_PROBES:
        try:
            out[cmd] = session.run(cmd)
        except Exception as exc:
            out[cmd] = f"<ERROR {type(exc).__name__}: {exc}>"

    # 把完整输出塞进报告，方便事后人工复核
    rep.findings.append(Finding(
        id="shell.raw",
        name="命令探测原始输出",
        strength=WEAK, weight=0,
        evidence="\n\n".join(f"$ {c}\n{o}" for c, o in out.items()),
        explanation="全部探测命令的原始返回，供人工复核",
    ))

    # ---- 文件系统层 ----

    # (a) /etc/os-release 不是普通文件
    # Cowrie 的假文件系统里这个路径可能是一个空目录，cat 无输出，
    # 而 ls -l 显示成一个大小的普通文件 —— 两者矛盾。
    os_rel = out.get("cat /etc/os-release", "")
    os_rel_ls = out.get("ls -ld /etc/os-release", "")
    os_rel_broken = False
    if "No such file" in os_rel or "No such file" in os_rel_ls:
        os_rel_broken = False  # 不存在不算异常（有些系统确实没有）
    elif not os_rel.strip() and os_rel_ls.strip():
        os_rel_broken = True
    elif os_rel_ls.startswith("d"):
        os_rel_broken = True

    rep.findings.append(Finding(
        id="fs.os_release_invalid",
        name="/etc/os-release 内容为空或类型异常",
        strength=DECISIVE, weight=25, hit=os_rel_broken,
        evidence=f"$ cat /etc/os-release\n{os_rel or '<空>'}\n$ ls -ld /etc/os-release\n{os_rel_ls}",
        explanation=(
            "所有现代 Linux 发行版的 /etc/os-release 都必须是非空普通文件。"
            "cat 无输出而 ls 有内容，说明这是假文件系统的占位项。"
        ),
    ))

    # (b) 主机名不一致：提示符 vs hostname 命令 vs /etc/hostname
    #
    # 三个来源应当完全一致：
    #   1. 提示符里的主机名（shell 的 PS1，来自内核 hostname）
    #   2. `hostname` 命令的输出
    #   3. /etc/hostname 的内容（systemd 启动时写入内核）
    # 真实系统上三者由同一个值驱动；Cowrie 里它们来自三份独立配置。
    prompt_host = session.hostname_from_prompt
    cmd_host = out.get("hostname", "").strip().split("\n")[0].strip()
    etc_host = out.get("cat /etc/hostname", "").strip().split("\n")[0].strip()

    sources = {v for v in (prompt_host, cmd_host, etc_host) if v}
    host_mismatch = len(sources) > 1

    rep.findings.append(Finding(
        id="fs.hostname_mismatch",
        name="主机名的多个来源互相矛盾",
        strength=STRONG, weight=15, hit=host_mismatch,
        evidence=(f"提示符={prompt_host!r}  `hostname`={cmd_host!r}  "
                  f"/etc/hostname={etc_host!r}"),
        explanation=(
            "真实系统上这三者必然相同。"
            "Cowrie 的提示符来自 [honeypot] hostname 配置，"
            "`hostname` 命令的输出也是配置值，但假文件系统里的 /etc/hostname "
            "是第三份独立数据，三者互不同步。"
        ),
    ))

    # (c) 容器标记文件存在
    dockerenv = out.get("ls -la /.dockerenv", "")
    procdocker = out.get("ls -la /proc/docker", "")
    has_docker = ("No such file" not in dockerenv and dockerenv.strip() != "") or \
                 ("No such file" not in procdocker and procdocker.strip() != "")

    rep.findings.append(Finding(
        id="fs.container_markers",
        name="存在容器标记（/.dockerenv 或 /proc/docker）",
        strength=STRONG, weight=15, hit=has_docker,
        evidence=f"$ ls -la /.dockerenv\n{dockerenv}\n$ ls -la /proc/docker\n{procdocker}",
        explanation=(
            "这两个路径只存在于 Docker 容器内部。"
            "Cowrie 自带的 fs.pickle 是从一个真实 Docker 容器里制作快照抓出来的，"
            "所以把这套容器痕迹一起带进了'物理服务器'的伪装里。"
        ),
    ))

    # (d) 根目录时间戳高度一致
    #
    # 真实系统的 / 下，每个目录的 mtime 取决于它最后一次被修改的时间，
    # 分布在数年范围内。Cowrie 的假文件系统是从一次容器快照生成的，
    # 大量条目共享快照时刻的同一个时间戳。
    #
    # 判据：统计 ls -la / 里出现的所有时间戳，若去重后不超过 2 个
    # 而总数 >= 10，说明几乎全部来自同一时刻。
    ls_root = out.get("ls -la /", "")
    stamps = re.findall(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}", ls_root)
    # 真实系统的去重率通常在 0.8 以上（几乎每个条目都不同）。
    # 取 0.3 作为阈值：出现大量重复时间戳即视为可疑。
    ratio = (len(set(stamps)) / len(stamps)) if stamps else 1.0
    stamp_dup = len(stamps) >= 10 and ratio <= 0.30

    rep.findings.append(Finding(
        id="fs.uniform_timestamps",
        name="根目录文件时间戳高度雷同",
        strength=WEAK, weight=10, hit=stamp_dup,
        evidence=(f"{len(stamps)} 个条目，去重后 {len(set(stamps))} 个"
                  f"（去重率 {ratio:.0%}）：{sorted(set(stamps))[:6]}"),
        explanation=(
            "真实系统上 / 下各目录的修改时间分散在不同年份，去重率接近 1。"
            "假文件系统从一次快照生成，大量条目共享少数几个 mtime。"
        ),
    ))

    # (e) sshd_config 为空
    sshd = out.get("cat /etc/ssh/sshd_config", "")
    sshd_empty = ("No such file" not in sshd) and (sshd.strip() == "") and \
                 ("cat /etc/ssh/sshd_config" in out)

    rep.findings.append(Finding(
        id="fs.sshd_config_empty",
        name="/etc/ssh/sshd_config 为空",
        strength=STRONG, weight=12, hit=sshd_empty,
        evidence=sshd or "<空>",
        explanation=(
            "运行 SSH 服务的真实系统必然有非空的 sshd_config。"
            "文件存在但内容为空，说明假文件系统只建了路径没填内容。"
        ),
    ))

    # ---- 命令行为层 ----

    # (f) head -3 / tail -2 不接受数字简写
    # POSIX 允许 `head -3 file` 这种写法，GNU coreutils 也支持。
    # Cowrie 的模拟器只认 `head -n 3`。
    head_out = out.get("head -3 /etc/passwd", "")
    head_broken = "invalid option" in head_out or "invalid number" in head_out

    rep.findings.append(Finding(
        id="cmd.head_numeric_shorthand",
        name="head -3 不支持数字简写",
        strength=STRONG, weight=18, hit=head_broken,
        evidence=head_out or "<无输出>",
        explanation=(
            "`head -3 file` 是 POSIX 与 GNU coreutils 都支持的写法，"
            "真实 Linux 上不会报 invalid option。只有自行实现的简化解析器才会这样。"
        ),
    ))

    tail_out = out.get("tail -2 /etc/passwd", "")
    tail_broken = "invalid option" in tail_out or "invalid number" in tail_out
    rep.findings.append(Finding(
        id="cmd.tail_numeric_shorthand",
        name="tail -2 不支持数字简写",
        strength=STRONG, weight=12, hit=tail_broken,
        evidence=tail_out or "<无输出>",
        explanation="同 head，是同一类简化解析器的表现",
    ))

    # (g) df / sed 报 "cannot execute binary file"
    # Cowrie 对未实现的命令会返回一个"通用二进制"内容，导致内核层面报格式错误。
    # 真实系统上 df 和 sed 是标准基础命令，不可能缺失。
    df_out = out.get("df -h", "")
    df_broken = "cannot execute binary file" in df_out or "Exec format error" in df_out

    rep.findings.append(Finding(
        id="cmd.df_broken_binary",
        name="df 无法执行（二进制格式错误）",
        strength=DECISIVE, weight=20, hit=df_broken,
        evidence=df_out or "<无输出>",
        explanation=(
            "df 属于 coreutils，是所有 Linux 发行版的必备命令。"
            "报 'Exec format error' 意味着这是一个被当作可执行文件返回的假二进制，"
            "说明命令根本没有被真正执行。"
        ),
    ))

    sed_out = out.get("sed -n 1p /etc/passwd", "")
    sed_broken = "cannot execute binary file" in sed_out or "Exec format error" in sed_out
    rep.findings.append(Finding(
        id="cmd.sed_broken_binary",
        name="sed 无法执行（二进制格式错误）",
        strength=DECISIVE, weight=15, hit=sed_broken,
        evidence=sed_out or "<无输出>",
        explanation="同 df。sed 是 POSIX 必备工具，真实系统不可能无法执行。",
    ))

    # (h) top 崩溃
    top_out = out.get("top -n 1", "")
    top_broken = "Cannot allocate" in top_out or "E82" in top_out or \
                 "top:" in top_out and "invalid" in top_out

    rep.findings.append(Finding(
        id="cmd.top_crash",
        name="top 执行异常",
        strength=STRONG, weight=12, hit=top_broken,
        evidence=top_out or "<无输出>",
        explanation=(
            "top 在 Cowrie 里是通过读取预置的 /proc 数据模拟的，"
            "遇到真实参数组合会走进未处理的代码路径并报错。"
        ),
    ))

    # (i) ss / ip / systemctl 不存在
    which_out = out.get("which ss ip systemctl", "")
    missing_modern = 0
    for tool in ("ss", "ip", "systemctl"):
        # which 对不存在的命令不输出任何东西
        if tool not in which_out:
            missing_modern += 1

    rep.findings.append(Finding(
        id="cmd.missing_modern_tools",
        name="缺少现代系统工具（ss/ip/systemctl）",
        strength=STRONG, weight=15, hit=missing_modern >= 2,
        evidence=f"$ which ss ip systemctl\n{which_out or '<无输出>'}\n缺失数量：{missing_modern}/3",
        explanation=(
            "iproute2（ip、ss）自 2001 年起就是主流发行版默认网络工具，"
            "systemd 自 2015 年起是 Ubuntu/Debian 默认 init。"
            "两者的缺失与 banner 宣称的 Debian 12 严重矛盾。"
        ),
    ))

    # (j) ifconfig 网卡名与真实环境不符
    ifc_out = out.get("ifconfig", "")
    # Cowrie 默认输出 eth0；现代系统用可预测命名（enp0s3、ens33 等）
    ifc_eth0 = bool(re.search(r"^eth\d", ifc_out, re.MULTILINE))

    rep.findings.append(Finding(
        id="cmd.legacy_nic_name",
        name="网卡使用旧的 eth0 命名",
        strength=WEAK, weight=8, hit=ifc_eth0,
        evidence=ifc_out[:300] if ifc_out else "<无输出>",
        explanation=(
            "systemd 的 net.ifnames 自 2015 年起默认启用可预测网卡名"
            "（enp0s3、ens33 等），现代 Debian/Ubuntu 不再使用 eth0。"
            "Cowrie 的 ifconfig 模拟输出是硬编码的 eth0。"
        ),
    ))

    # (k) 内核标识与发行版不一致
    #
    # 两个独立数据源：
    #   - uname 的构建字符串来自 [shell] kernel_build_string 配置
    #   - 发行版身份来自假文件系统的 /etc/os-release
    # 若 / 下存在 Ubuntu 特有的痕迹（如 /etc/lsb-release、snap 目录），
    # 而 uname 说 Debian，就矛盾了。
    uname_out = out.get("uname -a", "")
    ls_root_scan = out.get("ls -la /", "")
    ubuntu_markers = any(m in ls_root_scan for m in ("snap", ".dockerenv"))
    uname_debian = "debian" in uname_out.lower()
    lsb_out = out.get("cat /etc/lsb-release", "")
    # lsb-release 只有 Ubuntu/Debian 系有；如果读不到就算缺失，不作为证据
    kernel_mismatch = bool(uname_out) and uname_debian and bool(ubuntu_markers)

    rep.findings.append(Finding(
        id="cmd.kernel_distro_mismatch",
        name="内核标识与目录结构暗示的发行版不一致",
        strength=WEAK, weight=8, hit=kernel_mismatch,
        evidence=f"$ uname -a\n{uname_out}",
        explanation=(
            "uname 的构建字符串来自 [shell] kernel_build_string 配置，"
            "而目录结构来自假文件系统快照，两者独立，容易互相矛盾。"
        ),
    ))

    # (l) uptime 过短
    up_out = out.get("uptime", "")
    m = re.search(r"up\s+(?:(\d+)\s+day[s]?,\s*)?(?:(\d+):(\d+)|(\d+)\s+min)", up_out)
    minutes = None
    if m:
        if m.group(4):
            minutes = int(m.group(4))
        elif m.group(2):
            minutes = int(m.group(2)) * 60 + int(m.group(3))
        if m.group(1) and m.group(2):
            minutes += int(m.group(1)) * 1440

    uptime_short = minutes is not None and minutes < 60
    rep.findings.append(Finding(
        id="cmd.uptime_short",
        name="系统运行时间异常短",
        strength=WEAK, weight=10, hit=uptime_short,
        evidence=up_out or "<无输出>",
        explanation=(
            "Cowrie 的 uptime 从进程启动开始算，而不是从系统启动开始算，"
            "所以每次重启蜜罐都会显示成刚开机。生产服务器极少在 1 小时内重启。"
        ),
    ))

    # (m) 终端控制序列异常
    # 这里已经从输出里清洗掉了，改由 Session 记录原始数据来判断。
    # 见 check_terminal_quirks。
    _ = out


def check_terminal_quirks(rep: Report, host: str, port: int, user: str,
                          password: str, timeout: float) -> None:
    """会话层检测：终端控制序列与 shell 行为。

    单独开一个会话，专门观察原始字节流。
    """
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, port=port, username=user, password=password,
                       look_for_keys=False, allow_agent=False, timeout=timeout)
        chan = client.invoke_shell(term="xterm", width=200, height=50)
        time.sleep(0.8)
        while chan.recv_ready():
            chan.recv(65535)

        chan.sendall("echo MARKER_PROBE\n")
        time.sleep(0.8)
        raw = b""
        while chan.recv_ready():
            raw += chan.recv(65535)
        chan.close()
        client.close()

        raw_text = raw.decode("utf-8", errors="replace")

        # Cowrie 在每次输出前后插入 ESC[4l / ESC[4h（关闭/开启下划线）。
        # 真实 shell 不会主动发这两个序列。
        has_underline = "\x1b[4l" in raw_text or "\x1b[4h" in raw_text

        rep.findings.append(Finding(
            id="term.underline_escape",
            name="输出中出现异常的终端下划线控制序列",
            strength=STRONG, weight=15, hit=has_underline,
            evidence=repr(raw_text[:400]),
            explanation=(
                "Cowrie 在每条命令输出前后插入 \\x1b[4l / \\x1b[4h（关闭/开启下划线）。"
                "真实 bash 不会主动发送这两个序列。"
            ),
        ))

        # 真实 bash 会发送 bracketed-paste 模式（ESC[?2004h/l）和 OSC 标题设置，
        # Cowrie 不会。缺失本身是弱信号（用户可能改过 PS1 / 关闭了这些特性）。
        has_bracketed_paste = "\x1b[?2004" in raw_text
        rep.findings.append(Finding(
            id="term.no_bracketed_paste",
            name="缺少 bracketed paste 模式序列",
            strength=WEAK, weight=6, hit=not has_bracketed_paste,
            evidence="未观察到 \\x1b[?2004h/l",
            explanation=(
                "现代 bash（5.0+）默认启用 bracketed paste 与 OSC 3008 会话标记。"
                "缺失可能是用户自定义配置，所以只能算弱信号。"
            ),
        ))

    except Exception as exc:
        rep.findings.append(Finding(
            id="term.probe", name="终端行为探测", strength=WEAK, weight=0,
            error=f"{type(exc).__name__}: {exc}",
        ))


# ============================================================================
# 四、评分与结论
# ============================================================================

def compute_score(rep: Report) -> None:
    """根据命中项计算暴露指数。

    规则：
      - 任一条 DECISIVE 命中 → 直接给到 >= 70，保证判定为蜜罐
      - 其余按权重累加，上限 100
      - DECISIVE 命中数 >= 1 时，最低分 70
    """
    decisive_hits = 0
    total = 0
    strong_hits = 0
    weak_hits = 0

    for f in rep.findings:
        if not f.hit:
            continue
        total += f.weight
        if f.strength == DECISIVE:
            decisive_hits += 1
        elif f.strength == STRONG:
            strong_hits += 1
        else:
            weak_hits += 1

    # 只有一条不同的"强信号"命中时，不要判太重 —— 避免误报
    if decisive_hits == 0 and strong_hits == 1 and weak_hits <= 1:
        total = min(total, 25)

    if decisive_hits >= 1:
        total = max(total, 70)

    # 记录未裁剪的原始分：改造过程中分数会撞上 100 的天花板，
    # raw_score 能继续反映每一条检测项的消除情况。
    rep.raw_score = total
    rep.score = max(0, min(100, total))

    # 各层小计，便于定位"哪一层最难改"
    layers = {"proto": "协议层", "auth": "认证层", "fs": "文件系统层",
              "cmd": "命令行为层", "term": "终端行为层"}
    rep.by_layer = {}
    for prefix, label in layers.items():
        rep.by_layer[label] = sum(f.weight for f in rep.findings
                                  if f.hit and f.id.startswith(prefix))

    if rep.score >= 60:
        rep.verdict = "确定是蜜罐（Cowrie 或其衍生实现）"
    elif rep.score >= 30:
        rep.verdict = "高度可疑：疑似蜜罐"
    elif rep.score >= 10:
        rep.verdict = "存在异常，建议人工复核"
    else:
        rep.verdict = "未发现明显蜜罐特征"


# ============================================================================
# 五、输出
# ============================================================================

# ANSI 颜色（终端输出时用）
class C:
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


def print_report(rep: Report, show_evidence: bool, color: bool) -> None:
    """把检测结果打印成人能读的报告。"""
    def c(code: str, text: str) -> str:
        return f"{code}{text}{C.RESET}" if color else text

    print()
    print(c(C.BOLD, "=" * 78))
    print(c(C.BOLD, "  Cowrie SSH 蜜罐识别报告"))
    print(c(C.BOLD, "=" * 78))
    print(f"  目标      : {rep.target}")
    print(f"  时间      : {rep.timestamp}")
    print(f"  连接状态  : {'成功' if rep.connection_ok else c(C.RED, '失败')}")
    print(f"  登录状态  : {'成功' if rep.login_ok else c(C.RED, '失败')}")
    print()

    # 按强度分组显示
    order = [(DECISIVE, "决定性证据"), (STRONG, "强信号"), (WEAK, "弱信号")]
    for strength, title in order:
        items = [f for f in rep.findings
                 if f.strength == strength and f.id != "shell.raw"]
        if not items:
            continue
        hits = [f for f in items if f.hit]
        header = f"{title}  （命中 {len(hits)}/{len(items)}）"
        print(c(C.BOLD, f"── {header} " + "─" * max(0, 70 - len(header))))
        for f in items:
            if f.hit:
                mark = c(C.RED, "[命中]")
            elif f.error:
                mark = c(C.YELLOW, "[错误]")
            else:
                mark = c(C.GREEN, "[正常]")
            print(f"  {mark} {f.name}  {c(C.DIM, f'(+{f.weight})' if f.hit else '')}")
            if f.error:
                print(c(C.DIM, f"         {f.error}"))
            if show_evidence and f.evidence:
                ev = f.evidence.replace("\n", "\n         ")
                print(c(C.DIM, f"         证据: {ev[:800]}"))
            if show_evidence and f.explanation:
                print(c(C.DIM, f"         说明: {f.explanation}"))
        print()

    # 结论
    print(c(C.BOLD, "=" * 78))
    bar_len = rep.score // 2
    bar_color = C.RED if rep.score >= 60 else (C.YELLOW if rep.score >= 30 else C.GREEN)
    print(f"  暴露指数: {c(bar_color + C.BOLD, f'{rep.score}/100')}  "
          f"{c(bar_color, '█' * bar_len + '░' * (50 - bar_len))}")
    if rep.raw_score != rep.score:
        print(c(C.DIM, f"  原始权重和: {rep.raw_score}（超出上限，指数已封顶）"))
    if rep.by_layer:
        parts = [f"{k} {v}" for k, v in rep.by_layer.items() if v]
        print(c(C.DIM, "  分项小计: " + "  ".join(parts)))
    print(f"  判定结论: {c(bar_color + C.BOLD, rep.verdict)}")
    print(c(C.BOLD, "=" * 78))
    print()


def build_json(rep: Report, include_evidence: bool) -> dict:
    """构造 JSON 结构。"""
    findings = []
    for f in rep.findings:
        item = {
            "id": f.id,
            "name": f.name,
            "strength": f.strength,
            "weight": f.weight,
            "hit": f.hit,
        }
        if include_evidence:
            item["evidence"] = f.evidence
            item["explanation"] = f.explanation
        if f.error:
            item["error"] = f.error
        findings.append(item)

    return {
        "target": rep.target,
        "timestamp": rep.timestamp,
        "score": rep.score,
        "raw_score": rep.raw_score,
        "by_layer": rep.by_layer,
        "verdict": rep.verdict,
        "connection_ok": rep.connection_ok,
        "login_ok": rep.login_ok,
        "summary": {
            "decisive_hits": sum(1 for f in rep.findings
                                 if f.strength == DECISIVE and f.hit),
            "strong_hits": sum(1 for f in rep.findings
                               if f.strength == STRONG and f.hit),
            "weak_hits": sum(1 for f in rep.findings
                             if f.strength == WEAK and f.hit),
        },
        "findings": findings,
    }


# ============================================================================
# 六、主流程
# ============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Cowrie SSH 蜜罐识别器（只做被动检测，不包含任何利用逻辑）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例：\n"
            "  %(prog)s --host 192.168.122.252 --port 2222\n"
            "  %(prog)s --host 192.168.122.252 --port 2222 --json\n"
            "  %(prog)s --host 192.168.122.252 --port 2222 --passive\n"
        ),
    )
    parser.add_argument("--host", required=True, help="目标 IP 或主机名")
    parser.add_argument("--port", type=int, default=2222, help="SSH 端口，默认 2222")
    parser.add_argument("--user", default="root", help="登录用户名，默认 root")
    parser.add_argument("--password", default="password", help="登录密码，默认 password")
    parser.add_argument("--timeout", type=float, default=15.0, help="连接超时秒数，默认 15")
    parser.add_argument("--json", action="store_true", help="以 JSON 输出")
    parser.add_argument("--evidence", metavar="FILE", help="把完整证据写入指定 JSON 文件")
    parser.add_argument("--passive", action="store_true",
                        help="只做协议层与认证层检测，不进入 shell（更隐蔽）")
    parser.add_argument("--no-color", action="store_true", help="禁用彩色输出")
    parser.add_argument("--verbose", action="store_true", help="终端输出中包含证据")

    args = parser.parse_args()

    rep = Report(
        target=f"{args.host}:{args.port}",
        timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
    )

    # ---- 第 1 层：协议 ----
    check_protocol(rep, args.host, args.port, args.timeout,
                   user=args.user, password=args.password)

    # ---- 第 2 层：认证 ----
    if rep.connection_ok:
        check_authentication(rep, args.host, args.port, args.timeout)

    # ---- 第 3、4 层：文件系统与命令行为 ----
    if not args.passive and rep.connection_ok:
        session = Session(args.host, args.port, args.user, args.password, args.timeout)
        try:
            session.connect()
            rep.login_ok = True
            check_filesystem_and_shell(rep, session)
        except Exception as exc:
            rep.findings.append(Finding(
                id="shell.connect", name="建立交互式会话", strength=WEAK, weight=0,
                error=f"{type(exc).__name__}: {exc}",
            ))
        finally:
            session.close()

        # ---- 第 5 层：终端行为 ----
        if rep.login_ok:
            check_terminal_quirks(rep, args.host, args.port, args.user,
                                  args.password, args.timeout)

    # ---- 评分 ----
    compute_score(rep)

    # ---- 输出 ----
    use_color = (not args.no_color) and sys.stdout.isatty()

    if args.json:
        print(json.dumps(build_json(rep, include_evidence=args.verbose),
                         ensure_ascii=False, indent=2))
    else:
        print_report(rep, show_evidence=args.verbose, color=use_color)

    if args.evidence:
        try:
            with open(args.evidence, "w", encoding="utf-8") as fh:
                json.dump(build_json(rep, include_evidence=True), fh,
                          ensure_ascii=False, indent=2)
            if not args.json:
                print(f"完整证据已写入：{args.evidence}")
        except OSError as exc:
            sys.stderr.write(f"写入证据文件失败：{exc}\n")

    return 0 if rep.score >= 60 else 1


if __name__ == "__main__":
    sys.exit(main())
