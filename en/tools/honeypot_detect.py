#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cowrie SSH honeypot detector (honeypot_detect.py)
================================================

Purpose
-------
Given an SSH service address, decide whether it is a Cowrie honeypot and output an "exposure score".

This script performs **passive detection only**: it logs in like an ordinary SSH client, runs
read-only commands and observes the responses. It contains no exploitation, upload, privilege
escalation, persistence or lateral movement logic.

Design
------
Cowrie is a "medium-interaction honeypot": it does not execute real commands but emulates output
with Python modules. Emulation inevitably differs from a real system, and those differences are
fingerprints. This project groups the fingerprints into four layers:

  1. Protocol layer     -- things visible during the SSH handshake (banner, algorithm set, channel capabilities)
  2. Authentication     -- which passwords it accepts
  3. Filesystem layer   -- consistency of the fake filesystem with a real system
  4. Command behaviour  -- differences between emulated command output and real GNU coreutils

Within each layer, checks are graded by "evidence strength" into three levels:

  DECISIVE  a single hit is enough to conclude. Such a feature is impossible on a real system.
  STRONG    very unlikely on a real system; two or more hits conclude.
  WEAK      alone it may only be a configuration difference; needs several hits together to be convincing.

Scoring model
-------------
Each check has a weight, added up on a hit. The maximum is 100, and the final output is an
"exposure index" from 0 to 100:

    >= 60  definitely a honeypot (Cowrie)
    30-59  highly suspicious
    10-29  anomalies present, manual review recommended
    <  10  no obvious honeypot features found

Note: the weight is not "vulnerability severity" but "ease of being detected". A higher index means easier to detect.

Usage
-----
    # basic usage (human-readable report by default)
    python3 honeypot_detect.py --host 192.168.122.252 --port 2222

    # output JSON (handy for automated before/after comparison)
    python3 honeypot_detect.py --host 192.168.122.252 --port 2222 --json

    # protocol and auth layers only, no login (fastest, stealthiest)
    python3 honeypot_detect.py --host 192.168.122.252 --port 2222 --passive

    # export full evidence
    python3 honeypot_detect.py --host 192.168.122.252 --port 2222 --evidence evidence.json

    # specify credentials (defaults to root/password, which Cowrie accepts)
    python3 honeypot_detect.py --host X --port 2222 --user root --password password

Dependencies
------------
    paramiko >= 3.0   (pip install paramiko)
    everything else is the Python standard library.

Exit codes
----------
    0  identified as a honeypot (index >= 60)
    1  not identified (index < 60)
    2  connection failure or argument error
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
    sys.stderr.write("Error: paramiko missing, run pip install paramiko first\n")
    sys.exit(2)


# ============================================================================
# 1. Check definitions
# ============================================================================

# Evidence strength
DECISIVE = "DECISIVE"   # a single hit is enough to conclude
STRONG = "STRONG"       # needs 2 or more
WEAK = "WEAK"           # needs several together


@dataclass
class Finding:
    """A single check result.

    A Finding describes "what I checked, what I saw, and what it means".
    Even a non-hit is recorded, so the report can show "these items were checked".
    """
    id: str                  # unique id, e.g. "fs.os_release_is_dir"
    name: str                # human-readable name
    strength: str            # DECISIVE / STRONG / WEAK
    weight: int              # score contributed on a hit
    hit: bool = False        # whether it hit (True = honeypot feature found)
    evidence: str = ""       # evidence actually observed (raw output excerpt)
    explanation: str = ""    # why this feature is meaningful
    error: str = ""          # error during the check (connection issues etc., not a hit)


@dataclass
class Report:
    """The whole detection report."""
    target: str = ""
    timestamp: str = ""
    findings: list[Finding] = field(default_factory=list)
    score: int = 0
    raw_score: int = 0          # uncapped weight sum, used to track modification progress
    by_layer: dict = field(default_factory=dict)   # per-layer score subtotals
    verdict: str = ""
    connection_ok: bool = False
    login_ok: bool = False

    def get(self, fid: str) -> Optional[Finding]:
        """Get a result by id."""
        for f in self.findings:
            if f.id == fid:
                return f
        return None


# ============================================================================
# 2. SSH session wrapper
# ============================================================================

class Session:
    """Wrap an interactive SSH session to the target.

    Why an interactive shell is required instead of exec_command:
    this is one of the first fingerprints this project found -- Cowrie does not support the SSH
    exec channel (`ssh host 'command'`), while real OpenSSH does. So our probing itself must use
    invoke_shell, otherwise it cannot connect.
    """

    # Cowrie prompts look like "root@ubuntu-server:~# "; real bash may be
    # "user@host:~$ " or "root@host:/path# ". This regex covers the common forms.
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

    # ---- Connect --------------------------------------------------

    def connect(self) -> None:
        """Establish the SSH connection and open an interactive shell."""
        self.client = paramiko.SSHClient()
        # the honeypot host key changes, so do not verify it
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
        # term/width/height affect the terminal control sequences the server sends; use common values
        self.chan = self.client.invoke_shell(term="xterm", width=200, height=50)
        time.sleep(0.8)
        self._drain()

    def close(self) -> None:
        """Close the connection, ignoring exceptions during close."""
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

    # ---- Low-level I/O --------------------------------------------

    def _drain(self) -> str:
        """Drain all currently readable data from the channel."""
        buf = b""
        deadline = time.time() + 3.0
        while time.time() < deadline:
            if not self.chan.recv_ready():
                # wait a little longer, so we do not return before command output arrives
                time.sleep(0.15)
                if not self.chan.recv_ready():
                    break
            buf += self.chan.recv(65535)
        return buf.decode("utf-8", errors="replace")

    def run(self, command: str, settle: float = 0.55) -> str:
        """Run one command and return the raw output after stripping the echo and prompt.

        settle is how long to wait for server output after sending the command. A honeypot
        usually responds quickly, but a conservative value accommodates slow real commands.
        """
        if self.chan is None:
            raise RuntimeError("session not established")
        self.chan.sendall(command + "\n")
        time.sleep(settle)
        raw = self._drain()
        self._remember_prompt(raw)
        return self._clean(raw, command)

    # ---- Output cleaning ------------------------------------------

    def _remember_prompt(self, raw: str) -> None:
        """Parse the hostname from the prompt, to compare with /etc/hostname.

        Note: ANSI sequences must be stripped before matching. Cowrie inserts an ESC[4h
        (enable underline) before the prompt; matching the raw bytes directly would hide the prompt itself.
        """
        text = re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", "", raw)
        # like "root@ubuntu-server:~# " or "user@host:/var/www$ "
        matches = re.findall(r"([A-Za-z0-9_.-]+)@([A-Za-z0-9_.-]+):[^\r\n]*?[#$] ?", text)
        if matches:
            # take the last match -- the prompt is at the end of the output
            self.hostname_from_prompt = matches[-1][1]
        # also record where the username came from, for the report
        self.prompt_user = matches[-1][0] if matches else None

    def _clean(self, raw: str, command: str) -> str:
        """Strip ANSI escapes, the command echo and the trailing prompt.

        Cowrie inserts \\x1b[4l and \\x1b[4h (terminal underline toggle) around every output,
        while a real shell does not. We strip it here because that difference is checked
        separately (see proto.underline_escape); cleaning is only to keep later output readable.
        """
        # strip all ANSI CSI / OSC sequences
        text = re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", "", raw)
        text = re.sub(r"\x1b\][^\x07\x1b]*(\x07|\x1b\\)", "", text)
        text = text.replace("\r\n", "\n").replace("\r", "\n")

        lines = text.split("\n")
        # the first line is usually the command echo, drop it
        if lines and lines[0].strip().endswith(command.strip()):
            lines = lines[1:]
        # the last line is usually the new prompt, drop it
        while lines and re.search(r"[#$]\s*$", lines[-1]) and "@" in lines[-1]:
            lines = lines[:-1]
        return "\n".join(lines).strip("\n")


# ============================================================================
# 3. Per-layer detection logic
# ============================================================================

def check_protocol(rep: Report, host: str, port: int, timeout: float,
                   user: str = "root", password: str = "password") -> None:
    """Protocol layer check: only the SSH handshake, no login.

    This layer is the stealthiest -- it produces no auth log (though a connection record remains).
    user/password are only used for the exec channel probe, which needs one real login.
    """

    # ---- 1. Read the SSH banner ----
    banner = ""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        banner = sock.recv(512).decode("utf-8", errors="replace").strip()
        sock.close()
    except Exception as exc:
        rep.findings.append(Finding(
            id="proto.connect", name="SSH port reachable", strength=WEAK, weight=0,
            error=f"{type(exc).__name__}: {exc}",
        ))
        return

    rep.connection_ok = True
    rep.findings.append(Finding(
        id="proto.banner", name="SSH Banner", strength=WEAK, weight=0,
        evidence=banner, explanation="records the SSH version string the server declares",
    ))

    # ---- 2. Does the banner version string match the real distribution ----
    # Cowrie's banner is set by the [ssh] version config, independent of the
    # /etc/os-release content in the fake filesystem, so they easily conflict.
    # The default config is Debian 12, but the fake filesystem is Debian 11 style.
    if banner.startswith("SSH-2.0-"):
        ver = banner[len("SSH-2.0-"):]
        # real OpenSSH banners usually carry a distro suffix, e.g. "Debian-2+deb12u3"
        # Cowrie can fake that too, so alone it is not a strong signal; but a malformed format is
        if not re.match(r"^OpenSSH_[\d.p]+", ver):
            rep.findings.append(Finding(
                id="proto.banner_nonstandard",
                name="Banner version string malformed",
                strength=STRONG, weight=12, hit=True,
                evidence=ver,
                explanation="a real OpenSSH version string starts with OpenSSH_x.y",
            ))

    # ---- 3. Algorithm-set fingerprint (the hardest layer to fake) ----
    #
    # Approach: read raw TCP and parse the KEXINIT packet ourselves, not via paramiko internals.
    # Reason: paramiko 5.x clears remote_kex_init after one handshake, so the raw data is gone;
    # parsing it ourselves also avoids triggering any auth, leaving only a connection record in the log.
    #
    # SSH handshake flow:
    #   the server sends its banner first ("SSH-2.0-..." on one line)
    #   the client replies with its own banner
    #   each side sends an SSH_MSG_KEXINIT (message type 20) declaring supported algorithms
    try:
        _banner2, algos = _grab_kexinit(host, port, timeout)

        if algos:
            kex_set = set(algos.get("kex", []))
            enc_set = set(algos.get("enc_c2s", [])) | set(algos.get("enc_s2c", []))
            mac_set = set(algos.get("mac_c2s", [])) | set(algos.get("mac_s2c", []))

            # (a) Modern AEAD ciphers: enabled by default in OpenSSH 7.3+
            #     Cowrie's Twisted stack has no AEAD support at all
            aead = {"chacha20-poly1305@openssh.com",
                    "aes128-gcm@openssh.com", "aes256-gcm@openssh.com"}
            has_aead = bool(enc_set & aead)
            rep.findings.append(Finding(
                id="proto.no_aead_cipher",
                name="Offers no AEAD cipher",
                strength=STRONG, weight=16, hit=not has_aead,
                evidence=f"enc = {sorted(enc_set)}",
                explanation=(
                    "OpenSSH offers aes*-gcm since 6.5 and chacha20-poly1305 since 6.7, "
                    "enabled by default in modern versions. No AEAD algorithm at all means this is not OpenSSH's crypto stack."
                ),
            ))

            # (b) CBC-mode ciphers: no longer offered by default since OpenSSH 8.2
            legacy_enc = {"3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc",
                          "cast128-cbc", "blowfish-cbc", "arcfour"}
            enc_legacy = enc_set & legacy_enc
            rep.findings.append(Finding(
                id="proto.legacy_cbc",
                name="Offers deprecated CBC/weak ciphers",
                strength=STRONG, weight=14, hit=bool(enc_legacy),
                evidence=f"matched {sorted(enc_legacy)}",
                explanation=(
                    "OpenSSH 8.2 (2020) disabled all CBC-mode algorithms by default, "
                    "because of Padding Oracle attacks (CVE-2008-5161 etc.). "
                    "A server still advertising 3des-cbc / cast128-cbc cannot be modern OpenSSH."
                ),
            ))

            # (c) Missing ETM (Encrypt-then-MAC) MACs
            #     OpenSSH 7.2+ prefers *-etm@openssh.com by default
            has_etm = any("etm@openssh.com" in m for m in mac_set)
            rep.findings.append(Finding(
                id="proto.no_etm_mac",
                name="Offers no Encrypt-then-MAC algorithm",
                strength=STRONG, weight=14, hit=not has_etm,
                evidence=f"mac = {sorted(mac_set)}",
                explanation=(
                    "OpenSSH supports *-etm@openssh.com since 6.2 and enables it by default since 7.2. "
                    "Not a single ETM algorithm means the MAC layer is not OpenSSH's implementation either."
                ),
            ))

            # (d) Still offers hmac-md5 / hmac-sha1: OpenSSH 8.8 removed hmac-md5 from defaults
            weak_mac = {m for m in mac_set if "md5" in m}
            rep.findings.append(Finding(
                id="proto.md5_mac",
                name="Offers the removed hmac-md5",
                strength=STRONG, weight=12, hit=bool(weak_mac),
                evidence=f"matched {sorted(weak_mac)}",
                explanation=(
                    "OpenSSH 8.8 (2021) removed hmac-md5 and hmac-ripemd160 from the default set. "
                    "Still advertising an md5 MAC marks an old version or a non-OpenSSH implementation."
                ),
            ))

            # (e) host key algorithms: modern OpenSSH uses rsa-sha2-512/256, no longer bare ssh-rsa
            hostkey = set(algos.get("hostkey", []))
            only_legacy_rsa = ("ssh-rsa" in hostkey and
                               not ({"rsa-sha2-512", "rsa-sha2-256"} & hostkey))
            rep.findings.append(Finding(
                id="proto.legacy_rsa_hostkey",
                name="host key offers only legacy ssh-rsa (no rsa-sha2-*)",
                strength=WEAK, weight=8, hit=only_legacy_rsa,
                evidence=f"hostkey = {sorted(hostkey)}",
                explanation=(
                    "OpenSSH replaced bare ssh-rsa signatures with rsa-sha2-256/512 since 7.2, "
                    "and disabled ssh-rsa by default since 8.8. Advertising only ssh-rsa indicates an older implementation."
                ),
            ))
    except Exception as exc:
        rep.findings.append(Finding(
            id="proto.kex", name="SSH algorithm-set probe", strength=WEAK, weight=0,
            error=f"{type(exc).__name__}: {exc}",
        ))

    # ---- 4. Whether the exec channel is supported ----
    # Real OpenSSH supports `ssh host 'command'` (the exec channel).
    # Cowrie only implements an interactive shell; the exec channel is closed outright.
    # This is a **very strong fingerprint**, and it is testable at the protocol layer.
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        # the caller's credentials must be used here -- using the default password against a real
        # sshd fails auth, and an auth failure would be misread as "channel closed". That conclusion is unreliable.
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
            name="SSH exec channel not supported",
            strength=STRONG, weight=18, hit=not exec_ok,
            evidence=f"exec_command result: {'success' if exec_ok else 'channel closed'}",
            explanation=(
                "Every real OpenSSH supports the non-interactive `ssh host 'command'` mode. "
                "An unavailable exec channel means the server is a self-implemented minimal SSH stack, "
                "one of Cowrie's (Twisted) most typical structural features, and not fixable by configuration."
            ),
        ))
    except paramiko.AuthenticationException:
        # auth failed -> cannot verify the exec channel; record this item as "untested" rather than "clean"
        rep.findings.append(Finding(
            id="proto.no_exec_channel",
            name="SSH exec channel not supported",
            strength=STRONG, weight=18, hit=False,
            error="auth failed, cannot verify (this item excluded from the verdict)",
            explanation="the exec channel can only be tested after a successful login",
        ))
    except Exception as exc:
        rep.findings.append(Finding(
            id="proto.no_exec_channel", name="SSH exec channel not supported",
            strength=STRONG, weight=18, hit=False,
            error=f"{type(exc).__name__}: {exc} (this item excluded from the verdict)",
        ))


def _grab_kexinit(host: str, port: int, timeout: float = 8.0) -> tuple[str, dict]:
    """Read the raw TCP connection directly and extract the algorithm lists the server declares in SSH_MSG_KEXINIT.

    Why not use paramiko for this data:
      - paramiko 5.x clears remote_kex_init after the handshake, so it is unavailable;
      - parsing it ourselves also fully avoids the auth flow, leaving only a connection record in the log.

    SSH transport-layer handshake (RFC 4253 section 4.2):
      server -> client   version string "SSH-2.0-xxx\\r\\n"
      client -> server   version string
      each side sends SSH_MSG_KEXINIT

    Packet structure:
      uint32    packet_length        (excluding its own 4 bytes and the MAC)
      byte      padding_length
      byte[n]   payload
      byte[m]   padding
    The first byte of the payload is the message type; 20 means KEXINIT.

    KEXINIT payload structure:
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
    Each name-list is a uint32 length + a comma-separated ASCII string.

    Returns (banner, {algorithm category: [algorithm name, ...]})
    """
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    try:
        # ---- Read the server banner ----
        line = b""
        while not line.endswith(b"\n"):
            ch = sock.recv(1)
            if not ch:
                break
            line += ch
        banner = line.strip().decode("utf-8", errors="replace")

        # ---- Send our banner to make the server send KEXINIT ----
        sock.sendall(b"SSH-2.0-Probe_1.0\r\n")

        # ---- Read one complete SSH packet ----
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

        # ---- Parse each name-list ----
        names = ["kex", "hostkey", "enc_c2s", "enc_s2c",
                 "mac_c2s", "mac_s2c", "comp_c2s", "comp_s2c"]
        out: dict[str, list[str]] = {}
        pos = 17  # skip message type (1) + cookie (16)
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
    """Authentication layer check: see which passwords it accepts.

    This is the layer where Cowrie is most easily exposed, but also the most "by design" one --
    the honeypot deliberately accepts any password, or attackers could not get in. So this has a
    high hit rate but low fixability (fixing it makes it no longer a honeypot).
    """
    # generate a high-entropy random password that no real system could accept
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
            id="auth.rand", name="random password test", strength=WEAK, weight=0,
            error=f"{type(exc).__name__}: {exc}",
        ))

    rep.findings.append(Finding(
        id="auth.accepts_random_password",
        name="Accepts any random password",
        strength=DECISIVE, weight=30, hit=accepted_random,
        evidence=f"tried password {rand_pw!r} -> {'login succeeded' if accepted_random else 'rejected'}",
        explanation=(
            "A real system does not allow login with a meaningless random password. "
            "Accepting any password is the default behaviour of the honeypot UserDB (root is allowed except for a small blacklist). "
            "This item alone is almost conclusive."
        ),
    ))


# probe commands to run inside the honeypot -> the corresponding check
SHELL_PROBES = [
    # (command, description)
    ("id", "current user"),
    ("hostname", "hostname command output"),
    ("cat /etc/hostname", "hostname in the fake filesystem"),
    ("cat /etc/os-release", "distribution identity file"),
    ("ls -ld /etc/os-release", "type of the distribution identity file"),
    ("ls -la /", "root directory listing (timestamps and hidden files)"),
    ("ls -la /.dockerenv", "container marker file"),
    ("ls -la /proc/docker", "container marker directory"),
    ("head -3 /etc/passwd", "head with numeric shorthand"),
    ("tail -2 /etc/passwd", "tail with numeric shorthand"),
    ("df -h", "disk usage"),
    ("sed -n 1p /etc/passwd", "sed stream editor"),
    ("top -n 1", "top process viewer"),
    ("which ss ip systemctl", "whether modern system tools exist"),
    ("cat /etc/lsb-release", "Ubuntu/Debian distribution identity"),
    ("cat /etc/debian_version", "Debian version number"),
    ("ifconfig", "network interface info"),
    ("uname -a", "kernel info"),
    ("uptime", "uptime"),
    ("cat /etc/ssh/sshd_config", "SSH server configuration"),
]


def check_filesystem_and_shell(rep: Report, session: Session) -> None:
    """Filesystem layer + command behaviour layer checks.

    These two layers are done together because both rely on a shell after login.
    """
    out: dict[str, str] = {}
    for cmd, _desc in SHELL_PROBES:
        try:
            out[cmd] = session.run(cmd)
        except Exception as exc:
            out[cmd] = f"<ERROR {type(exc).__name__}: {exc}>"

    # put the full output into the report for later manual review
    rep.findings.append(Finding(
        id="shell.raw",
        name="raw output of probe commands",
        strength=WEAK, weight=0,
        evidence="\n\n".join(f"$ {c}\n{o}" for c, o in out.items()),
        explanation="raw responses of all probe commands, for manual review",
    ))

    # ---- Filesystem layer ----

    # (a) /etc/os-release is not a regular file
    # In Cowrie's fake filesystem this path may be an empty directory: cat shows nothing,
    # while ls -l shows a regular file with a size -- the two contradict each other.
    os_rel = out.get("cat /etc/os-release", "")
    os_rel_ls = out.get("ls -ld /etc/os-release", "")
    os_rel_broken = False
    if "No such file" in os_rel or "No such file" in os_rel_ls:
        os_rel_broken = False  # absence is not an anomaly (some systems genuinely lack it)
    elif not os_rel.strip() and os_rel_ls.strip():
        os_rel_broken = True
    elif os_rel_ls.startswith("d"):
        os_rel_broken = True

    rep.findings.append(Finding(
        id="fs.os_release_invalid",
        name="/etc/os-release is empty or has an abnormal type",
        strength=DECISIVE, weight=25, hit=os_rel_broken,
        evidence=f"$ cat /etc/os-release\n{os_rel or '<empty>'}\n$ ls -ld /etc/os-release\n{os_rel_ls}",
        explanation=(
            "On all modern Linux distributions /etc/os-release must be a non-empty regular file. "
            "cat showing nothing while ls shows content means this is a placeholder in the fake filesystem."
        ),
    ))

    # (b) Hostname mismatch: prompt vs hostname command vs /etc/hostname
    #
    # The three sources should be identical:
    #   1. the hostname in the prompt (shell PS1, from the kernel hostname)
    #   2. the output of the `hostname` command
    #   3. the content of /etc/hostname (written to the kernel by systemd at boot)
    # On a real system all three are driven by one value; in Cowrie they come from three independent configs.
    prompt_host = session.hostname_from_prompt
    cmd_host = out.get("hostname", "").strip().split("\n")[0].strip()
    etc_host = out.get("cat /etc/hostname", "").strip().split("\n")[0].strip()

    sources = {v for v in (prompt_host, cmd_host, etc_host) if v}
    host_mismatch = len(sources) > 1

    rep.findings.append(Finding(
        id="fs.hostname_mismatch",
        name="Hostname sources contradict each other",
        strength=STRONG, weight=15, hit=host_mismatch,
        evidence=(f"prompt={prompt_host!r}  `hostname`={cmd_host!r}  "
                  f"/etc/hostname={etc_host!r}"),
        explanation=(
            "On a real system these three are necessarily identical. "
            "Cowrie's prompt comes from the [honeypot] hostname config, "
            "the `hostname` command output is also a config value, but /etc/hostname in the fake filesystem "
            "is a third independent piece of data, and the three are out of sync."
        ),
    ))

    # (c) Container marker files exist
    dockerenv = out.get("ls -la /.dockerenv", "")
    procdocker = out.get("ls -la /proc/docker", "")
    has_docker = ("No such file" not in dockerenv and dockerenv.strip() != "") or \
                 ("No such file" not in procdocker and procdocker.strip() != "")

    rep.findings.append(Finding(
        id="fs.container_markers",
        name="Container markers present (/.dockerenv or /proc/docker)",
        strength=STRONG, weight=15, hit=has_docker,
        evidence=f"$ ls -la /.dockerenv\n{dockerenv}\n$ ls -la /proc/docker\n{procdocker}",
        explanation=(
            "These two paths exist only inside a Docker container. "
            "Cowrie's bundled fs.pickle was snapshotted from a real Docker container, "
            "so it carried these container traces into the 'physical server' disguise."
        ),
    ))

    # (d) Root directory timestamps highly uniform
    #
    # On a real system, the mtime of each directory under / depends on when it was last modified,
    # spread over several years. Cowrie's fake filesystem was generated from one container snapshot,
    # so many entries share the single timestamp of the snapshot moment.
    #
    # Criterion: count all timestamps in ls -la /; if the deduplicated count is at most 2
    # while the total is >= 10, almost all come from the same moment.
    ls_root = out.get("ls -la /", "")
    stamps = re.findall(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}", ls_root)
    # a real system usually has a uniqueness ratio above 0.8 (almost every entry differs).
    # use 0.3 as the threshold: many repeated timestamps are considered suspicious.
    ratio = (len(set(stamps)) / len(stamps)) if stamps else 1.0
    stamp_dup = len(stamps) >= 10 and ratio <= 0.30

    rep.findings.append(Finding(
        id="fs.uniform_timestamps",
        name="Root directory timestamps highly repetitive",
        strength=WEAK, weight=10, hit=stamp_dup,
        evidence=(f"{len(stamps)} entries, {len(set(stamps))} after dedup"
                  f" (uniqueness {ratio:.0%}): {sorted(set(stamps))[:6]}"),
        explanation=(
            "On a real system the mtimes of directories under / span different years, with a uniqueness ratio near 1. "
            "The fake filesystem was generated from one snapshot, so many entries share a few mtimes."
        ),
    ))

    # (e) sshd_config is empty
    sshd = out.get("cat /etc/ssh/sshd_config", "")
    sshd_empty = ("No such file" not in sshd) and (sshd.strip() == "") and \
                 ("cat /etc/ssh/sshd_config" in out)

    rep.findings.append(Finding(
        id="fs.sshd_config_empty",
        name="/etc/ssh/sshd_config is empty",
        strength=STRONG, weight=12, hit=sshd_empty,
        evidence=sshd or "<empty>",
        explanation=(
            "A real system running an SSH service necessarily has a non-empty sshd_config. "
            "The file existing but empty means the fake filesystem created the path without content."
        ),
    ))

    # ---- Command behaviour layer ----

    # (f) head -3 / tail -2 reject numeric shorthand
    # POSIX allows `head -3 file`, and GNU coreutils supports it too.
    # Cowrie's emulator only understands `head -n 3`.
    head_out = out.get("head -3 /etc/passwd", "")
    head_broken = "invalid option" in head_out or "invalid number" in head_out

    rep.findings.append(Finding(
        id="cmd.head_numeric_shorthand",
        name="head -3 does not support numeric shorthand",
        strength=STRONG, weight=18, hit=head_broken,
        evidence=head_out or "<no output>",
        explanation=(
            "`head -3 file` is supported by both POSIX and GNU coreutils; "
            "a real Linux never reports invalid option. Only a self-implemented simplified parser does."
        ),
    ))

    tail_out = out.get("tail -2 /etc/passwd", "")
    tail_broken = "invalid option" in tail_out or "invalid number" in tail_out
    rep.findings.append(Finding(
        id="cmd.tail_numeric_shorthand",
        name="tail -2 does not support numeric shorthand",
        strength=STRONG, weight=12, hit=tail_broken,
        evidence=tail_out or "<no output>",
        explanation="same as head, a symptom of the same simplified parser",
    ))

    # (g) df / sed report "cannot execute binary file"
    # For unimplemented commands Cowrie returns a "generic binary" content, causing a format error at the kernel level.
    # On a real system df and sed are standard basic commands and cannot be missing.
    df_out = out.get("df -h", "")
    df_broken = "cannot execute binary file" in df_out or "Exec format error" in df_out

    rep.findings.append(Finding(
        id="cmd.df_broken_binary",
        name="df cannot execute (binary format error)",
        strength=DECISIVE, weight=20, hit=df_broken,
        evidence=df_out or "<no output>",
        explanation=(
            "df is part of coreutils, an essential command on every Linux distribution. "
            "Reporting 'Exec format error' means this is a fake binary returned as an executable, "
            "showing the command was never actually run."
        ),
    ))

    sed_out = out.get("sed -n 1p /etc/passwd", "")
    sed_broken = "cannot execute binary file" in sed_out or "Exec format error" in sed_out
    rep.findings.append(Finding(
        id="cmd.sed_broken_binary",
        name="sed cannot execute (binary format error)",
        strength=DECISIVE, weight=15, hit=sed_broken,
        evidence=sed_out or "<no output>",
        explanation="same as df. sed is an essential POSIX tool; a real system cannot fail to run it.",
    ))

    # (h) top crashes
    top_out = out.get("top -n 1", "")
    top_broken = "Cannot allocate" in top_out or "E82" in top_out or \
                 "top:" in top_out and "invalid" in top_out

    rep.findings.append(Finding(
        id="cmd.top_crash",
        name="top behaves abnormally",
        strength=STRONG, weight=12, hit=top_broken,
        evidence=top_out or "<no output>",
        explanation=(
            "In Cowrie top is emulated by reading preset /proc data; "
            "a real argument combination reaches an unhandled code path and errors out."
        ),
    ))

    # (i) ss / ip / systemctl do not exist
    which_out = out.get("which ss ip systemctl", "")
    missing_modern = 0
    for tool in ("ss", "ip", "systemctl"):
        # which prints nothing for a command that does not exist
        if tool not in which_out:
            missing_modern += 1

    rep.findings.append(Finding(
        id="cmd.missing_modern_tools",
        name="Missing modern system tools (ss/ip/systemctl)",
        strength=STRONG, weight=15, hit=missing_modern >= 2,
        evidence=f"$ which ss ip systemctl\n{which_out or '<no output>'}\nmissing count: {missing_modern}/3",
        explanation=(
            "iproute2 (ip, ss) has been the default network tooling on mainstream distributions since 2001, "
            "and systemd the default init on Ubuntu/Debian since 2015. "
            "Their absence severely contradicts the Debian 12 the banner claims."
        ),
    ))

    # (j) ifconfig interface name does not match a real environment
    ifc_out = out.get("ifconfig", "")
    # Cowrie outputs eth0 by default; modern systems use predictable names (enp0s3, ens33, etc.)
    ifc_eth0 = bool(re.search(r"^eth\d", ifc_out, re.MULTILINE))

    rep.findings.append(Finding(
        id="cmd.legacy_nic_name",
        name="Interface uses the old eth0 naming",
        strength=WEAK, weight=8, hit=ifc_eth0,
        evidence=ifc_out[:300] if ifc_out else "<no output>",
        explanation=(
            "systemd's net.ifnames has enabled predictable interface names by default since 2015 "
            "(enp0s3, ens33, etc.); modern Debian/Ubuntu no longer use eth0. "
            "Cowrie's ifconfig emulated output is a hard-coded eth0."
        ),
    ))

    # (k) Kernel identity inconsistent with the distribution
    #
    # Two independent data sources:
    #   - uname's build string comes from the [shell] kernel_build_string config
    #   - distribution identity comes from /etc/os-release in the fake filesystem
    # If Ubuntu-specific traces exist under / (e.g. /etc/lsb-release, snap directory)
    # while uname says Debian, that is a contradiction.
    uname_out = out.get("uname -a", "")
    ls_root_scan = out.get("ls -la /", "")
    ubuntu_markers = any(m in ls_root_scan for m in ("snap", ".dockerenv"))
    uname_debian = "debian" in uname_out.lower()
    lsb_out = out.get("cat /etc/lsb-release", "")
    # lsb-release exists only on Ubuntu/Debian; if unreadable it counts as missing and is not used as evidence
    kernel_mismatch = bool(uname_out) and uname_debian and bool(ubuntu_markers)

    rep.findings.append(Finding(
        id="cmd.kernel_distro_mismatch",
        name="Kernel identity inconsistent with the distribution implied by the directory structure",
        strength=WEAK, weight=8, hit=kernel_mismatch,
        evidence=f"$ uname -a\n{uname_out}",
        explanation=(
            "uname's build string comes from the [shell] kernel_build_string config, "
            "while the directory structure comes from the fake filesystem snapshot; being independent, they easily conflict."
        ),
    ))

    # (l) uptime too short
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
        name="System uptime abnormally short",
        strength=WEAK, weight=10, hit=uptime_short,
        evidence=up_out or "<no output>",
        explanation=(
            "Cowrie's uptime counts from process start, not system boot, "
            "so every honeypot restart shows as just booted. A production server rarely reboots within an hour."
        ),
    ))

    # (m) Abnormal terminal control sequences
    # These are already stripped from the output here; the judgement uses the raw data recorded by Session.
    # See check_terminal_quirks.
    _ = out


def check_terminal_quirks(rep: Report, host: str, port: int, user: str,
                          password: str, timeout: float) -> None:
    """Session layer check: terminal control sequences and shell behaviour.

    Opens a dedicated session just to observe the raw byte stream.
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

        # Cowrie inserts ESC[4l / ESC[4h (disable/enable underline) around every output.
        # A real shell does not send these two sequences on its own.
        has_underline = "\x1b[4l" in raw_text or "\x1b[4h" in raw_text

        rep.findings.append(Finding(
            id="term.underline_escape",
            name="Abnormal terminal underline control sequences in output",
            strength=STRONG, weight=15, hit=has_underline,
            evidence=repr(raw_text[:400]),
            explanation=(
                "Cowrie inserts \\x1b[4l / \\x1b[4h (disable/enable underline) around every command output. "
                "A real bash does not send these two sequences on its own."
            ),
        ))

        # A real bash sends bracketed-paste mode (ESC[?2004h/l) and OSC title settings,
        # Cowrie does not. The absence itself is a weak signal (the user may have changed PS1 / disabled these features).
        has_bracketed_paste = "\x1b[?2004" in raw_text
        rep.findings.append(Finding(
            id="term.no_bracketed_paste",
            name="Missing bracketed paste mode sequences",
            strength=WEAK, weight=6, hit=not has_bracketed_paste,
            evidence="did not observe \\x1b[?2004h/l",
            explanation=(
                "Modern bash (5.0+) enables bracketed paste and OSC 3008 session marking by default. "
                "The absence may be user customisation, so it counts only as a weak signal."
            ),
        ))

    except Exception as exc:
        rep.findings.append(Finding(
            id="term.probe", name="terminal behaviour probe", strength=WEAK, weight=0,
            error=f"{type(exc).__name__}: {exc}",
        ))


# ============================================================================
# 4. Scoring and verdict
# ============================================================================

def compute_score(rep: Report) -> None:
    """Compute the exposure index from the hits.

    Rules:
      - any DECISIVE hit -> raise to >= 70, guaranteeing a honeypot verdict
      - otherwise sum the weights, capped at 100
      - with DECISIVE hits >= 1, the minimum score is 70
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

    # with only a single distinct "strong" hit, do not judge too heavily -- avoid false positives
    if decisive_hits == 0 and strong_hits == 1 and weak_hits <= 1:
        total = min(total, 25)

    if decisive_hits >= 1:
        total = max(total, 70)

    # record the uncapped raw score: during modification the score hits the ceiling of 100,
    # while raw_score keeps reflecting the elimination of each individual check.
    rep.raw_score = total
    rep.score = max(0, min(100, total))

    # per-layer subtotals, to locate "which layer is hardest to fix"
    layers = {"proto": "protocol", "auth": "auth", "fs": "filesystem",
              "cmd": "command behaviour", "term": "terminal behaviour"}
    rep.by_layer = {}
    for prefix, label in layers.items():
        rep.by_layer[label] = sum(f.weight for f in rep.findings
                                  if f.hit and f.id.startswith(prefix))

    if rep.score >= 60:
        rep.verdict = "Definitely a honeypot (Cowrie or a derivative)"
    elif rep.score >= 30:
        rep.verdict = "Highly suspicious: likely a honeypot"
    elif rep.score >= 10:
        rep.verdict = "Anomalies present, manual review recommended"
    else:
        rep.verdict = "No obvious honeypot features found"


# ============================================================================
# 5. Output
# ============================================================================

# ANSI colours (for terminal output)
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
    """Print the detection results as a human-readable report."""
    def c(code: str, text: str) -> str:
        return f"{code}{text}{C.RESET}" if color else text

    print()
    print(c(C.BOLD, "=" * 78))
    print(c(C.BOLD, "  Cowrie SSH Honeypot Detection Report"))
    print(c(C.BOLD, "=" * 78))
    print(f"  Target        : {rep.target}")
    print(f"  Time          : {rep.timestamp}")
    print(f"  Connection    : {'ok' if rep.connection_ok else c(C.RED, 'failed')}")
    print(f"  Login         : {'ok' if rep.login_ok else c(C.RED, 'failed')}")
    print()

    # display grouped by strength
    order = [(DECISIVE, "Decisive evidence"), (STRONG, "Strong signals"), (WEAK, "Weak signals")]
    for strength, title in order:
        items = [f for f in rep.findings
                 if f.strength == strength and f.id != "shell.raw"]
        if not items:
            continue
        hits = [f for f in items if f.hit]
        header = f"{title}  (hits {len(hits)}/{len(items)})"
        print(c(C.BOLD, f"── {header} " + "─" * max(0, 70 - len(header))))
        for f in items:
            if f.hit:
                mark = c(C.RED, "[HIT]")
            elif f.error:
                mark = c(C.YELLOW, "[ERR]")
            else:
                mark = c(C.GREEN, "[OK ]")
            print(f"  {mark} {f.name}  {c(C.DIM, f'(+{f.weight})' if f.hit else '')}")
            if f.error:
                print(c(C.DIM, f"         {f.error}"))
            if show_evidence and f.evidence:
                ev = f.evidence.replace("\n", "\n         ")
                print(c(C.DIM, f"         evidence: {ev[:800]}"))
            if show_evidence and f.explanation:
                print(c(C.DIM, f"         note: {f.explanation}"))
        print()

    # verdict
    print(c(C.BOLD, "=" * 78))
    bar_len = rep.score // 2
    bar_color = C.RED if rep.score >= 60 else (C.YELLOW if rep.score >= 30 else C.GREEN)
    print(f"  Exposure index: {c(bar_color + C.BOLD, f'{rep.score}/100')}  "
          f"{c(bar_color, '#' * bar_len + '.' * (50 - bar_len))}")
    if rep.raw_score != rep.score:
        print(c(C.DIM, f"  Raw weight sum: {rep.raw_score} (exceeds the cap, index is capped)"))
    if rep.by_layer:
        parts = [f"{k} {v}" for k, v in rep.by_layer.items() if v]
        print(c(C.DIM, "  Layer subtotals: " + "  ".join(parts)))
    print(f"  Verdict       : {c(bar_color + C.BOLD, rep.verdict)}")
    print(c(C.BOLD, "=" * 78))
    print()


def build_json(rep: Report, include_evidence: bool) -> dict:
    """Build the JSON structure."""
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
# 6. Main flow
# ============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Cowrie SSH honeypot detector (passive detection only, no exploitation logic)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s --host 192.168.122.252 --port 2222\n"
            "  %(prog)s --host 192.168.122.252 --port 2222 --json\n"
            "  %(prog)s --host 192.168.122.252 --port 2222 --passive\n"
        ),
    )
    parser.add_argument("--host", required=True, help="target IP or hostname")
    parser.add_argument("--port", type=int, default=2222, help="SSH port, default 2222")
    parser.add_argument("--user", default="root", help="login username, default root")
    parser.add_argument("--password", default="password", help="login password, default password")
    parser.add_argument("--timeout", type=float, default=15.0, help="connection timeout in seconds, default 15")
    parser.add_argument("--json", action="store_true", help="output as JSON")
    parser.add_argument("--evidence", metavar="FILE", help="write full evidence to the given JSON file")
    parser.add_argument("--passive", action="store_true",
                        help="protocol and auth layers only, no shell (stealthier)")
    parser.add_argument("--no-color", action="store_true", help="disable coloured output")
    parser.add_argument("--verbose", action="store_true", help="include evidence in terminal output")

    args = parser.parse_args()

    rep = Report(
        target=f"{args.host}:{args.port}",
        timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
    )

    # ---- Layer 1: protocol ----
    check_protocol(rep, args.host, args.port, args.timeout,
                   user=args.user, password=args.password)

    # ---- Layer 2: authentication ----
    if rep.connection_ok:
        check_authentication(rep, args.host, args.port, args.timeout)

    # ---- Layers 3 & 4: filesystem and command behaviour ----
    if not args.passive and rep.connection_ok:
        session = Session(args.host, args.port, args.user, args.password, args.timeout)
        try:
            session.connect()
            rep.login_ok = True
            check_filesystem_and_shell(rep, session)
        except Exception as exc:
            rep.findings.append(Finding(
                id="shell.connect", name="establish interactive session", strength=WEAK, weight=0,
                error=f"{type(exc).__name__}: {exc}",
            ))
        finally:
            session.close()

        # ---- Layer 5: terminal behaviour ----
        if rep.login_ok:
            check_terminal_quirks(rep, args.host, args.port, args.user,
                                  args.password, args.timeout)

    # ---- Scoring ----
    compute_score(rep)

    # ---- Output ----
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
                print(f"Full evidence written to: {args.evidence}")
        except OSError as exc:
            sys.stderr.write(f"Failed to write evidence file: {exc}\n")

    return 0 if rep.score >= 60 else 1


if __name__ == "__main__":
    sys.exit(main())
