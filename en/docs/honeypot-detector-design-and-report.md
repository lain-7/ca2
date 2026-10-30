# Cowrie honeypot detector: design, implementation and detection results

> Companion script: `tools/honeypot_detect.py`
> Document version: 2026-10-26
> Context: ITSD010 CA2 group assignment -- honeypot deployment and security analysis

---

## Contents

1. [What this document addresses](#1-what-this-document-addresses)
2. [Detection principle: why a honeypot can be identified](#2-detection-principle-why-a-honeypot-can-be-identified)
3. [Five-layer detection model](#3-five-layer-detection-model)
4. [Scoring model](#4-scoring-model)
5. [Usage](#5-usage)
6. [Detection results](#6-detection-results)
7. [Detailed explanation of each check](#7-detailed-explanation-of-each-check)
8. [Defender view: how to minimise the index](#8-defender-view-how-to-minimise-the-index)
9. [Threat analysis chain: the full assessment record](#9-threat-analysis-chain-the-full-assessment-record)
10. [Limitations and known errors](#10-limitations-and-known-errors)
11. [Appendix: empirical comparison tables](#11-appendix-empirical-comparison-tables)

---

## 1. What this document addresses

### 1.1 Background

This group's assignment requires deploying a Cowrie SSH honeypot on an Ubuntu VM, simulating attacks and analysing logs. During deployment, a natural question arose:

> **Can an attacker tell this is a honeypot?**

This question matters in real security operations. A honeypot's value depends on whether the attacker believes it is a real server. Once seen through, the attacker will:

- stop immediately, leaving no valuable TTP information;
- use the honeypot in reverse, feeding the defender false intelligence;
- or even use the honeypot as a stepping stone to attack the defender (though this does not hold for Cowrie, see chapter 9).

So **quantifying "how easily this honeypot can be seen through" is a required lesson in honeypot deployment**.

### 1.2 What this project did

This project implements `honeypot_detect.py`, an active honeypot detector. It works as follows:

1. connects to the target like an ordinary SSH client;
2. runs a series of probes at the protocol, auth, filesystem, command-behaviour and terminal-behaviour layers;
3. collects the observations and compares them with "how a real Linux system should behave";
4. outputs a 0-100 **exposure index** and a verdict.

It **does passive probing only**: all operations are read-only (`ls`, `cat`, `head`, `uname`, etc.), modify no target state, and contain no exploitation, upload, privilege escalation, persistence or lateral movement logic.

### 1.3 Why not simply write "Cowrie detected"

Because **identifying Cowrie itself has no engineering value**. Cowrie's install path, process name and port can all be changed. What is valuable is identifying the **structural contradiction** "this system is not what it claims to be".

All checks in this script are based on "the gap between emulation and reality", not on "some known string of Cowrie". So:

- it can identify a renamed Cowrie;
- it can identify some features of other medium-interaction honeypots (Kippo, Heralding, etc.);
- every check can explain "why this cannot appear on a real system".

---

## 2. Detection principle: why a honeypot can be identified

### 2.1 Two implementation paths of a honeypot, two kinds of tells

**High-interaction honeypots** (such as some T-Pot components) run a real system, where everything the attacker does is real. The tells of such honeypots are mainly in **network position** and **business logic** (a "production database" with no business traffic), not inside the system.

**Medium-interaction honeypots** (Cowrie is one) do not run a real system but **emulate** Linux behaviour with code:

- fake filesystem: a pickle-serialised file tree replaces a real disk
- fake shell: Python modules implement `ls`, `cat`, `wget`, etc. one by one
- fake auth: a rule table decides which passwords "log in successfully"

**Emulation necessarily differs, and the difference is a fingerprint.** This is the common source of all checks in this project.

### 2.2 Four layers of difference

| Layer | Source of difference | Fixability |
|---|---|---|
| Protocol | the SSH implementation is not OpenSSH, so the algorithm set and capability set differ | **very hard** -- requires replacing the whole SSH stack |
| Authentication | by design: it must accept any password, or the attacker cannot get in | **unfixable** -- fixing it means it is no longer a honeypot |
| Filesystem | the fake filesystem is generated from a snapshot, so its internal data is self-contradictory | **easy** -- just regenerate fs.pickle |
| Command behaviour | a simplified parser cannot cover all the syntax of real commands | **medium** -- requires completing command implementations one by one |

This table directly determines the feasibility boundary of chapter 8 "how to minimise the index".

---

## 3. Five-layer detection model

### 3.1 Protocol layer: things visible without logging in

**Core idea**: during the SSH handshake, both sides exchange their "capability lists" (`SSH_MSG_KEXINIT`). The algorithm set a real OpenSSH offers has clear era characteristics, while Cowrie uses Twisted's SSH implementation underneath, with an algorithm set stuck many years ago.

This project reads the raw TCP packet directly and parses `SSH_MSG_KEXINIT` itself, relying on no library internals. This has two benefits:

1. it fully avoids the auth flow, leaving only a connection record in the log;
2. it is not affected by paramiko version differences (paramiko 5.x clears `remote_kex_init` after the handshake).

**Checks**:

| Check | Basis | OpenSSH version of the basis |
|---|---|---|
| Offers no AEAD cipher | OpenSSH 6.5+ offers AES-GCM, 6.7+ offers chacha20-poly1305 | since 2014 |
| Offers deprecated CBC ciphers | OpenSSH 8.2 disabled all CBC by default | since 2020 |
| No Encrypt-then-MAC | OpenSSH 6.2+ supports it, 7.2+ enables it by default | since 2016 |
| Offers the removed hmac-md5 | OpenSSH 8.8 removed it from the default set | since 2021 |
| host key offers only legacy ssh-rsa | OpenSSH 7.2+ uses rsa-sha2-*, 8.8 disabled bare ssh-rsa | since 2021 |
| No exec channel support | all OpenSSH supports `ssh host 'command'` | -- |

### 3.2 Authentication layer: which passwords it accepts

**Core idea**: a real system does not accept a meaningless random password. Cowrie's `UserDB` default rule is "root is allowed except for a small blacklist", so a 24-character high-entropy random password logging in successfully is almost conclusive on its own.

The special thing about this item is: **it is unfixable**. A honeypot's essence is to let attackers in, so it must accept guessed passwords. Changed to accept only the correct password, attackers cannot get in and the honeypot stops working.

### 3.3 Filesystem layer: internal contradictions of the fake filesystem

**Core idea**: Cowrie's `fs.pickle` is a snapshot taken with `bin/createfs` from some real system (actually a Docker container). The snapshot stores only metadata and a little file content, and is **never updated** afterwards. This causes three kinds of contradiction:

1. **Data sources out of sync**: the prompt hostname comes from the `[honeypot] hostname` config, `/etc/hostname` comes from the pickle, and the two are independent
2. **Missing content**: files with a path but no content (e.g. empty `sshd_config`)
3. **Snapshot traces**: many entries share the same mtime; container marker files are captured along with it

**Checks**:

| Check | Principle |
|---|---|
| `/etc/os-release` empty or abnormal type | all modern distributions require it to be a non-empty regular file |
| Three hostname sources contradict | prompt / `hostname` command / `/etc/hostname` should be identical |
| Container markers present | `/.dockerenv`, `/proc/docker` exist only inside a Docker container |
| `/etc/ssh/sshd_config` empty | a system running an SSH service must have a non-empty config |
| Timestamps highly uniform | a real system's mtimes span years, with a uniqueness ratio near 100% |

### 3.4 Command-behaviour layer: traces of a simplified parser

**Core idea**: Cowrie implements Unix commands one by one with Python modules. Each implementation covers only common usage, and reveals itself on syntax a real command supports but the emulator does not.

**Checks**:

| Check | Principle |
|---|---|
| `head -3` / `tail -2` report invalid option | both POSIX and GNU coreutils support numeric shorthand |
| `df` / `sed` report Exec format error | essential coreutils and POSIX commands cannot fail to run |
| `top` reports E82 | the emulator reaches an unhandled path |
| Missing `ss` / `ip` / `systemctl` | iproute2 since 2001, systemd since 2015 have been default components |
| `ifconfig` shows eth0 | net.ifnames switched to predictable interface names since 2015 |
| `uptime` abnormally short | Cowrie's uptime counts from process start, not system boot |

### 3.5 Terminal-behaviour layer: shell output characteristics

**Core idea**: a real bash sends a series of terminal control sequences (bracketed paste, OSC title settings, session marking). Cowrie's fake shell sends only the most basic prompt, and additionally inserts its own escape sequences.

**Checks**:

| Check | Principle |
|---|---|
| `ESC[4l` / `ESC[4h` present | Cowrie inserts an underline toggle around every output; real bash does not |
| Missing bracketed paste sequences | modern bash (5.0+) enables `ESC[?2004h` by default |

---

## 4. Scoring model

### 4.1 Three evidence-strength levels

Each check has a strength label and a weight:

| Strength | Meaning | Rule |
|---|---|---|
| **DECISIVE** | a feature impossible on a real system | a single hit concludes |
| **STRONG** | extremely unlikely on a real system | two or more hits conclude |
| **WEAK** | alone it may just be a configuration difference | needs several hits together |

### 4.2 Scoring rules

```
exposure index = Σ(weights of hits)
```

with three adjustments:

1. **Decisive floor**: if any decisive item hits, the index is at least 70 (guaranteeing a honeypot verdict)
2. **False-positive guard**: with no decisive hit and only 1 strong signal + at most 1 weak signal, the index is capped at 25
3. **Ceiling**: 100

### 4.3 Verdict bands

| Index | Verdict | Meaning |
|---|---|---|
| >= 60 | Definitely a honeypot | structural contradiction found, cannot be a real system |
| 30-59 | Highly suspicious | multiple anomalies, very likely an emulated environment |
| 10-29 | Anomalies present | manual review recommended |
| < 10 | No obvious features found | well disguised, or genuinely real |

**Note**: the index is not "vulnerability severity" but "ease of being seen through". A higher index means the attacker more easily sees it is a honeypot.

---

## 5. Usage

### 5.1 Requirements

```bash
# only paramiko is needed; everything else is the Python standard library
pip install paramiko

# Python 3.9+
```

### 5.2 Basic usage

```bash
# full detection (recommended)
python3 honeypot_detect.py --host 192.168.122.252 --port 2222

# conclusion only, no evidence
python3 honeypot_detect.py --host 192.168.122.252 --port 2222

# with evidence output (see each check's actual observed value in the terminal)
python3 honeypot_detect.py --host 192.168.122.252 --port 2222 --verbose

# JSON output (for scripting and before/after comparison)
python3 honeypot_detect.py --host 192.168.122.252 --port 2222 --json

# protocol + auth layers only, no shell (the stealthiest probe)
python3 honeypot_detect.py --host 192.168.122.252 --port 2222 --passive

# export full evidence to a file
python3 honeypot_detect.py --host 192.168.122.252 --port 2222 --evidence evidence.json

# specify credentials
python3 honeypot_detect.py --host X --port 22 --user ubuntucowrie --password 'yourpass'
```

### 5.3 Argument reference

| Argument | Default | Description |
|---|---|---|
| `--host` | required | target IP or hostname |
| `--port` | 2222 | SSH port |
| `--user` | root | login username |
| `--password` | password | login password |
| `--timeout` | 15.0 | connection timeout in seconds |
| `--json` | off | output as JSON |
| `--evidence FILE` | none | write full evidence to the given file |
| `--passive` | off | protocol and auth layers only, no shell |
| `--no-color` | off | disable coloured output |
| `--verbose` | off | include evidence and notes in terminal output |

### 5.4 Exit codes

| Exit code | Meaning |
|---|---|
| 0 | identified as a honeypot (index >= 60) |
| 1 | not identified (index < 60) |
| 2 | connection failure or argument error |

Handy in CI or batch scripts:

```bash
if python3 honeypot_detect.py --host $H --port $P --json > /dev/null; then
    echo "honeypot detected"
fi
```

### 5.5 Moving from the host to VM B

The script depends on no particular environment; copy it over and run:

```bash
scp honeypot_detect.py ubuntuclient@<vm-b-ip>:~/
ssh ubuntuclient@<vm-b-ip> 'sudo apt install -y python3-paramiko && python3 ~/honeypot_detect.py --host <honeypot IP> --port 2222'
```

---

## 6. Detection results

### 6.1 Control-group design

To verify the detector **does not raise false positives**, this project tested two targets simultaneously:

| Target | Description |
|---|---|
| `192.168.122.252:2222` | Cowrie honeypot (the object under test) |
| `192.168.122.252:22` | the real OpenSSH on the same VM (control group) |

**Why this control group is especially valuable**: both are the **same IP, same physical machine, same subnet**. The only variable is "whether the server is Cowrie or OpenSSH". If the detector judged merely by external factors like "suspicious IP" or "non-standard port", the two results would be identical; if it really analyses system behaviour, the two are completely different.

### 6.2 Results comparison

| Metric | Cowrie :2222 | real sshd :22 |
|---|---|---|
| **Exposure index** | **100 / 100** | **10 / 100** |
| Verdict | Definitely a honeypot | Anomalies present, manual review recommended |
| Decisive hits | 4 / 4 | 0 / 4 |
| Strong hits | 13 / 13 | 0 / 12 |
| Weak hits | 6 / 7 | 1 / 8 |

**Conclusion**: the detector clearly distinguishes the two, with almost no false positives on the real system.

### 6.3 What are the 10 points on the real sshd

The only hit on the real sshd is "system uptime abnormally short" (+10). This is a **real observation**: the VM started around 10:08 and the test ran at 10:31, so `uptime` showed 23 minutes.

This is not a false positive but a **correct identification of a suspicious state**. A just-booted server is indeed suspicious, only this signal alone is insufficient to conclude -- which is exactly why it is classed as a "weak signal" (weight 10) rather than a "strong signal".

### 6.4 Full output example (Cowrie)

```
── Decisive evidence  (hits 4/4) ────────────────────────────────────
  [HIT] Accepts any random password  (+30)
  [HIT] /etc/os-release is empty or has an abnormal type  (+25)
  [HIT] df cannot execute (binary format error)  (+20)
  [HIT] sed cannot execute (binary format error)  (+15)

── Strong signals  (hits 13/13) ─────────────────────────────────────
  [HIT] Offers no AEAD cipher  (+16)
  [HIT] Offers deprecated CBC/weak ciphers  (+14)
  [HIT] Offers no Encrypt-then-MAC algorithm  (+14)
  [HIT] Offers the removed hmac-md5  (+12)
  [HIT] SSH exec channel not supported  (+18)
  [HIT] Hostname sources contradict each other  (+15)
  [HIT] Container markers present (/.dockerenv or /proc/docker)  (+15)
  [HIT] /etc/ssh/sshd_config is empty  (+12)
  [HIT] head -3 does not support numeric shorthand  (+18)
  [HIT] tail -2 does not support numeric shorthand  (+12)
  [HIT] top behaves abnormally  (+12)
  [HIT] Missing modern system tools (ss/ip/systemctl)  (+15)
  [HIT] Abnormal terminal underline control sequences in output  (+15)

── Weak signals  (hits 6/7) ───────────────────────────────────────
  [OK ] SSH Banner
  [HIT] host key offers only legacy ssh-rsa (no rsa-sha2-*)  (+8)
  [HIT] Root directory timestamps highly repetitive  (+10)
  [HIT] Interface uses the old eth0 naming  (+8)
  [HIT] Kernel identity inconsistent with the distribution implied by the directory structure  (+8)
  [HIT] System uptime abnormally short  (+10)
  [HIT] Missing bracketed paste mode sequences  (+6)

Exposure index: 100/100
Verdict: Definitely a honeypot (Cowrie or a derivative)
```

---

## 7. Detailed explanation of each check

### 7.1 Decisive items

#### `auth.accepts_random_password` (+30)

**Method**: log in as `root` with a 24-character high-entropy random password.

```python
rand_pw = "".join(random.choices(string.ascii_letters + string.digits + "!@#$%^&*", k=24))
```

**Result**:

```
Cowrie  : ACCEPTED  root / 'Zq9$xK!mP2vR'
real sshd: REJECTED  -> AuthenticationException
```

**Principle**: Cowrie's `core/auth.py` defines built-in rules:

```python
_USERDB_DEFAULTS = [
    "root:x:!root",       # reject password root
    "root:x:!123456",     # reject password 123456
    "root:x:!/honeypot/i",# reject passwords containing honeypot
    "root:x:*",           # allow everything else
    "phil:x:*",
    "phil:x:fout",
]
```

`root:x:*` means root is **allowed except for the three blacklist entries**. So any random password logs in.

**Why decisive**: a real system cannot accept a meaningless random password. This item alone concludes.

**Fixability**: **unfixable**. It is the honeypot's design premise.

---

#### `fs.os_release_invalid` (+25)

**Method**:

```bash
cat /etc/os-release       # returns empty
ls -ld /etc/os-release    # returns -rw-r--r-- ... 267 ... /etc/os-release
```

**The contradiction**: `ls` says this is a 267-byte regular file, yet `cat` reads no content.

**Principle**: the data structure for this path in Cowrie's `fs.pickle` is wrong. Dumping it with `dumpfs` shows its type flag is `T_DIR` (directory), but `ls.py` renders it as a regular file and shows a size value inherited from elsewhere.

**Why decisive**: `/etc/os-release` is a mandatory requirement of the systemd specification; all modern distributions must provide non-empty content. This contradiction cannot occur on a real system.

**Fixability**: **easy**. Fill the content correctly when regenerating fs.pickle.

---

#### `cmd.df_broken_binary` (+20) / `cmd.sed_broken_binary` (+15)

**Method**:

```bash
df -h
sed -n 1p /etc/passwd
```

**Result**:

```
-bash: /usr/bin/df: cannot execute binary file: Exec format error
-bash: /usr/bin/sed: cannot execute binary file: Exec format error
```

**Principle**: for **unimplemented** commands (those with no corresponding Python module in `commands/`), Cowrie returns a "generic binary" content. When the attacker actually executes it, the kernel (at the emulation layer) decides it is not a valid executable and reports `Exec format error`.

**Why decisive**: `df` is part of coreutils, `sed` is an essential POSIX tool. No Linux distribution can lack them, let alone "exist but fail to execute".

**Fixability**: **medium**. Requires adding real Python implementations for these commands.

---

### 7.2 Strong signals

#### `proto.no_exec_channel` (+18)

**Method**: try `ssh host 'true'` (the SSH exec channel).

**Result**:

```
Cowrie  : paramiko.ssh_exception.SSHException: Channel closed.
real sshd: exec_command succeeds, rc=0
```

**Principle**: the SSH protocol has two channel types:

- `session` + `shell` request -> interactive terminal (`ssh host`)
- `session` + `exec` request -> run a single command (`ssh host 'command'`)

Cowrie implements only the former. This is a structural limitation of the Twisted SSH implementation.

**Why it matters**: this is a **structural defect of the protocol layer**, not a configuration issue. Fixing it requires replacing the whole SSH stack.

**Fixability**: **very hard**.

---

#### `proto.no_aead_cipher` (+16) / `proto.legacy_cbc` (+14) / `proto.no_etm_mac` (+14) / `proto.md5_mac` (+12)

**Method**: read raw TCP and parse the server's `SSH_MSG_KEXINIT` packet.

**Measured comparison**:

```
Cowrie :2222
  enc = aes128-ctr, aes192-ctr, aes256-ctr, aes256-cbc, aes192-cbc,
        aes128-cbc, 3des-cbc, cast128-cbc
  mac = hmac-sha2-512, hmac-sha2-384, hmac-sha2-256, hmac-sha1, hmac-md5

real sshd :22
  enc = chacha20-poly1305@openssh.com, aes128-gcm@openssh.com,
        aes256-gcm@openssh.com, aes128-ctr, aes192-ctr, aes256-ctr
  mac = umac-64-etm@openssh.com, umac-128-etm@openssh.com,
        hmac-sha2-256-etm@openssh.com, hmac-sha2-512-etm@openssh.com, ...
```

**Four differences**:

| Feature | Cowrie | OpenSSH | Boundary |
|---|---|---|---|
| AEAD cipher | none | has GCM / chacha20 | 2014 |
| CBC cipher | offers | disabled by default | 2020 |
| ETM MAC | none | has | 2016 |
| hmac-md5 | offers | removed | 2021 |

**Why strong signals**: these four together depict an SSH implementation from "around 2013". Yet the banner claims to be `OpenSSH_9.2p1 Debian-2+deb12u3` (a 2023 version). **The era mismatch between the banner and the algorithm set** is itself conclusive.

**Fixability**: **very hard**. The algorithm set is determined by Twisted's (or paramiko's) SSH stack; changing `ciphers`/`macs` in `cowrie.cfg` can only **reduce** the advertised algorithms, not **add** algorithms Twisted does not support. So a real fix means replacing the SSH implementation layer.

---

#### `term.underline_escape` (+15)

**Method**: observe the raw byte stream of an interactive shell.

**Result**:

```
Cowrie  : b'whoami\r\n\x1b[4lroot\r\n\x1b[4hroot@ubuntu-server:~# '
real sshd: b'whoami\r\n\x1b[?2004l\r\x1b]3008;start=...\x1b\\ubuntucowrie\r\n...'
```

**Principle**: Cowrie inserts `ESC[4l` (disable underline) and `ESC[4h` (enable underline) around every command output. This is a trick Cowrie uses to mask internal prompt state changes, but a real bash does not send these two sequences on its own.

**Fixability**: **medium**. Requires editing Cowrie's `shell/protocol.py` to remove these two sequences.

---

#### `fs.hostname_mismatch` (+15)

**Method**: compare three sources

```bash
# 1. prompt (PS1)
root@ubuntu-server:~#

# 2. hostname command
hostname          # -> ubuntu-server

# 3. /etc/hostname
cat /etc/hostname # -> svr04
```

**Contradiction**: the first two say `ubuntu-server`, the third says `svr04`.

**Principle**:

- the prompt hostname and the `hostname` command output both come from `cowrie.cfg`'s `[honeypot] hostname = ubuntu-server`
- the `/etc/hostname` content comes from the static snapshot in `fs.pickle` (`svr04`)

The two are fully independent; changing one does not sync the other.

**Why a strong signal**: on a real system all three are driven by one kernel hostname and cannot differ.

**Fixability**: **easy**. Unify `cowrie.cfg`'s `hostname` with `/etc/hostname` in fs.pickle.

---

#### `fs.container_markers` (+15)

**Method**:

```bash
ls -la /.dockerenv     # -> -rwxr-xr-x ... 0 2026-05-04 14:44 .dockerenv
ls -la /proc/docker    # -> exists
```

**Principle**: Cowrie's bundled `fs.pickle` was captured with `bin/createfs` from a **real Docker container**. The container's distinctive markers (`/.dockerenv`, `/proc/docker`, `/var/log/runit`) were carried into the fake filesystem along with it.

**Why it is ironic**: this "physical server" simultaneously claims to be a Debian server, yet has container markers in its root directory.

**Fixability**: **easy**. Exclude these paths when regenerating fs.pickle.

---

#### `cmd.head_numeric_shorthand` (+18) / `cmd.tail_numeric_shorthand` (+12)

**Method**:

```bash
head -3 /etc/passwd
tail -2 /etc/passwd
```

**Result**:

```
head: invalid option -- '3'
tail: invalid option -- '2'
```

**Principle**: `head -3 file` is supported by both POSIX and GNU coreutils (numeric shorthand). Cowrie's emulator only understands `head -n 3`.

**Why a strong signal**: a real `head` binary would not reject `-3`. This shows the parser was self-written.

**Fixability**: **medium**. Requires editing the argument parsing of `commands/ls.py` and similar modules.

---

#### `cmd.missing_modern_tools` (+15)

**Method**:

```bash
which ss ip systemctl
```

**Result**: no output (all three missing).

**Principle**:

| Tool | Introduced | Note |
|---|---|---|
| `ip` / `ss` | 2001 (iproute2) | replaces `ifconfig` / `netstat` |
| `systemctl` | 2015 (systemd) | default since Ubuntu 15.04 |

The banner claims to be Debian 12 (released 2023), yet lacks these two components that should have been present 8 years earlier.

**Fixability**: **medium**. Requires adding Python implementations for these commands.

---

#### `fs.sshd_config_empty` (+12) / `cmd.top_crash` (+12)

`sshd_config` empty: the fake filesystem created the path without content. A real SSH server must have a non-empty config.

`top` crash: Cowrie's `top` relies on preset `/proc` data; with an argument combination like `-n 1` it reaches an unhandled code path and reports `E82: Cannot allocate any buffer`.

---

### 7.3 Weak signals

A weak signal alone may be a configuration difference; several hitting together are needed to be convincing.

| Check | Weight | Note |
|---|---|---|
| `cmd.uptime_short` | +10 | Cowrie's uptime counts from process start, not system boot |
| `fs.uniform_timestamps` | +10 | snapshot generation makes many entries share mtimes, uniqueness only 18% |
| `proto.legacy_rsa_hostkey` | +8 | advertises only `ssh-rsa`, no `rsa-sha2-*` |
| `cmd.legacy_nic_name` | +8 | `ifconfig` hard-codes `eth0`, modern systems use `enp0s3` |
| `cmd.kernel_distro_mismatch` | +8 | uname says Debian, but the directory structure is a container snapshot |
| `term.no_bracketed_paste` | +6 | missing modern bash's bracketed paste sequences |

---

## 8. Defender view: how to minimise the index

> This chapter is for a deployer who "wants a more realistic honeypot". It also shows the detector's value -- **only what can be quantified can be optimised**.

### 8.1 Fixability grading

| Layer | Current score | Can drop to | Difficulty |
|---|---|---|---|
| Filesystem | 50 | ~0 | low (regenerate fs.pickle) |
| Command behaviour | 88 | ~20 | medium (add command implementations) |
| Terminal behaviour | 21 | ~6 | medium (edit protocol.py) |
| Protocol | 87 | ~50 | very high (replace the SSH stack) |
| Authentication | 30 | 0 (but the honeypot stops working) | unfixable |

### 8.2 Recommended modification order

**Step 1: unify identity (eliminate the cheapest tells)**

```ini
# etc/cowrie.cfg
[honeypot]
hostname = svr04          # consistent with /etc/hostname in fs.pickle
```

**Step 2: regenerate fs.pickle**

Generate it with `bin/createfs` from a controllable rootfs directory, noting:

- exclude `/.dockerenv`, `/proc/docker`, `/var/log/runit`
- fill `/etc/os-release` correctly (a non-empty regular file)
- fill `/etc/ssh/sshd_config` correctly
- scatter mtimes (randomise with `touch -d`)

**Step 3: complete the command implementations**

Priority:

1. numeric shorthand for `head` / `tail` (edit the parser in `commands/base.py`)
2. Python implementations of `df`, `sed`
3. stub implementations of `ss`, `ip`, `systemctl`

**Step 4: remove terminal traces**

Edit `shell/protocol.py` to remove the `ESC[4l` / `ESC[4h` around output.

**Step 5 (the only hard wound): the SSH protocol stack**

Cowrie's algorithm set is determined by the underlying SSH library; `cowrie.cfg` can only trim, not extend. A real fix requires:

- switching to an SSH library that supports modern algorithms (e.g. one based directly on `cryptography` + a self-implemented handshake), or
- fronting Cowrie with a real OpenSSH doing TLS-termination-style forwarding (changing the architecture)

**This is why the start of chapter 8 says "very hard".** The protocol layer is Cowrie's architectural trace.

### 8.3 Expectation after modification

Based on the table above, **after a full modification the exposure index can drop from 100 to about 55-65**, still judged "highly suspicious" but out of the "definitely a honeypot" band.

This matches the early judgement of the project: **a honeypot can be made harder to identify, but the principle of a medium-interaction honeypot means it cannot be made fully invisible**. The reason is simple -- it must expose an interactive fake system, and a fake system necessarily differs from a real one.

### 8.4 An important insight

**The return on lowering the exposure index diminishes.**

Dropping the index from 100 to 60 may cost only a few hours (edit config + regenerate fs.pickle); from 60 to 40 costs weeks of development (completing command implementations + editing protocol); from 40 to 20 requires rewriting the SSH stack.

In real security operations, **most deployments choose "good enough"**: patch the most easily seen-through tells, then carry responsibility via **network isolation** and **off-host logging**, rather than chasing a perfect disguise. This is also one of the core conclusions this project reached in its threat analysis (see chapter 9).

---

## 9. Threat analysis chain: the full assessment record

> This chapter records the systematic examination of Cowrie's threat surface during the project. Each item was empirically verified; all conclusions are "does not hold", but for different reasons.

### 9.1 Threat 1: escape from inside the honeypot to the host

**Hypothesis**: can the attacker break out of Cowrie's fake shell and gain control of the real host?

**Verification**:

- across all 57 command modules, `eval()` / `exec()` / `os.system` / `subprocess` appear 0 times (only 2 harmless `subprocess.run(["which",...])` and `["clear"]`, not on the attack path)
- `gcc` produces random bytes, does not invoke a compiler
- `scp` / `sftp` uploads write to `avatar.server.fs` (the in-memory pickle tree), not a real disk
- `python` / `perl` / `bash` commands output preset text, do not start an interpreter
- the honeypot process has `CapEff = 0000000000000000` (no capabilities)

**Conclusion**: **does not hold**. Cowrie has no code execution path; this is determined by architecture.

**Remark**: Bunyan/pickle deserialisation (fs.pickle's `__reduce__`) is a theoretical risk, but replacing that file needs uid 1001 write permission, forming a circular dependency.

### 9.2 Threat 2: lateral movement from the host into the LAN

**Hypothesis**: after compromising the honeypot host, can it be used as a stepping stone to attack other LAN machines?

**Verification** (network layer, TCP initiated directly from the VM):

| Target | Result |
|---|---|
| internet `example.com:80` | reachable |
| `192.168.122.1:22` (host virbr0) | closed |
| `192.168.122.1:53` | closed |
| `192.168.1.x` (real LAN) | unreachable |
| `172.17.0.1` (docker0) | closed |

**Conclusion**: **does not hold** (under the current configuration). libvirt's NAT and the host firewalld together isolate the VM.

**Important reminder**: this isolation is **implicit** -- it relies on the host firewall's default policy, not on explicit rules in the VM itself. If the firewall rules change, this layer disappears, and the VM has no awareness of it. Declare egress rules explicitly in `nwfilter` to turn "happens to be safe" into "declared safe".

### 9.3 Threat 3: exploiting a known CVE

**Hypothesis**: does Cowrie have an exploitable public vulnerability?

**Verification**:

- the only public CVE: **CVE-2025-34469** (DoS, affects <= 3.0.13)
- this group's version: 3.0.13, but **already patched** (the code contains the `outbound_rate_limiter()` factory function and the `[shell] *_rate_limit_*` config options, a structural signature of the patch; upstream did not bump the version)

**Conclusion**: **does not hold**. And a DoS by itself provides no code execution.

### 9.4 Threat 4: as a botnet node

**Hypothesis**: since the honeypot can reach the internet, can it be recruited as a botnet node?

**Verification**:

| Necessary condition for a botnet node | The honeypot's actual state |
|---|---|
| code execution | does not exist (see 9.1) |
| persistence | no systemd service, no cron jobs |
| C2 channel | a theoretical path (output plugins), but the URL comes from the config file |

**Key clarification**: `wget` is Python-emulated; it calls Twisted's `Agent`/`connectTCP`, and the downloaded file is **saved to the `downloads/` directory and never executed**. "The honeypot can reach the internet" means "the Cowrie Python process can reach the internet", not "you can run things on this machine".

**Conclusion**: **does not hold**.

### 9.5 Threat 5: as a DDoS amplifier

**Hypothesis**: can the honeypot's internet access be used to launch DDoS?

**Verification**:

| Dimension | What DDoS needs | Cowrie's actual limit |
|---|---|---|
| Concurrency | tens of thousands of simultaneous connections | commands in a session run serially (`cmdstack` is a stack) |
| Rate | hundreds of thousands of PPS | `outbound_rate_limiter`: **5 per 60 seconds per host** |
| Duration | hours on end | `idle_timeout = 180` seconds |
| Backend | hundreds of sessions | no `max_connections` in the config |

**Peak firepower estimate**:

```
5 per 60s per host × N concurrent sessions = 5N/60 requests/second
```

Even with 100 sessions (which already makes the honeypot itself unresponsive), the peak is about **8 RPS**. A real UDP reflection attack can reach hundreds of thousands of PPS.

**Extra structural barrier**: the rate limit counts per "destination host", not per session. So multiple sessions hitting the same target share the quota; to bypass it you must change targets -- and then it is no longer DDoS.

**Conclusion**: **does not hold**. Technically it can emit connections, but with less firepower than a home router.

### 9.6 Threat 6: using output plugins as an egress channel

**Hypothesis**: 13 output plugins call `Agent.request()` directly, bypassing the `_is_blocked` blacklist -- can this be exploited?

**Verification**:

```python
# output/discord.py:52
self.url = CowrieConfig.get("output_discord", "url").encode("utf8")  # fully config-determined
self.agent = client.Agent(reactor)
d = self.agent.request(b"POST", self.url, headers, body)             # bypasses _is_blocked
```

**Coverage clarification**:

| Path | Checks `_is_blocked`? |
|---|---|
| `curl` / `wget` / `nc` / `ftpget` / `tftp` | yes |
| 13 output plugins (axiom/cuckoo/datadog/discord/dshield/graylog/greynoise/malshare/signal/splunk/telegram/urlhaus/virustotal) | no |
| `[llm] host` (default `https://api.openai.com`) | no |

**Conclusion**: **partly holds, but not controllable by the attacker**. The URL comes from the config file, which the attacker cannot change (needs uid 1001). This **is not a hole the attacker can actively exploit, but a consequence of misconfiguration**.

**The real risk**: if the administrator points a webhook at a compromised domain, the honeypot **actively and periodically** sends data there. This is a "config-driven egress channel".

**The security recommendation that follows**: the honeypot host must strictly control **who can write the config file** -- write permission on the config file is the privilege boundary.

### 9.7 Threat analysis summary

| Threat | Conclusion | Root cause | Fixability |
|---|---|---|---|
| Escape to host | does not hold | no code execution path | determined by architecture |
| Lateral into LAN | does not hold | network isolation | implicit, recommend making it explicit |
| Known CVE | does not hold | the only CVE is patched | -- |
| Botnet node | does not hold | no code execution + no persistence | determined by architecture |
| DDoS amplifier | does not hold | rate limit + serial execution | determined by architecture |
| Output-plugin egress | partly holds | config-driven, not attacker-controllable | privilege management |

**The real attack surface is not in these six, but in the deployment configuration**:

1. **a real SSH service exists on the honeypot host independent of the honeypot**, with account credentials reused on the management channel
2. **Cowrie's code, config and logs are owned by the same uid that runs the honeypot and are group-writable** (measured: `cowrie.cfg`, all 57 `.py` files and `cowrie.json` belong to `cowrie:cowrie`, permission `-rw-rw-r--`)
3. **the honeypot process does not enable `NoNewPrivs` / seccomp** (measured `NoNewPrivs: 0`, `Seccomp: 0`)
4. **logs can be tampered with** -- the honeypot's entire output is logs, and making them writable means "evidence can be destroyed"

---

## 10. Limitations and known errors

### 10.1 Detector limitations

**1. Depends on the default configuration**

Some checks (e.g. empty `/etc/os-release`, presence of `/.dockerenv`) depend on Cowrie's bundled `fs.pickle`. If the deployer regenerated the filesystem, these items fail.

**2. Cannot identify high-interaction honeypots**

A high-interaction honeypot runs a real system, so this project's filesystem and command-behaviour checks all do not apply. Identifying a high-interaction honeypot needs network traffic analysis, business logic analysis and similar means.

**3. The auth-layer check leaves a log**

`auth.accepts_random_password` requires one real login attempt, which leaves a `cowrie.login.success` record in Cowrie's `cowrie.json`. The defender can spot "someone is detecting the honeypot" from this record.

**4. The protocol-layer check requires a TCP connection**

Even `--passive` mode leaves a `cowrie.session.connect` record.

**5. Weak signals can give false positives**

`cmd.uptime_short` falsely triggers on a just-rebooted real system (the control group hit this one). This is a design trade-off: better a false positive on one weak signal (+10) than missing a genuine sign of short-term running.

### 10.2 Known implementation details

**1. `remote_kex_init` scenario difference**

paramiko 5.x clears `remote_kex_init` after one auth handshake. This project reads raw TCP instead, avoiding the problem, but it also means the algorithm-set probe is independent of the paramiko session.

**2. `--passive` mode is incomplete**

`--passive` skips the shell session, but the `proto.no_exec_channel` check still needs one login. If login fails (wrong credentials), that check is recorded as "excluded from the verdict" rather than "clean".

**3. Prompt parsing relies on the PS1 format**

`_remember_prompt` parses the prompt with the regex `([A-Za-z0-9_.-]+)@([A-Za-z0-9_.-]+):`. If the deployer changed the PS1 format, the hostname comparison fails.

---

## 11. Appendix: empirical comparison tables

### 11.1 Command output comparison

| Command | Cowrie output | Expected output on a real system |
|---|---|---|
| `cat /etc/hostname` | `svr04` | consistent with `hostname` |
| `hostname` | `ubuntu-server` | as above |
| `cat /etc/os-release` | (empty) | full distribution info |
| `head -3 /etc/passwd` | `head: invalid option -- '3'` | the first three lines |
| `tail -2 /etc/passwd` | `tail: invalid option -- '2'` | the last two lines |
| `df -h` | `cannot execute binary file` | disk usage table |
| `sed -n 1p /etc/passwd` | `cannot execute binary file` | the first line |
| `top -n 1` | `E82: Cannot allocate any buffer` | process list |
| `which ss ip systemctl` | (no output) | three paths |
| `ifconfig` | `eth0` | `enp0s3` / `ens33` etc. |
| `uptime` | `up 7 min` | real uptime |

### 11.2 SSH algorithm set comparison

| Category | Cowrie :2222 | real sshd :22 |
|---|---|---|
| **kex** | curve25519, ecdh-*, dh-group-* | + mlkem768x25519, sntrup761x25519 |
| **hostkey** | ssh-rsa, ecdsa-*, ssh-ed25519 | rsa-sha2-512/256, ecdsa-*, ssh-ed25519 |
| **enc** | aes*-ctr, **aes*-cbc, 3des-cbc, cast128-cbc** | **chacha20-poly1305, aes*-gcm**, aes*-ctr |
| **mac** | hmac-sha2-*, hmac-sha1, **hmac-md5** | umac-*-etm, **hmac-*-etm**, hmac-sha1 |
| **comp** | zlib@openssh.com, zlib, none | none, zlib@openssh.com |

(bold = key differences)

### 11.3 Filesystem key-path comparison

| Path | Cowrie | Real system |
|---|---|---|
| `/etc/os-release` | empty / wrong type | non-empty regular file |
| `/etc/ssh/sshd_config` | empty | non-empty |
| `/.dockerenv` | exists | does not exist (physical machine) |
| `/proc/docker` | exists | does not exist |
| `/etc/hostname` | `svr04` | consistent with the kernel |
| `/etc/passwd` | has the `phil` user | consistent with reality |
| `/etc/shadow` | has bcrypt hashes | as above |

### 11.4 Terminal byte-stream comparison

```
Cowrie:
  b'whoami\r\n\x1b[4lroot\r\n\x1b[4hroot@ubuntu-server:~# '

real bash:
  b'whoami\r\n\x1b[?2004l\r\x1b]3008;start=<uuid>;...\x1b\\ubuntucowrie\r\n'
  b'\x1b]3008;end=<uuid>;exit=success\x1b\\'
  b'\x1b]3008;start=<uuid>;...\x1b\\'
  b'\x1b[?2004h\x1b]0;ubuntucowrie@ubuntucowrie: ~\x07'
  b'ubuntucowrie@ubuntucowrie:~$ '
```

Key differences:

- Cowrie has `ESC[4l` / `ESC[4h`, real bash does not
- real bash has `ESC[?2004h/l` (bracketed paste), Cowrie does not
- real bash has `OSC 3008` (session marking) and `OSC 0` (window title), Cowrie does not

---

## Closing

The value of this project is not "we wrote a script that recognises Cowrie" -- that part could be done by just string-matching a known honeypot.

The value is in **building a reusable analysis framework**:

1. **Layering**: split "disguise" into five independent attack surfaces, each assessed separately
2. **Grading**: grade evidence by strength, avoiding false positives from a single weak signal
3. **Quantification**: give a comparable score, making "before / after" a measurable engineering metric
4. **Explainability**: every check can explain "why this cannot appear on a real system", rather than a black-box verdict

This framework applies equally to assessing other honeypot products, reviewing the behavioural consistency of automated systems, and understanding "where the gap between emulation and reality lies" -- which is exactly the core theme of this assignment.

---

*This document was written by the group members for the ITSD010 CA2 group assignment. All empirical data comes from our group's self-built isolated lab environment.*
