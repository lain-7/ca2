# CA2 Honeypot Project: Cowrie Deployment, Detection and Hardening

> [中文](../README.md) · **English**

> ITSD010 Computing and Cybersecurity Fundamentals — CA2 group assignment
> Singapore Institute of Management · Diploma in Information Technology
> October 2026 Term

---

## What this is

This repository documents a complete honeypot engineering exercise: **deploy Cowrie -> identify its tells -> harden it step by step -> quantify the improvement**.

Unlike the common "install a honeypot and take a screenshot" approach, the core of this project is a closed loop:

```
  write detector  ──→  measure exposure score
      ↑                        │
      │                        ↓
  re-measure      ←──  targeted modification
```

Every modification has a **reproducible score comparison**, with the data stored under `reports/`.

---

## Project structure

```
.
├── docs/                          documentation
│   ├── honeypot-detector-design-and-report.md  detector theory, five-layer model, scoring (~23k chars)
│   ├── honeypot-modification-log.md             step-by-step modification process with score comparison (~14k chars)
│   └── vm-environment.md                        every change and reason for the OVA-to-KVM migration
│
├── attack/                        **attacker tools**
│   ├── simulate_attack.sh         SSH credential guessing and reconnaissance simulation
│   ├── deploy_attack.sh           one-shot environment setup for the attacker machine
│   ├── payloads/                  attack payloads (credential list)
│   └── README.md                  attacker tool usage
│
├── defense/                       **defender tools**
│   ├── deploy_defense.sh          one-shot deploy for the defender host (VPS), reproducing the honeypot by hand
│   ├── analyze_logs.sh            main Cowrie log analysis script
│   ├── ip_tracker.py              IP geolocation tracing and threat assessment
│   ├── visualizer.py              terminal ASCII charts
│   ├── report_generator.py        generates a detailed Markdown analysis report
│   └── README.md                  defender tool usage
│
├── tools/                         **honeypot modification tools**
│   ├── honeypot_detect.py         honeypot detector (core)
│   ├── measure.sh                 one-shot measure-and-record of the score
│   ├── probe.py                   interactive command probing (for manual inspection)
│   │
│   ├── rebuild_fs.py              rebuild Cowrie's fake filesystem
│   ├── add_fs_paths.py            fill in missing fake-filesystem paths
│   ├── patch_underline.py         remove terminal control sequences
│   ├── patch_headtail.py          head/tail numeric shorthand support
│   ├── patch_uptime_nic.py        fix uptime and interface name
│   ├── register_cmd.py            register a new command module
│   ├── add_import.py              add an import to a file
│   │
│   ├── cowrie_commands/           newly added Cowrie command implementations
│   │   ├── df.py                  df (full implementation)
│   │   ├── sed.py                 sed (common subset)
│   │   └── systemtools.py         top / ss / ip / systemctl
│   │
│   └── (diagnostic tools)
│       ├── dump_fs.py             dump the contents of fs.pickle
│       ├── check_bin.py           check the /bin /sbin structure
│       ├── check_ciphers.py       list the algorithms Twisted supports
│       ├── find_esc.py            byte-search for escape sequences
│       ├── trace_modes.py         trace the terminal-mode call stack
│       └── trace_write.py         trace the SSH write path
│
└── reports/                       measurement data and analysis reports
    ├── detect_honeypot.json       Cowrie (after modification)
    ├── detect_realsshd.json       control group: real OpenSSH
    ├── step01~06_*.json           step-by-step comparison of the six modifications
    └── analysis_*/                log analysis reports (generated at runtime)
```

**Documentation directory** (`docs/`):

- `honeypot-detector-design-and-report.md` - detector theory, five-layer model, scoring (~23k chars)
- `honeypot-modification-log.md` - step-by-step modification process with score comparison (~14k chars)
- `vm-environment.md` - every change and reason for the OVA-to-KVM migration
- `exercise-guide.md` - **full attack/defence workflow** (up and running in 30 minutes)
- `vps-deployment-security-audit.md` - risks and a hardening checklist for putting the honeypot on a public VPS
- `presentation-notes-and-qa.md` - how to cut content for a 35-minute presentation + 20 anticipated questions

---

## Two usage paths

### Path A: honeypot modification and detection (detector angle)

**Goal**: understand the exposure features of a honeypot and learn hardening methods.

```bash
# 1. Connect to the honeypot and run the detector
python3 tools/honeypot_detect.py 192.168.122.123 2222 root admin

# 2. Read the modification log to understand each change
cat docs/honeypot-modification-log.md

# 3. Compare the score before and after modification
jq .score reports/step01_hostname.json  # before
jq .score reports/detect_honeypot.json  # after
```

**For**: those who want to understand honeypot technology, the SSH protocol and terminal emulation in depth.

### Path B: attack/defence exercise and log analysis (security analysis angle)

**Goal**: simulate a real attack, analyse attacker behaviour and produce a security report.

```bash
# 1. Simulate an attack
cd attack/
./simulate_attack.sh 192.168.122.123 2222

# 2. Analyse the logs
cd ../defense/
./analyze_logs.sh /path/to/cowrie/logs

# 3. View the report
cat reports/analysis_*/summary.txt
```

**For**: those who want to quickly finish CA2 Task 3-4 (Attack Simulation & Log Analysis).

**Detailed workflow**: see [`docs/exercise-guide.md`](docs/exercise-guide.md)

---

## Quick start

### Path A dependencies

```bash
# Python 3.9+ and paramiko
pip install paramiko
```

### Path B dependencies

```bash
# Arch Linux
sudo pacman -S sshpass openssh jq python curl

# Ubuntu/Debian
sudo apt install sshpass openssh-client jq python3 curl
```

### Run the detector (path A)

```bash
# full detection
python3 tools/honeypot_detect.py --host 192.168.122.252 --port 2222 --verbose

# JSON output (for automated comparison)
python3 tools/honeypot_detect.py --host 192.168.122.252 --port 2222 --json

# protocol and auth layers only, no login (stealthiest)
python3 tools/honeypot_detect.py --host 192.168.122.252 --port 2222 --passive
```

Exit codes: `0` = identified as a honeypot, `1` = not identified, `2` = connection failure.

---

## Key results

### Detector effectiveness

| Target | Exposure index | Hits |
|---|---|---|
| Cowrie (before) | **100** / raw 313 | 4 decisive / 12 strong / 6 weak |
| Cowrie (after) | **100** / raw **118** | 1 decisive / 5 strong / 2 weak |
| Real OpenSSH (control) | **10** | 0 decisive / 0 strong / 1 weak |

**The control group is the real sshd on the same machine** (same IP, same subnet, same moment). The only variable is the server-side implementation, so this data proves the detector analyses **system behaviour**, not external features like "non-standard port".

### Modification curve

| Step | Change | Raw score | Filesystem | Command behaviour | Terminal |
|---|---|---|---|---|---|
| Baseline | — | 313 | 62 | 118 | 21 |
| 1 | Unify hostname | 313 | 62 | 118 | 21 |
| 2 | Rebuild fake filesystem | 243 | **0** | 110 | 21 |
| 3 | Remove terminal control sequences | 228 | 0 | 110 | **6** |
| 4 | Implement df | 178 | 0 | **60** | 6 |
| 5 | uptime + interface name | 160 | 0 | **42** | 6 |
| 6 | Add sed/top/ss/ip/systemctl | **118** | 0 | **0** | 6 |

**Raw score down 62%; the filesystem and command-behaviour layers fully zeroed.**

> **Why does the "index" stay at 100?**
> The scoring model has a "floor of 70 if any decisive item hits" rule, and the authentication-layer item (accepts any random password) is a defining feature of a honeypot and cannot be eliminated. So the index is always pinned at the ceiling of 100.
> For this reason the script also outputs the **raw score** (the uncapped weight sum), which is the correct metric for measuring modification progress.

---

## Five-layer detection model

| Layer | What it checks | Fixability |
|---|---|---|
| **Protocol** | SSH algorithm set (AEAD / CBC / ETM / md5), exec channel | very hard (requires a new SSH stack) |
| **Authentication** | whether it accepts any random password | unfixable (honeypot definition) |
| **Filesystem** | hostname consistency, container markers, timestamps, config file content | easy |
| **Command behaviour** | head/tail syntax, df/sed executability, presence of modern tools | medium |
| **Terminal behaviour** | control sequences, bracketed paste | medium |

Within each layer, evidence is graded by strength:

- **Decisive**: impossible on a real system -> a single hit concludes
- **Strong**: extremely unlikely on a real system -> two or more hits conclude
- **Weak**: may just be a configuration difference -> needs several hits together

---

## Key conclusions

### 1. A medium-interaction honeypot has a clear disguise ceiling

Low-cost modifications can eliminate 180 points, but below that lie architectural problems. Neither the protocol layer (82 points) nor the authentication layer (30 points) can be solved by configuration.

**Conclusion: a medium-interaction honeypot can be made harder to identify, but it cannot be made fully invisible.**

### 2. Detection score != realism

About 34 points of the protocol layer could in theory be removed by "trimming the algorithm set" (dropping CBC and md5). But the result would be an SSH server with no AEAD, no ETM and no CBC -- the detector scores it even lower, and a slightly experienced attacker becomes more suspicious instead.

**Optimising for the detector is not the same as increasing realism.** This is the classic trap of mistaking the metric for the goal.

### 3. The authentication-layer exposure should be accepted

A honeypot exists to be "broken into". Demanding that it not reveal "accepts any password" is demanding that it not work. The right approach is to accept this layer and use network isolation and off-host logging to carry the risk of "after it is seen through".

---

## Threat analysis summary

Six classes of threat were systematically examined during the project, all with empirical verification:

| Threat | Conclusion | Reason |
|---|---|---|
| Escape from honeypot to host | Does not hold | 57 command modules with no `eval`/`exec`/`subprocess` |
| Lateral movement into the LAN | Does not hold | network isolation (but relies on the host firewall, an implicit defence) |
| Exploit a known CVE | Does not hold | the only CVE (CVE-2025-34469, DoS) is already patched in this version |
| Use as a botnet node | Does not hold | no code execution + no persistence |
| Use as a DDoS amplifier | Does not hold | outbound rate-limited to 5 per 60s per host, peak about 8 RPS |
| Output-plugin egress | Partly holds | config-driven, not controllable by the attacker |

**The real attack surface is in the deployment configuration**: the honeypot host's separate SSH service and account reuse, code/config/log at the same privilege (all the `cowrie` user and group-writable), and the process not enabling `NoNewPrivs`/seccomp.

See chapter 9 of `docs/honeypot-detector-design-and-report.md` for details.

---

## Lab environment

| Component | Configuration |
|---|---|
| Host | Arch Linux, KVM/QEMU (libvirt) |
| Honeypot VM | Ubuntu 26.04 Server, 2 vCPU / 2G, NAT network `192.168.122.252` |
| Honeypot software | Cowrie 3.0.13 (pip install) |
| Honeypot ports | 2222 (Cowrie) / 22 (real sshd, control group) |

**The clean pre-modification state is snapshotted**: `baseline-2026-10-26`, one-click rollback.

---

## Declaration

All testing in this project was carried out in **our own isolated virtual environment**; no scan or attack was launched against any external system. The honeypot was not exposed to the public internet.

The code and documentation were written by our group members, for the ITSD010 CA2 group assignment.

---

## References

- Nawrocki, Wählisch, Schmidt, Keil & Schönfelder (2016). *A survey on honeypot software and data analysis*. arXiv:1608.06249
- Ylonen & Lonvick (2006). *The Secure Shell (SSH) protocol architecture*. RFC 4251
- Cowrie official docs: https://docs.cowrie.org/
