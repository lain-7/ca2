# Honeypot modification log: lowering the exposure index step by step

> Companion scripts: `tools/rebuild_fs.py`, `tools/patch_*.py`, `tools/cowrie_commands/`
> Companion measurement tool: `tools/measure.sh`
> Date: 2026-10-26
> Environment: Ubuntu 26.04 VM (KVM), Cowrie 3.0.13

---

## Contents

1. [Goal and method](#1-goal-and-method)
2. [Overview: the score curve](#2-overview-the-score-curve)
3. [Step-by-step detail](#3-step-by-step-detail)
4. [Remaining-score analysis: why it cannot go lower](#4-remaining-score-analysis-why-it-cannot-go-lower)
5. [Rollback guide](#5-rollback-guide)
6. [Conclusion](#6-conclusion)

---

## 1. Goal and method

### 1.1 Goal

Push the honeypot's "exposure index" (see *Honeypot detector design and detection report*) as low as possible, so `honeypot_detect.py` finds it harder to conclude it is a honeypot.

The realistic goal set early in the project was: **zero out the decisive signals and push the index below "highly suspicious"**, not to chase full invisibility.

### 1.2 Measurement method

After every step we run a full detection and record:

| Metric | Meaning |
|---|---|
| **Index** | 0-100, the official score of `honeypot_detect.py` (capped at 100) |
| **Raw score** | uncapped weight sum -- during modification the index hits the ceiling of 100, so only the raw score reflects real progress |
| **D / S / W** | number of decisive / strong / weak hits |
| **Layer subtotals** | the respective scores of the protocol / auth / filesystem / command-behaviour / terminal-behaviour layers |

Measurement command:

```bash
./tools/measure.sh step06_commands_full
```

Each result is saved in `reports/<label>.json` for comparison at any time.

### 1.3 An important methodological point

**The index did not change at all in the early stages (always 100).** This is because the scoring model has a "decisive-item floor" rule: if any decisive item hits, the index is at least 70; and the honeypot has 4 decisive items, with a raw score far above 100.

Looking at the index alone, the improvements of the first 5 steps are all "invisible". This is exactly why we later added the "raw score" metric -- **an observable metric must reflect real improvement, or modification becomes blind**.

The problem itself is worth recording: any "scoring system" hits a ceiling effect, and the design must also provide an uncapped auxiliary metric.

---

## 2. Overview: the score curve

| Step | Change | Index | Raw | D | S | W | Layers (proto/auth/fs/cmd/term) |
|---|---|---|---|---|---|---|---|
| Baseline | original state | 100 | **313** | 4 | 12 | 6 | 82 / 30 / 62 / 118 / 21 |
| 1 | Unify hostname | 100 | 313 | 4 | 12 | 6 | 82 / 30 / 62 / 118 / 21 |
| 2 | Rebuild fake filesystem | 100 | **243** | 3 | 10 | 4 | 82 / 30 / **0** / 110 / 21 |
| 3 | Remove terminal control sequences | 100 | **228** | 3 | 9 | 4 | 82 / 30 / 0 / 110 / **6** |
| 4 | Implement the df command | 100 | **178** | 2 | 7 | 4 | 82 / 30 / 0 / **60** / 6 |
| 5 | Fix uptime and interface name | 100 | **160** | 2 | 7 | 2 | 82 / 30 / 0 / **42** / 6 |
| 6 | Add sed/top/ss/ip/systemctl | 100 | **118** | 1 | 5 | 2 | 82 / 30 / 0 / **0** / 6 |

**Total: raw score from 313 down to 118, a 62% reduction.**

### 2.1 Reduction per layer

| Layer | Baseline | Final | Reduction | Note |
|---|---|---|---|---|
| Filesystem | 62 | **0** | 100% | fully eliminated |
| Command behaviour | 118 | **0** | 100% | fully eliminated |
| Terminal behaviour | 21 | 6 | 71% | 1 architectural flaw remains |
| Protocol | 82 | 82 | 0% | **cannot be lowered** |
| Authentication | 30 | 30 | 0% | **by design** |

### 2.2 Why the index stays at 100

Because the scoring model dictates "if any decisive item hits, the index >= 70", and the decisive auth-layer item (accepts any random password) **cannot be eliminated** -- it is a defining feature of a honeypot.

So **the index can never drop below 70** unless the honeypot function is abandoned. This is expanded in chapter 4.

---

## 3. Step-by-step detail

### Step 1: unify the hostname

**Problem**

The same machine has three "names", all different:

```bash
$ hostname               # ubuntu-server   <- from cowrie.cfg
root@ubuntu-server:~#    # ubuntu-server   <- the prompt, also from cowrie.cfg
$ cat /etc/hostname      # svr04           <- from fs.pickle
```

On a real system all three are driven by one kernel hostname and cannot differ.

**Fix**

```ini
# etc/cowrie.cfg
[honeypot]
hostname = svr04
```

**Result**

- eliminated 1 strong signal (`fs.hostname_mismatch`, 15 points)
- raw score 313 -> 313 (this check was also masked by other signals; the effect shows in the strong-signal count 13 -> 12)

**What this shows**: fixing a single low-weight item, while the total is capped, produces no visible change. This is the trigger for later introducing the raw-score metric.

---

### Step 2: rebuild the fake filesystem (the biggest step)

**Problem**

Cowrie's `fs.pickle` is a snapshot taken from a **Docker container**, causing three kinds of tells:

| Tell | Symptom |
|---|---|
| Missing content | `/etc/os-release` is an empty directory (`cat` shows nothing, `ls` shows 267 bytes) |
| Missing content | `/etc/ssh/sshd_config` exists but is empty |
| Snapshot trace | `/.dockerenv`, `/proc/docker`, `/var/log/runit` all present |
| Snapshot trace | 22 root entries have only 4 distinct mtimes (uniqueness 18%) |
| Identity conflict | `/etc/passwd` has a `phil` user and `vboxsf` group (VirtualBox traces) |

**Fix**

`tools/rebuild_fs.py` operates directly on the pickle node tree:

```bash
python3 tools/rebuild_fs.py <source fs.pickle> <output fs.pickle>
```

Node format (10-element positional list):

```
[name, type, uid, gid, size, mode, ctime, contents, target, realfile]
```

The script does 6 things:

1. **Fix the distribution identity** -- write a complete Debian 12 `os-release`, add `lsb-release`, `debian_version`
2. **Unify the hostname** -- `hostname`, `hosts`, `motd` all set to `svr04`
3. **Replace the user database** -- use a clean Debian 12 `passwd` / `group`, remove `phil` / `vboxsf`, add the `deploy` admin and its home directory
4. **Fill in sshd_config** -- write the full Debian 12 default config (keeping `PermitRootLogin prohibit-password`, so "root can log in" is self-consistent at the filesystem level too)
5. **Remove container traces** -- `/.dockerenv`, `/proc/docker`, 8 runit paths
6. **Scatter timestamps** -- the mtimes of 19 root entries randomly spread over 540 days (fixed seed, reproducible)

**Result**

| Metric | Change |
|---|---|
| Filesystem layer | 62 -> **0** |
| Raw score | 313 -> **243** |
| Decisive items | 4 -> 3 (the `os-release` one eliminated) |
| Strong signals | 12 -> 10 |

**This is the most cost-effective step**: one modification clears the entire filesystem layer (62 points).

**Note**: the rebuilt identity is **Debian 12 + svr04**, consistent with `[shell] kernel_version = 6.1.0-21-amd64` in `cowrie.cfg`. To switch to an Ubuntu identity later, change the constants at the top of the script.

---

### Step 3: remove terminal control sequences

**Problem**

Cowrie inserts terminal control sequences around every command:

```
$ echo TEST
b'echo TEST\r\n\x1b[4lTEST\r\n\x1b[4hroot@svr04:~# '
                 ^^^^^^^^      ^^^^^^^^
```

`ESC[4l` = disable insert mode, `ESC[4h` = enable insert mode. **Real bash does not send these two sequences on its own.**

**Locating it (an investigation worth recording)**

Searching the Cowrie source for `4l` / `4h` found nothing at first; a monkeypatch to trace the call stack finally located it:

```
cowrie/shell/honeypot.py:947  HoneyPotShell.resume()
  -> self.protocol.setInsertMode()
    -> twisted/conch/recvline.py:406  terminal.setModes([insults.modes.IRM])
      -> twisted/conch/insults/insults.py:713  write(b"\x1b[4h")

cowrie/shell/protocol.py:513  call_command()
  -> self.setTypeoverMode()
    -> twisted/conch/recvline.py:410  terminal.resetModes([IRM])
      -> insults.py:723  write(b"\x1b[4l")
```

**Fix**

Override these two methods in `HoneyPotInteractiveProtocol` in `cowrie/shell/protocol.py`.

**A pitfall hit (important)**

The first attempt overrode the methods as **complete no-ops**:

```python
def setInsertMode(self) -> None:
    """suppress ESC[4h"""
```

The shell crashed outright:

```
AttributeError: 'HoneyPotInteractiveProtocol' object has no attribute 'mode'
```

Reason: besides sending the sequence, these methods also maintain `self.mode` ("insert" / "typeover"), which `characterReceived()` relies on to decide insert vs. overwrite.

**The correct way** is to keep the state and only remove the sequence:

```python
def setInsertMode(self) -> None:
    self.mode = "insert"        # keep state

def setTypeoverMode(self) -> None:
    self.mode = "typeover"      # keep state
```

**Second pitfall**: the patch was first inserted into `HoneyPotExecProtocol` (the wrong place), because that class also has same-named methods. The corrected script verifies which class the insertion point belongs to.

**Third pitfall**: after editing a `.py`, you must clear `__pycache__` and restart, or the old bytecode is still loaded. The first edit tested as ineffective exactly because the process used the cached `.pyc`.

**Result**

```
before: b'echo TEST\r\n\x1b[4lTEST\r\n\x1b[4hroot@svr04:~# '
after:  b'echo TEST\r\nTEST\r\nroot@svr04:~# '
```

| Metric | Change |
|---|---|
| Terminal layer | 21 -> **6** |
| Raw score | 243 -> **228** |

---

### Step 4: implement the df command

**Problem**

```bash
$ df -h
-bash: /usr/bin/df: cannot execute binary file: Exec format error
```

Reason: Cowrie has no `commands/df.py`, only a static text in `data/txtcmds/bin/df`. The txtcmd mechanism takes no arguments, and some argument forms fall into the "generic binary" fallback path.

`df` is part of coreutils, essential on every Linux distribution -- this is a **decisive signal**.

**Fix**

Create `tools/cowrie_commands/df.py`, fully following Cowrie's official command module style:

```python
commands = {}

class Command_df(HoneyPotCommand):
    def call(self) -> None:
        ...

commands["df"] = Command_df
commands["/bin/df"] = Command_df
commands["/usr/bin/df"] = Command_df
```

Scope: `-h` / `-H` / `-T` / `-a` / `-i` / `-P` / `--help` / `--version`, plus any path argument.

The output partition table is consistent with the fs.pickle settings (20G root partition).

**Registration**

Do not edit the list in `commands/__init__.py` directly (easy to break the formatting); use `tools/register_cmd.py` to insert it in alphabetical order:

```bash
python3 tools/register_cmd.py df
```

**Result**

```
$ df -h
Filesystem                    Size    Used   Avail  Use% Mounted on
tmpfs                         200M      1M    199M   0%  /run
/dev/sda1                      20G    4.3G     16G  21%  /
tmpfs                        1000M       0   1000M   0%  /dev/shm
tmpfs                           5M       0      5M   0%  /run/lock
/dev/sda15                    105M      6M     99M   6%  /boot/efi
```

| Metric | Change |
|---|---|
| Command-behaviour layer | 110 -> **60** |
| Raw score | 228 -> **178** |
| Decisive items | 3 -> 2 (the `df` one eliminated) |

---

### Step 5: fix uptime and the interface name

**Problem A: uptime always shows "just booted"**

```bash
$ uptime
 02:10:44  up 10 min,  1 user,  load average: 0.00, 0.00, 0.00
```

The cause is in `cowrie/shell/protocol.py`:

```python
def uptime(self):
    pt = self.getProtoTransport()
    return time.time() - pt.factory.starttime     # <- when the Cowrie process started
```

Every honeypot restart resets uptime to zero. A production server rarely reboots within an hour.

**Fix**

```python
offset_days = CowrieConfig.getint("honeypot", "uptime_offset_days", fallback=47)
boot_time = pt.factory.starttime - offset_days * 86400
return time.time() - boot_time
```

**Problem B: ifconfig hard-codes eth0**

```bash
$ ifconfig
eth0      Link encap:Ethernet  HWaddr ...
```

systemd's `net.ifnames` has enabled predictable interface names (`enp0s3`, `ens33`) by default since 2015; modern Debian/Ubuntu no longer use `eth0`.

Moreover `ip a` shows `enp1s0` (my new implementation) while `ifconfig` shows `eth0` -- **the two commands contradict each other**.

**Fix**

Make the interface name read from config:

```python
nic_name = CowrieConfig.get("honeypot", "nic_name", fallback="enp1s0")
```

**A pitfall hit**

After the change `ifconfig` errored outright:

```
NameError: name 'CowrieConfig' is not defined
```

`ifconfig.py` did not import `CowrieConfig`. Adding the import fixes it (use `tools/add_import.py`).

**Result**

```
$ uptime
04:18:30  up 47 days,  0:00,  1 user,  load average: 0.00, 0.00, 0.00

$ ifconfig
enp1s0    Link encap:Ethernet  HWaddr 2d:f6:9a:e3:a7:3e
          inet addr:192.168.122.252  Bcast:192.168.122.255  Mask:255.255.255.0
```

| Metric | Change |
|---|---|
| Command-behaviour layer | 60 -> **42** |
| Raw score | 178 -> **160** |
| Weak signals | 4 -> 2 |

---

### Step 6: add sed / top / ss / ip / systemctl

**Problem**

| Command | Original state |
|---|---|
| `sed` | not implemented -> `cannot execute binary file` |
| `top` | txtcmd has only one line `E82: Cannot allocate any buffer, exiting...` |
| `ss` / `ip` / `systemctl` | do not exist at all -> `command not found` |

`sed` is an essential POSIX tool; `ip`/`ss` have been default since 2001 and `systemd` since 2015. A system claiming to be Debian 12 cannot lack these.

**Fix**

Create `tools/cowrie_commands/sed.py` and `systemtools.py` (the latter contains four classes: top / ss / ip / systemctl).

**sed's scope** (not a full implementation):

```
sed -n 1p file          print line 1
sed -n 1,5p file        print lines 1-5
sed 's/a/b/' file       replace the first
sed 's/a/b/g' file      replace all
sed -n '/pat/p' file    print matching lines
sed '1,3d' file         delete lines 1-3
```

Unsupported things report an explicit error rather than failing silently.

**Why not use the real sed**: the honeypot's design premise is "do not execute real binaries". Calling `/usr/bin/sed` would both expose the host toolchain and lose logging.

**Remove the top txtcmd**

```bash
rm -f $P/data/txtcmds/usr/bin/top
```

Otherwise the txtcmd takes priority over the Python implementation and still returns that error line.

**Fill in the fake-filesystem paths**

The new commands have Python implementations, but `which` / `ls /usr/bin` rely on the fs.pickle directory tree. After filling them in:

```bash
$ which ss ip systemctl
/usr/bin/ss
/bin/ss
/usr/sbin/ip
...
```

The paths repeat because `PATH` has both `/bin` and `/usr/bin`, and in fs.pickle `/bin` is a symlink to `usr/bin` -- **this is how a real Debian 12 behaves too**, so this output is correct.

**Result**

```
$ top -n 1
top - 04:25:12 up 47 days,  0:00,  1 user,  load average: 0.00, 0.01, 0.00
Tasks: 128 total,   1 running, 127 sleeping,   0 stopped,   0 zombie
...

$ ss -tulnp
Netid  State        Recv-Q  Send-Q Local Address:Port   Peer Address:Port  Process
tcp    LISTEN            0     128 0.0.0.0:22           0.0.0.0:*          users:(("sshd",pid=462,fd=3))

$ systemctl status ssh
● ssh.service - OpenBSD Secure Shell server
     Loaded: loaded (/lib/systemd/system/ssh.service; enabled; preset: enabled)
     Active: active (running) since Tue 2025-09-09 03:41:15 UTC; 47 days ago
   Main PID: 462 (sshd)
```

| Metric | Change |
|---|---|
| Command-behaviour layer | 42 -> **0** |
| Raw score | 160 -> **118** |
| Strong signals | 7 -> 5 |

---

## 4. Remaining-score analysis: why it cannot go lower

After modification, 118 points remain, all from the protocol layer (82) and auth layer (30), plus one terminal-layer item (6).

### 4.1 Auth layer: 30 points, not eliminable

```
[HIT] Accepts any random password  (+30)
```

**This is a defining feature of a honeypot.** A honeypot must let attackers in, or it cannot collect intelligence. Changed to accept only the correct password, attackers cannot get in and the honeypot degrades into an ordinary SSH service.

**The only way to "improve" it is to change the deployment approach**: put Cowrie inside a high-interaction environment that is never meant to be breached, or accept the fact that "the auth layer must be exposed".

**Conclusion: these 30 points should be kept.** The report should state clearly -- this is not a flaw, it is a design trade-off.

### 4.2 Protocol layer: 82 points, an architectural ceiling

All six items come from Twisted's SSH stack:

| Check | Weight | Eliminable? |
|---|---|---|
| Offers no AEAD cipher | 16 | No |
| Offers deprecated CBC | 14 | Partially (advertise fewer) |
| No ETM MAC | 14 | No |
| Offers hmac-md5 | 12 | Partially |
| Only ssh-rsa host key | 8 | Partially |
| No exec channel support | 18 | No |

**An empirical test confirmed Twisted's real capability boundary**:

```python
transport._getSupportedCiphers()
→ ['aes256-ctr', 'aes256-cbc', 'aes192-ctr', 'aes192-cbc',
   'aes128-ctr', 'aes128-cbc', '3des-cbc']
```

**Twisted simply does not implement chacha20-poly1305 or AES-GCM.** So the `ciphers` in `cowrie.cfg` can only be **trimmed** (advertise fewer), not **extended**.

**The trimming that is possible** (about 34 points):

```ini
[ssh]
# keep only CTR modes, drop all CBC
ciphers = aes128-ctr,aes192-ctr,aes256-ctr
# drop hmac-md5 and hmac-sha1
macs = hmac-sha2-512,hmac-sha2-384,hmac-sha2-256
```

**But this has a counterproductive effect**: a real Debian 12 SSH advertises AEAD algorithms, and after deleting CBC we still have no AEAD, which looks even more like "a manually trimmed server". **Trimming lowers the detector's score but does not increase realism.**

This is an important conclusion of the project: **detection score and realism are not fully equivalent**. Deliberately optimising for the detector may produce something "the detector cannot recognise, but a human immediately feels is off".

**So we did not perform this step**, and wrote it into the report as an analysis conclusion rather than a modification method.

### 4.3 Terminal layer: 6 points, acceptable

```
[HIT] Missing bracketed paste mode sequences  (+6)
```

Modern bash (5.0+) sends `ESC[?2004h` to enable bracketed paste. Cowrie's simplified shell does not implement this feature.

This item is classed as a **weak signal**; alone it may just mean a user customised PS1 or disabled the feature, so it is not grounds for a verdict. **Keeping it is reasonable.**

### 4.4 Final verdict state

| Metric | Value |
|---|---|
| Exposure index | 100 (capped) |
| Raw score | 118 |
| Verdict | "Definitely a honeypot" |
| Decisive items | 1 (auth layer only) |
| Strong signals | 5 (all protocol layer) |
| Weak signals | 2 |

**Excluding the 30 auth-layer points, the actual "technical exposure" is 88 points**, with 82 concentrated in the protocol layer.

---

## 5. Rollback guide

Every step kept a backup and can be rolled back individually.

### 5.1 Roll back to the pre-modification state (recommended: use the VM snapshot)

```bash
virsh -c qemu:///system snapshot-revert cowrie baseline-2026-10-26
```

This is the cleanest way; it returns to "KVM conversion done, netplan fixed, Cowrie 3.0.13 original state".

### 5.2 Per-item rollback

```bash
# Step 1: hostname
cp etc/cowrie.cfg.bak-step1 etc/cowrie.cfg

# Step 2: fake filesystem
cp cowrie-env/lib/python3.14/site-packages/cowrie/data/fs.pickle.orig-backup \
   cowrie-env/lib/python3.14/site-packages/cowrie/data/fs.pickle

# Step 3: terminal sequences
python3 tools/patch_underline.py --revert

# Step 4: head/tail
python3 tools/patch_headtail.py --revert

# Step 5: uptime / interface name
python3 tools/patch_uptime_nic.py --revert

# Step 6: new commands
rm cowrie-env/lib/python3.14/site-packages/cowrie/commands/{df,sed,systemtools}.py
# and remove the corresponding entries from command_modules in commands/__init__.py
```

### 5.3 Standard restart procedure

**After every Python edit you must clear the cache and restart**, or the change does not take effect:

```bash
source cowrie-env/bin/activate
cowrie stop
rm -rf cowrie-env/lib/python3.14/site-packages/cowrie/{shell,commands}/__pycache__
cowrie start
```

This procedure was missed once during investigation, leading to a false "the patch had no effect" and wasting a round of debugging.

---

## 6. Conclusion

### 6.1 Modification results

| Dimension | Before | After |
|---|---|---|
| Raw exposure score | 313 | **118** (down 62%) |
| Decisive signals | 4 | **1** (auth layer only) |
| Strong signals | 12 | **5** (all protocol layer) |
| Weak signals | 6 | **2** |
| Filesystem layer | 62 | **0** |
| Command-behaviour layer | 118 | **0** |
| Terminal-behaviour layer | 21 | **6** |

### 6.2 Three core insights

**First: a medium-interaction honeypot's disguise has a clear ceiling.**

Low-cost modifications (rebuilding the filesystem, adding command implementations) can eliminate 180 points, but below that lie architectural problems. The protocol and auth layers total 112 points, none solvable by "configuration".

This confirms the early judgement of the project: **a medium-interaction honeypot can be made harder to identify, but cannot be made fully invisible**, because it must expose an interactive fake system.

**Second: detection score is not realism.**

Of the 82 protocol-layer points, about 34 can be removed by "trimming the algorithm set". But the result is "an SSH server with no AEAD, no ETM and no CBC" -- the detector scores it lower, but a slightly experienced attacker finds it more suspicious, because a real server is not configured that way.

**Optimising for the detector != increasing realism.** This is a common trap in security engineering: mistaking the metric for the goal.

**Third: the auth-layer exposure should be accepted, not fixed.**

A honeypot exists to be "broken into". Demanding that it "not reveal that it accepts any password" is demanding that it not work.

The right approach is to **accept this layer**, invest resources in the other layers, and at deployment use network isolation, off-host logging and a dedicated host to carry the risk of "after it is seen through".

### 6.3 The real benefits of the modification

Setting the score aside, the modification genuinely improved the honeypot in several ways:

1. **Self-consistent filesystem** -- the `/etc/passwd`, `/etc/os-release`, `/etc/hostname` the attacker sees are mutually consistent, no longer contradictory
2. **Credible command behaviour** -- common commands run normally; the attacker does not bail out immediately because "df does not run"
3. **Container traces removed** -- no longer exposes the fatal tell "this server is actually a Docker snapshot"
4. **Can support more realistic attack simulation** -- the attacker can truly run a full reconnaissance flow, and only then does the resulting log have analytical value

**Point 4 matters most**: the assignment requires "collecting meaningful attack activity logs". A honeypot seen through at a glance makes the attacker leave immediately, leaving only a few failed-login lines in the log and nothing to write in the analysis chapter.

---

*All data recorded in this document comes from our group's self-built isolated lab environment. The modification scripts are in the `tools/` directory, and every step can be rolled back.*
