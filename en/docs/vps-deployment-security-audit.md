# Security audit for deploying the Cowrie honeypot on a VPS

For: Ubuntu 24.04 LTS, a VPS like DigitalOcean / Vultr / Linode, with the honeypot exposed to the public internet to capture real attacks.

The school advises against running a honeypot on a VPS, and the risks below are the core reason. This document gives, item by item, "what can go wrong + how to fix it", and marks which items are handled automatically by `defense/deploy_defense.sh`.

---

## Conclusion first

You can run it on a VPS, but a honeypot is a service designed to be "broken into" -- it is deliberately putting a machine in the line of fire. The point of security is not "do not get hit", but **keeping the impact of being hit contained within the honeypot**: the real management plane must be completely separate from the honeypot, outbound traffic must have a backstop, logs must be exfiltrated off-host, and provider abuse complaints must be answerable. Manual deployment (not the .ova) is precisely to build this hardening in.

---

## 1. The host's own exposure surface

| Problem | Risk | Fix | Automated by the script? |
|------|------|------|------|
| Real sshd and the honeypot share 22 | real attacks on 22 reach your real sshd; or your traffic mixes with the attacker's | move management SSH to 2022, redirect 22 to Cowrie | Yes (two stages) |
| Password login enabled | the management port gets brute-forced | `PasswordAuthentication no`, key only; `PermitRootLogin prohibit-password` | Yes |
| Other default services listening | one more service is one more hole | after deploy, check with `ss -tulnp`, keep only the management port + honeypot | No, check manually |
| Firewall allows too much | unknown ports get probed and abused | ufw denies incoming by default, allows only 2022 / 22 | Yes |
| Cowrie port 2222 reachable directly | 22 and 2222 share a fingerprint, and 2222 is Cowrie's default port, revealing the honeypot's identity | allow only redirected connections "whose original destination port was 22" (conntrack); drop direct 2222 | Yes (--cutover) |

> Do it yourself: after install, be sure to run `ss -tulnp` to see whether any other port is listening (e.g. a monitoring agent preinstalled in the cloud image).

## 2. Keeping the honeypot contained (the most critical part)

Cowrie is a medium-interaction honeypot: the attacker's commands run inside a **fake shell** and never actually execute on your host -- this is its natural security boundary. But two real risks remain:

1. **Downloaded malware samples.** Attackers often `wget/curl` to drop scripts, and Cowrie saves these files to `var/lib/cowrie/downloads/`. These are **real malicious files**. Fix: make sure they are never executed (Cowrie does not execute them; do not foolishly run them yourself); isolate the directory permissions; after analysis either retain them properly or clean them up; never touch them as root.

2. **Outbound traffic = the biggest risk.** What you really fear is this machine being used as a stepping stone to reach a C2, mine, or launch DDoS. Cowrie itself does not actually initiate these, but you need a backstop:
   - Process hardening: the systemd unit already adds `NoNewPrivileges` / `ProtectSystem=strict` / `PrivateTmp` / `CPUQuota` / `LimitNOFILE`, so even a breakout can hardly escalate or saturate bandwidth. **Done by the script.**
   - Tighten outbound: ideally deny outbound by default and allow only DNS + apt + your log exfiltration + ip-api lookups. The script does **not** forcibly cut outbound (to avoid killing the machine itself); see "Optional: tighten outbound" below.

### Optional: tighten outbound (manual, do it only after verifying)

```bash
sudo ufw default deny outgoing
sudo ufw allow out 53          # DNS
sudo ufw allow out 80,443/tcp  # apt / ip-api lookups / time sync
# Note: before cutting outbound, confirm apt, DNS and your scp backup are all on the allow list, or the machine goes "dark"
```

## 3. Data and legal (VPS-specific)

- **Provider terms (AUP)**: DigitalOcean / Vultr / Linode are relatively tolerant of honeypots, but they **will always forward abuse complaints to you**. Complaints may come from: your IP scanning others (usually a false positive, but you must be able to explain it), or sample downloads triggering an alert at the far end. Read the provider AUP before deploying; **be sure to respond promptly** to abuse emails (explain it is an academic honeypot, already isolated), or you may be suspended.
- **You are collecting real data from real attackers** (IPs, credentials, payloads). Using it for analysis is fine, but: do not use it to "strike back", do not freely forward samples, and obey local law. Within academic research it is legitimate.
- **Log exfiltration**: a VPS can be suspended by the provider or targeted by attackers at any time. Do not keep logs only on the machine; `scp` them elsewhere regularly (or configure a Cowrie output plugin to send them to another machine of yours).

## 4. Operations and monitoring

- **auditd**: installed by the script. Use it to record **your own** management logins, to keep "you" and "the attacker" distinguishable.
- **Disk**: Cowrie's downloaded samples + json logs grow fast; monitor `df -h` so a full disk does not stop Cowrie.
- **Reproducible**: the deployment script is itself "infrastructure as code"; if the machine is wrecked, just reinstall + run the script. A snapshot is even safer.

---

## 5. Why manual reproduction beats the .ova (for this project)

1. The VPS gives you a cloud image and **simply cannot import a VirtualBox .ova**, so manual install is the only viable path.
2. Manual install lets you build the hardening above (port separation, ufw, systemd hardening, auditd) directly into the process; the `.ova` is a black box you cannot change.
3. Reproducible and version-controlled: one run of `deploy_defense.sh` rebuilds the same environment on another VPS.

## 6. Deployment order cheat-sheet

```bash
# Defender machine (honeypot VPS)
#  0. First make sure your SSH public key is on the server (or you cannot get in after stage 1 disables password login)
#  1. Stage 1: install Cowrie + tools + hardening, add management port 2022 (22 untouched)
sudo ./defense/deploy_defense.sh
#  2. In another terminal verify: ssh -p 2022 user@honeypotIP   continue only if it works
#  3. Stage 2: hand 22 over to the honeypot, start capturing real attacks
sudo ./defense/deploy_defense.sh --cutover

# Attacker machine (another VPS)
sudo ./attack/deploy_attack.sh
./attack/simulate_attack.sh honeypot-public-IP 22
```

> One last emphasis on the ordering trap: stage 1 disables password login and keeps only keys. **Be sure to upload your public key before running it**, or you will lock yourself out.
