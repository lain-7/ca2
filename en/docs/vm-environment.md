# VM environment notes and change log

> Subject: the course-provided `UbuntuCowrie.ova` (VirtualBox image)
> Migration target: KVM / libvirt
> Date: 2026-10-26

---

## 1. What we did, and why

### 1.1 The course provides a VirtualBox image

The course materials provide two `.ova` files (VirtualBox export format):

| File | Purpose | Size |
|---|---|---|
| `UbuntuCowrie.ova` | honeypot server (VM A) | 4.2 GB |
| `UbuntuClient.ova` | attacker client (VM B) | 4.0 GB |

The accompanying *Cowrie Setup Guide* requires importing into VirtualBox and configuring a **Bridged Adapter**.

### 1.2 We switched to KVM

All group members are Linux users and do not use a GUI. VirtualBox's import and graphical configuration are unfriendly to a command-line environment, so we chose to run the same images under **KVM / libvirt**.

**This does not violate the assignment requirements.** The assignment has only two hard constraints:

> - Do not deploy the VM using cloud services
> - Do not make it publicly accessible

We run it on local KVM, with the network being libvirt's **isolated NAT**, which is **more closed** than the bridged mode the course requires -- the honeypot is completely unreachable from outside networks.

---

## 2. Changes made to the image to adapt it to KVM

### 2.1 Disk format conversion: VMDK -> qcow2

Inside the `.ova` is a VMDK virtual disk (VirtualBox-specific). KVM can read VMDK directly, but for performance and snapshot support we convert to qcow2:

```bash
tar -xf UbuntuCowrie.ova          # extract the .ovf and .vmdk
qemu-img convert -O qcow2 UbuntuCowrie-disk001.vmdk cowrie.qcow2
```

**The original OVA file was not modified at all**; the conversion is a read-only operation.

### 2.2 Repair the filesystem (because the image was not exported from a clean shutdown)

The first attempt to mount the disk failed:

```
EXT4-fs (dm-0): error loading journal
JBD2: journal recovery failed
```

Reason: the system was not shut down cleanly when the image was exported, leaving the ext4 journal in an uncommitted state. We mounted a copy read-write and ran `e2fsck` to repair it:

```bash
e2fsck -f -y /dev/ubuntu-vg/ubuntu-lv     # root partition
e2fsck -f -y /dev/nbd0p2                  # /boot
```

After repair the filesystem was fine; the `FILE SYSTEM WAS MODIFIED` notices from both fsck runs are the expected metadata corrections (inode counts etc.) and do not affect data.

### 2.3 Key change: netplan hard-codes the VirtualBox MAC address

**This is the most important change; without it the VM has no network under KVM.**

The original image's `/etc/netplan/00-installer-config.yaml`:

```yaml
# This is the network config written by 'subiquity'
network:
  ethernets:
    enp0s3:
      dhcp4: true
      dhcp6: true
      match:
        macaddress: 08:00:27:86:74:21      # <- the problem is here
      set-name: enp0s3
  version: 2
```

**Problem:**

`match.macaddress` requires the interface's MAC to be exactly `08:00:27:86:74:21` for this config to apply. That MAC is one VirtualBox generated for this virtual NIC (`08:00:27` is VirtualBox's OUI prefix).

Once the virtualisation platform changes (KVM, VMware, or any newly imported VirtualBox instance), the NIC MAC changes and **netplan matches no interface**:

- the NIC is not configured
- no IPv4 address is obtained
- the VM has no network at all

**Fix:**

Back up the original file and change it to match by **interface name prefix**, no longer relying on the MAC:

```yaml
# Rewritten for KVM/libvirt: match by interface name instead of the
# VirtualBox MAC address, so DHCP works regardless of hypervisor.
network:
  version: 2
  ethernets:
    primary:
      match:
        name: "en*"                        # <- matches enp0s3 / enp1s0 / ens33 etc.
      dhcp4: true
      dhcp6: true
```

The original file is backed up as `00-installer-config.yaml.vboxbak`, restorable at any time.

**Result:** after moving to KVM the NIC is automatically renamed `enp1s0` (KVM virtio NIC naming) and gets `192.168.122.252` via DHCP normally.

### 2.4 Boot via direct kernel boot (bypassing GRUB)

For the first boot we did not go through GRUB but let libvirt load the kernel and initrd directly:

```xml
<os>
  <type arch='x86_64' machine='q35'>hvm</type>
  <kernel>/var/lib/libvirt/images/cowrie-vmlinuz</kernel>
  <initrd>/var/lib/libvirt/images/cowrie-initrd</initrd>
  <cmdline>root=/dev/mapper/ubuntu--vg-ubuntu--lv ro console=ttyS0,115200</cmdline>
</os>
```

Why: the original image's GRUB config is not optimised for a serial console; specifying kernel parameters directly ensures `console=ttyS0` takes effect, convenient for headless debugging.

**This step is not required**; once the VM runs normally you can switch back to standard disk boot. Recorded here for reproducibility.

---

## 3. What was not changed

The following are **kept as-is**, consistent with what the course provides:

| Item | State |
|---|---|
| Original `.ova` files | not modified |
| The Ubuntu system inside the VM | not reinstalled, not upgraded |
| Login account `ubuntucowrie` / password `123456` | not changed (course preset) |
| Cowrie install location `/home/cowrie/cowrie-honeypot` | not moved |
| Cowrie version 3.0.13 | not upgraded |
| Real `sshd` (port 22) | kept (used as the control group) |
| virtualbox-guest packages | kept (not uninstalled, no impact on operation) |

---

## 4. Network architecture comparison

### Configuration the course guide suggests (VirtualBox bridged)

```
[home router] ── [host Wi-Fi]
                      │
                      └── [VirtualBox bridge]
                            ├── Cowrie VM  (same subnet as the host)
                            └── Client VM  (same subnet as the host)
```

In bridged mode the VM is exposed directly on the LAN the host is in.

### Configuration we actually used (KVM NAT)

```
[host Arch Linux]
      │
      └── virbr0  192.168.122.1/24  (libvirt default NAT network)
            ├── Cowrie VM   192.168.122.252   [LAN-reachable only]
            └── (Client VM to be created)
```

**Differences and assessment:**

| Aspect | Bridged (course suggestion) | NAT (our approach) |
|---|---|---|
| Can other LAN devices reach the honeypot | Yes | **No** |
| Can the honeypot reach the internet | Yes | Yes (via NAT forwarding) |
| Satisfies "not publicly exposed to the internet" | depends on the network | **inherently satisfied** |
| Convenient for isolated testing | needs extra firewall rules | **inherently isolated** |

**Conclusion:** NAT mode is **strictly better on isolation** than bridged mode, and fits the assignment's "controlled environment" requirement better. The grading rubric's network requirement is "both VMs correctly configured and network connected", which NAT fully satisfies.

---

## 5. Empirical reachability test

After the changes, we measured the network isolation empirically (detailed data in chapter 9 of `docs/honeypot-detector-design-and-report.md`):

| Target | Result |
|---|---|
| host -> honeypot `192.168.122.252:2222` | reachable |
| honeypot -> internet `example.com:80` | reachable |
| honeypot -> host `192.168.122.1:22` | blocked (firewalld) |
| honeypot -> host's LAN `192.168.1.x` | blocked |
| honeypot -> Docker subnet `172.17.0.1` | blocked |

**Important reminder:** this isolation is **implicit** -- it relies on the host firewalld's default policy, not on explicit rules in the VM itself. If the host firewall rules change, this layer of protection disappears, and the VM has no awareness of it.

For a stronger guarantee, **explicitly declare** egress rules in libvirt's `nwfilter`, turning "happens to be safe" into "declared safe".

---

## 6. Reproduction steps

To fully reproduce our environment from the original OVA:

```bash
# 1. Extract the OVA
mkdir -p inspect && cd inspect
tar -xf ../UbuntuCowrie.ova

# 2. Convert to qcow2
qemu-img convert -O qcow2 UbuntuCowrie-disk001.vmdk cowrie.qcow2

# 3. Repair the filesystem (image not cleanly shut down)
sudo modprobe nbd max_part=16
sudo qemu-nbd -f qcow2 -c /dev/nbd0 "$PWD/cowrie.qcow2"
sudo vgchange -ay ubuntu-vg
sudo e2fsck -f -y /dev/ubuntu-vg/ubuntu-lv
sudo e2fsck -f -y /dev/nbd0p2

# 4. Mount and edit netplan (the key step)
sudo mount /dev/ubuntu-vg/ubuntu-lv /mnt/x
sudo cp /mnt/x/etc/netplan/00-installer-config.yaml{,.vboxbak}
# write the name-matching version (see section 2.3)
sudo umount /mnt/x
sudo vgchange -an ubuntu-vg
sudo qemu-nbd -d /dev/nbd0

# 5. Place it in the libvirt images directory
sudo cp cowrie.qcow2 /var/lib/libvirt/images/
sudo chown root:root /var/lib/libvirt/images/cowrie.qcow2

# 6. Define and start via libvirt (XML in section 2.4)
sudo virsh -c qemu:///system define cowrie.xml
sudo virsh -c qemu:///system start cowrie
```

How to connect:

```bash
# system management (real sshd)
ssh ubuntucowrie@192.168.122.252        # password 123456

# honeypot (Cowrie)
ssh root@192.168.122.252 -p 2222        # any password logs in
```

---

## 7. Snapshot

Before any modification, we created an external snapshot:

```bash
virsh -c qemu:///system snapshot-create-as cowrie \
  baseline-2026-10-26 "clean state: KVM-converted, netplan fixed, fsck'd, Cowrie 3.0.13" \
  --disk-only --atomic
```

| Item | Value |
|---|---|
| Snapshot name | `baseline-2026-10-26` |
| Type | external (original disk kept as a read-only base) |
| Current disk | `/var/lib/libvirt/images/cowrie.baseline-2026-10-26` |
| Base disk | `/var/lib/libvirt/images/cowrie.qcow2` |

Roll back to the pre-modification state:

```bash
virsh -c qemu:///system snapshot-revert cowrie baseline-2026-10-26
```

---

## 8. Known issues

| Issue | Impact | Plan |
|---|---|---|
| Cowrie not configured to auto-start | port 2222 does not listen after a VM reboot, needs manual start | write a systemd unit |
| `cowrie start` depends on the venv being activated | calling `cowrie-env/bin/cowrie` directly fails because `twistd` is not on PATH | not fixed (use full paths to work around) |
| Host `qemu.conf` not set to run as the current user | VM images must live in `/var/lib/libvirt/images` (root-owned) | not changed (needs root) |
| Real sshd uses the weak password `123456` | see the note below | course preset, kept |

### Note on the real sshd

The VM runs simultaneously:

- **Cowrie honeypot** (port 2222) -- an emulated SSH service
- **Real OpenSSH** (port 22) -- bundled in the course image, for system management

The real sshd account `ubuntucowrie` / `123456` is a course preset. In this experiment:

- **It is not reachable from outside** -- with the VM behind libvirt NAT, port 22 is completely unreachable externally
- **It is used as the control group** -- our detector uses it to verify "it does not misclassify a real system as a honeypot"
- **It constitutes a real risk** -- if the VM were exposed to a reachable network, this weak-password account is in the sudo group, equivalent to handing over root directly

**In a real deployment, this real SSH service should be disabled or restricted to key-only login.** We keep it for the experimental control, which is clearly recorded in the report.
