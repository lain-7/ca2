#!/bin/bash
# ============================================================================
# Defence machine (honeypot) one-shot deployment script  --  Ubuntu 24.04 LTS / VPS such as DigitalOcean
#
# Purpose: manually reproduce the Cowrie honeypot environment on a clean VPS and apply basic host hardening.
#          It does not include "restoring the school-provided .ova" -- a .ova cannot be used on a VPS,
#          so this installs from scratch by hand, which is more controllable and reproducible.
#
# Port plan (maximise capture of real attacks):
#   22   -- exposed to the internet, nat-redirected to 2222 and handed to Cowrie (catches real scans)
#   2222 -- the port Cowrie actually listens on; the firewall only allows connections redirected from 22,
#           direct external connections to 2222 are dropped (avoids exposing Cowrie's default port as a tell)
#   2022 -- your own management SSH (real sshd), key-only login
#
# Two-stage lockout prevention:
#   Stage 1 (default): install Cowrie + tools, add management SSH on 2022 as well (22 still usable),
#                      do not touch 22 or bring Cowrie live. Afterwards verify with ssh -p 2022.
#   Stage 2 (--cutover): run only after confirming 2022 works, remove the real sshd on 22,
#                      and redirect 22 to Cowrie. Only now do real attacks reach the honeypot.
# ============================================================================

set -euo pipefail

# ==================== Configuration ====================
ADMIN_PORT=2022                 # new management SSH port (log in with it after cutover)
COWRIE_PORT=2222                # Cowrie listen port
PUBLIC_PORT=22                  # public-facing port redirected to Cowrie
COWRIE_USER=cowrie              # dedicated non-root user that runs Cowrie
COWRIE_VERSION=3.0.13           # Cowrie version matching the original lab environment (PyPI)
COWRIE_HOME="/home/$COWRIE_USER"
COWRIE_DIR="$COWRIE_HOME/cowrie"
UFW_BEFORE="/etc/ufw/before.rules"
NAT_MARK="# cowrie-honeypot-nat"   # idempotency marker in before.rules

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ==================== Helper functions ====================
log()  { echo "[$(date '+%F %T')] [$1] ${*:2}"; }
die()  { log ERROR "$*"; exit 1; }

require_root() {
    [ "$(id -u)" -eq 0 ] || die "Please run as root: sudo $0 $*"
}

require_ubuntu() {
    command -v apt-get >/dev/null 2>&1 || die "This script targets Ubuntu/Debian (apt); the current system is not supported"
}

# ==================== Stage 1: install and basic hardening ====================

install_packages() {
    log INFO "Updating index and installing dependencies..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    # Cowrie build deps + analysis tool deps (jq/curl) + firewall/audit
    apt-get install -y \
        git python3 python3-venv python3-dev \
        libssl-dev libffi-dev build-essential \
        jq curl ufw auditd
}

create_cowrie_user() {
    if id "$COWRIE_USER" >/dev/null 2>&1; then
        log INFO "User $COWRIE_USER already exists, skipping creation"
    else
        log INFO "Creating dedicated non-root user $COWRIE_USER..."
        adduser --disabled-password --gecos "" "$COWRIE_USER"
    fi
}

install_cowrie() {
    # The old script left a git source checkout (the new Cowrie layout has changed and cannot be used as-is).
    # That checkout never started successfully and holds no captured data, so just clean it up.
    if [ -d "$COWRIE_DIR/.git" ]; then
        log WARN "Detected a Cowrie source checkout from the old script; cleaning up and switching to pip install: $COWRIE_DIR"
        rm -rf "$COWRIE_DIR"
    fi
    log INFO "pip-installing Cowrie $COWRIE_VERSION as $COWRIE_USER (idempotent)..."
    sudo -u "$COWRIE_USER" -H bash <<EOF
set -e
mkdir -p "$COWRIE_DIR"
cd "$COWRIE_DIR"
[ -x cowrie-env/bin/python ] || python3 -m venv cowrie-env
cowrie-env/bin/pip install --upgrade pip wheel
# Pin the version matching the original lab environment (the patches under tools/ are based on it too)
cowrie-env/bin/pip install "cowrie==$COWRIE_VERSION"
EOF
    sudo -u "$COWRIE_USER" test -x "$COWRIE_DIR/cowrie-env/bin/cowrie" \
        || die "Cowrie install failed (cowrie-env/bin/cowrie missing); check the pip errors above"
}

configure_cowrie() {
    # Cowrie 3.x keeps config, pid and logs relative to the working directory:
    #   ./etc/cowrie.cfg  ./var/run/cowrie.pid  ./var/log/cowrie/
    # `cowrie init` generates etc/cowrie.cfg from the packaged defaults and creates var/;
    # `cowrie start` refuses to run on an uninitialised directory. The default SSH port is 2222.
    log INFO "Initialising the Cowrie working directory (cowrie init)..."
    sudo -u "$COWRIE_USER" -H bash <<EOF
set -e
cd "$COWRIE_DIR"
[ -f etc/cowrie.cfg ] || cowrie-env/bin/cowrie init
EOF
    sudo -u "$COWRIE_USER" test -f "$COWRIE_DIR/etc/cowrie.cfg" \
        || die "Cowrie init failed (etc/cowrie.cfg missing)"
    log INFO "To customise the hostname etc., edit $COWRIE_DIR/etc/cowrie.cfg then systemctl restart cowrie"
}

install_systemd_unit() {
    log INFO "Installing the Cowrie systemd service (with process hardening)..."
    cat > /etc/systemd/system/cowrie.service <<EOF
[Unit]
Description=Cowrie SSH Honeypot
After=network.target

[Service]
Type=forking
User=$COWRIE_USER
Group=$COWRIE_USER
WorkingDirectory=$COWRIE_DIR
# the cowrie launcher uses execvp to find twistd via PATH, so the venv bin must be on PATH
Environment=PATH=$COWRIE_DIR/cowrie-env/bin:/usr/local/bin:/usr/bin:/bin
Environment=AUTHBIND_ENABLED=no
ExecStart=$COWRIE_DIR/cowrie-env/bin/cowrie start
ExecStop=$COWRIE_DIR/cowrie-env/bin/cowrie stop
PIDFile=$COWRIE_DIR/var/run/cowrie.pid
Restart=on-failure

# -- process hardening: even if the honeypot is compromised, privilege escalation or system contamination is hard --
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=$COWRIE_DIR
ProtectHome=false
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true
# resource caps: prevent the host being saturated if abused as a DDoS amplifier
LimitNOFILE=4096
CPUQuota=50%

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable cowrie.service
    systemctl restart cowrie.service || log WARN "Cowrie failed to start; check manually: journalctl -u cowrie"
}

setup_analysis_tools() {
    log INFO "Preparing log analysis tools (setting executable permission)..."
    chmod +x "$SCRIPT_DIR"/*.sh "$SCRIPT_DIR"/*.py 2>/dev/null || true
    log INFO "Analysis tools ready: $SCRIPT_DIR/analyze_logs.sh"
    log INFO "Cowrie log path: $COWRIE_DIR/var/log/cowrie/cowrie.json"
}

harden_ssh_phase1() {
    log INFO "Adding port $ADMIN_PORT for management SSH (keeping 22 to avoid lockout)..."
    local cfg=/etc/ssh/sshd_config.d/99-honeypot-admin.conf
    cat > "$cfg" <<EOF
# Honeypot host management SSH: stage 1 listens on both 22 and $ADMIN_PORT
Port 22
Port $ADMIN_PORT
PermitRootLogin prohibit-password
PasswordAuthentication no
PubkeyAuthentication yes
EOF
    log WARN "Set PasswordAuthentication no -- make sure your SSH public key is configured or you will be locked out!"
    systemctl restart ssh || systemctl restart sshd || die "sshd restart failed, check the config"
}

firewall_base() {
    log INFO "Configuring ufw: deny incoming by default, allow management and honeypot ports..."
    ufw --force reset >/dev/null
    ufw default deny incoming
    ufw default allow outgoing          # allow outgoing by default (see docs to tighten; do not cut it before verifying)
    ufw allow "$ADMIN_PORT"/tcp comment 'management SSH'
    ufw allow 22/tcp comment 'real sshd before cutover'
    # do not allow $COWRIE_PORT: after cutover, cutover_filter allows only redirected connections
    ufw --force enable
    ufw status verbose || true
}

phase1() {
    require_ubuntu
    install_packages
    create_cowrie_user
    install_cowrie
    configure_cowrie
    install_systemd_unit
    setup_analysis_tools
    harden_ssh_phase1
    firewall_base
    cat <<EOF

============================================================
Stage 1 complete. Now:
  1) Open another terminal and verify login via the new port:
        ssh -p $ADMIN_PORT <user>@<this host IP>
  2) Once login works, come back and run stage 2 (hand 22 over to the honeypot):
        sudo $0 --cutover

Right now port 22 is still your real sshd, with Cowrie on $COWRIE_PORT.
Real attacks will not reach the honeypot until you complete --cutover.
============================================================
EOF
}

# ==================== Stage 2: hand 22 over to the honeypot ====================

cutover_ssh() {
    log INFO "Removing the real sshd on 22, keeping only management port $ADMIN_PORT..."
    local cfg=/etc/ssh/sshd_config.d/99-honeypot-admin.conf
    cat > "$cfg" <<EOF
# Honeypot host management SSH: after cutover, listen only on $ADMIN_PORT
Port $ADMIN_PORT
PermitRootLogin prohibit-password
PasswordAuthentication no
PubkeyAuthentication yes
EOF
    systemctl restart ssh || systemctl restart sshd || die "sshd restart failed"
}

cutover_nat() {
    log INFO "Setting up nat redirect: public 22 -> Cowrie $COWRIE_PORT..."
    if grep -q "$NAT_MARK" "$UFW_BEFORE"; then
        log INFO "nat rule already present, skipping"
        return
    fi
    # Insert a nat table PREROUTING redirect at the top of before.rules
    local tmp
    tmp="$(mktemp)"
    cat > "$tmp" <<EOF
$NAT_MARK
*nat
:PREROUTING ACCEPT [0:0]
-A PREROUTING -p tcp --dport $PUBLIC_PORT -j REDIRECT --to-port $COWRIE_PORT
COMMIT
$NAT_MARK end

EOF
    cat "$UFW_BEFORE" >> "$tmp"
    cp "$UFW_BEFORE" "$UFW_BEFORE.bak.$(date +%s)"
    mv "$tmp" "$UFW_BEFORE"
    ufw reload
}

cutover_filter() {
    # Once redirected, packets reaching the INPUT chain already have destination port $COWRIE_PORT, so it must be allowed;
    # but only connections whose original destination port was $PUBLIC_PORT are allowed; direct external connections to $COWRIE_PORT are all dropped.
    local tag="cowrie-redirect-only"
    local anchor='-A ufw-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT'
    local rule="-A ufw-before-input -p tcp --dport $COWRIE_PORT -m conntrack --ctstate DNAT --ctorigdstport $PUBLIC_PORT -m comment --comment $tag -j ACCEPT"

    # Clean up the "directly allow $COWRIE_PORT" rule left by the old script
    ufw --force delete allow "$COWRIE_PORT"/tcp >/dev/null 2>&1 || true

    if grep -q -- "$tag" "$UFW_BEFORE"; then
        log INFO "The redirect-only filter rule for 2222 already exists, skipping"
    else
        grep -qxF -- "$anchor" "$UFW_BEFORE" \
            || die "Anchor line not found in before.rules; add this to the filter section manually: $rule"
        log INFO "Restricting $COWRIE_PORT to accept only connections redirected from $PUBLIC_PORT..."
        cp "$UFW_BEFORE" "$UFW_BEFORE.bak.$(date +%s)"
        sed -i "\|^${anchor}\$|a ${rule}" "$UFW_BEFORE"
    fi
    ufw reload
}

verify_cutover() {
    log INFO "Currently listening ports:"
    ss -tulnp 2>/dev/null | grep -E ":($ADMIN_PORT|$COWRIE_PORT|22)\b" || true
    cat <<EOF

============================================================
Stage 2 complete:
  - Management SSH: port $ADMIN_PORT (ssh -p $ADMIN_PORT)
  - Public 22: redirected to Cowrie, now capturing real attacks
  - Watch the honeypot live log:
        sudo tail -f $COWRIE_DIR/var/log/cowrie/cowrie.json
  - Analyse logs:
        cd $SCRIPT_DIR && ./analyze_logs.sh $COWRIE_DIR/var/log/cowrie
Reminder: scp the logs elsewhere for backup regularly, and watch for abuse emails from your provider.
============================================================
EOF
}

cutover() {
    require_ubuntu
    log WARN "About to hand 22 over to the honeypot. Confirm you can already log in with ssh -p $ADMIN_PORT!"
    read -r -p "Verified that $ADMIN_PORT can log in? Type yes to continue: " ans
    [ "$ans" = "yes" ] || die "Cancelled. Verify the management port first."
    cutover_ssh
    cutover_nat
    cutover_filter
    verify_cutover
}

usage() {
    cat <<EOF
Usage:
  sudo $0              Stage 1: install Cowrie + tools + basic hardening (does not touch 22)
  sudo $0 --cutover    Stage 2: hand 22 over to the honeypot (be sure $ADMIN_PORT login works first)
  $0 --help            show this help
EOF
}

# ==================== Entry point ====================
main() {
    case "${1:-}" in
        ""|--phase1) require_root "$@"; phase1 ;;
        --cutover)   require_root "$@"; cutover ;;
        --help|-h)   usage ;;
        *)           usage; exit 1 ;;
    esac
}

main "$@"
