#!/bin/bash
# ============================================================================
# Attacker machine (client / VM B) one-shot environment setup  --  Ubuntu 24.04 LTS / apt
#
# Purpose: install the tools simulate_attack.sh needs on the attacker machine, then self-check.
#          Only for a "controlled exercise" -- simulated logins against your own honeypot, nothing else.
#
# Kept separate from the defence machine: this script only installs attacker-side dependencies; do not run it on the honeypot machine.
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ATTACK_SCRIPT="$SCRIPT_DIR/simulate_attack.sh"
CREDS_FILE="$SCRIPT_DIR/payloads/common_creds.txt"

log()  { echo "[$(date '+%F %T')] [$1] ${*:2}"; }
die()  { log ERROR "$*"; exit 1; }

require_root() {
    [ "$(id -u)" -eq 0 ] || die "Please run as root: sudo $0"
}

install_packages() {
    command -v apt-get >/dev/null 2>&1 || die "This script targets Ubuntu/Debian (apt)"
    log INFO "Installing attack simulation dependencies: sshpass / openssh-client / coreutils ..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y sshpass openssh-client coreutils
}

prepare_scripts() {
    if [ ! -f "$ATTACK_SCRIPT" ]; then
        die "Cannot find $ATTACK_SCRIPT
The attacker machine needs the complete attack/ directory (including simulate_attack.sh and payloads/), not just this script.
Copy the whole attack/ directory (or the whole repository) to the attacker machine and run from inside attack/:
    cd <repo>/attack
    sudo ./deploy_attack.sh"
    fi
    chmod +x "$ATTACK_SCRIPT"
    [ -f "$CREDS_FILE" ] || die "Cannot find credential list $CREDS_FILE (payloads/ was not copied along)"
    log INFO "Attack script ready, credential list has $(grep -c ':' "$CREDS_FILE") pairs"
}

selfcheck() {
    log INFO "Self-checking tool availability..."
    for c in sshpass ssh timeout; do
        command -v "$c" >/dev/null 2>&1 && log INFO "  $c OK" || die "Missing $c"
    done
}

main() {
    require_root
    install_packages
    prepare_scripts
    selfcheck
    cat <<EOF

============================================================
Attacker environment ready. Run a controlled exercise against your own honeypot:
    cd $SCRIPT_DIR
    ./simulate_attack.sh <honeypot IP> <port>

For example, honeypot on VPS port 22 (already handed over to Cowrie):
    ./simulate_attack.sh <honeypot public IP> 22

Test only against your own group's honeypot; never use this against any other target.
============================================================
EOF
}

main "$@"
