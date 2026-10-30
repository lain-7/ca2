#!/bin/bash
# ============================================================================
# Cowrie honeypot log analysis script
# Features:
#   1. Parse Cowrie JSON logs
#   2. Extract login attempts, successful logins, command executions
#   3. Call the IP tracing tool to obtain attacker information
#   4. Generate a structured analysis report
# ============================================================================

set -u

# ==================== Configuration ====================
# The first argument may be a log directory or a specific JSON log file; the default directory is used if omitted.
COWRIE_LOG_INPUT="${1:-/home/cowrie/cowrie/var/log/cowrie}"
OUTPUT_DIR="./reports"                                     # output directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IP_TRACKER="$SCRIPT_DIR/ip_tracker.py"                     # IP tracing script
REPORT_GENERATOR="$SCRIPT_DIR/report_generator.py"         # report generator
VISUALIZER="$SCRIPT_DIR/visualizer.py"                     # visualisation script

# Resolve the log file:
#   - a file was passed -> use it directly
#   - a directory was passed -> take the newest cowrie.json* log inside it
if [ -f "$COWRIE_LOG_INPUT" ]; then
    COWRIE_JSON_LOG="$COWRIE_LOG_INPUT"
elif [ -d "$COWRIE_LOG_INPUT" ]; then
    COWRIE_JSON_LOG=$(find "$COWRIE_LOG_INPUT" -name "cowrie.json*" -type f | sort -r | head -1)
else
    COWRIE_JSON_LOG=""
fi

# ==================== Colour definitions ====================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# ==================== Function definitions ====================

print_banner() {
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║        Cowrie Honeypot Log Analysis Tool v1.0              ║"
    echo "║        Honeypot Log Analysis Tool                          ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

log_msg() {
    local level="$1"
    shift
    local msg="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "[$timestamp] [$level] $msg"
}

check_dependencies() {
    local missing=()

    for cmd in jq python3 curl; do
        if ! command -v $cmd &> /dev/null; then
            missing+=("$cmd")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        log_msg "ERROR" "Missing dependencies: ${missing[*]}"
        log_msg "INFO" "Install with: sudo pacman -S jq python curl"
        exit 1
    fi

    # Check the IP tracing script
    if [ ! -x "$IP_TRACKER" ]; then
        log_msg "ERROR" "IP tracing script missing or not executable: $IP_TRACKER"
        exit 1
    fi

    # Check the report generator
    if [ ! -f "$REPORT_GENERATOR" ]; then
        log_msg "WARN" "Report generator not found: $REPORT_GENERATOR"
        log_msg "INFO" "The report generation step will be skipped"
    fi

    # Initialise the lib directory
    local lib_dir="$SCRIPT_DIR/lib"
    if [ ! -d "$lib_dir" ]; then
        mkdir -p "$lib_dir" || {
            log_msg "WARN" "Could not create the lib directory; caching may be unavailable"
        }
    fi
}

parse_cowrie_log() {
    local logfile="$1"
    local output_prefix="$2"

    log_msg "INFO" "Parsing Cowrie log: $logfile"

    # Extract all login attempts
    log_msg "INFO" "Extracting login attempts..."
    jq -r 'select(.eventid == "cowrie.login.failed" or .eventid == "cowrie.login.success") |
           [.timestamp, .src_ip, .username, .password, .eventid] | @tsv' \
           "$logfile" > "$output_prefix.logins.tsv" 2>/dev/null || true

    local login_count=$(wc -l < "$output_prefix.logins.tsv")
    log_msg "INFO" "Found $login_count login attempts"

    # Extract successful logins
    log_msg "INFO" "Extracting successful logins..."
    jq -r 'select(.eventid == "cowrie.login.success") |
           [.timestamp, .src_ip, .username, .password, .session] | @tsv' \
           "$logfile" > "$output_prefix.successful_logins.tsv" 2>/dev/null || true

    local success_count=$(wc -l < "$output_prefix.successful_logins.tsv")
    log_msg "INFO" "Found $success_count successful logins"

    # Extract command executions
    log_msg "INFO" "Extracting command executions..."
    jq -r 'select(.eventid == "cowrie.command.input") |
           [.timestamp, .src_ip, .session, .input] | @tsv' \
           "$logfile" > "$output_prefix.commands.tsv" 2>/dev/null || true

    local cmd_count=$(wc -l < "$output_prefix.commands.tsv")
    log_msg "INFO" "Found $cmd_count command executions"

    # Extract the unique IP list
    log_msg "INFO" "Extracting source IPs..."
    jq -r 'select(.src_ip != null) | .src_ip' "$logfile" | sort -u > "$output_prefix.ips.txt" 2>/dev/null || true

    local ip_count=$(wc -l < "$output_prefix.ips.txt")
    log_msg "INFO" "Found $ip_count unique IP addresses"

    # Count the most frequent usernames
    log_msg "INFO" "Counting top usernames..."
    jq -r 'select(.username != null) | .username' "$logfile" | \
        sort | uniq -c | sort -rn | head -20 > "$output_prefix.top_usernames.txt" 2>/dev/null || true

    # Count the most frequent passwords
    log_msg "INFO" "Counting top passwords..."
    jq -r 'select(.password != null) | .password' "$logfile" | \
        sort | uniq -c | sort -rn | head -20 > "$output_prefix.top_passwords.txt" 2>/dev/null || true

    # Count the most frequent commands
    log_msg "INFO" "Counting top commands..."
    jq -r 'select(.input != null) | .input' "$logfile" | \
        sort | uniq -c | sort -rn | head -20 > "$output_prefix.top_commands.txt" 2>/dev/null || true
}

enrich_ips() {
    local ip_file="$1"
    local output_file="$2"

    if [ ! -s "$ip_file" ]; then
        log_msg "WARN" "IP list is empty, skipping tracing"
        return
    fi

    log_msg "INFO" "Starting IP tracing analysis..."
    log_msg "INFO" "This may take a few minutes..."

    # Note: only the JSON result goes to the file; progress goes to stderr/terminal,
    # otherwise progress text would mix into the JSON and break later jq parsing.
    if "$IP_TRACKER" --file "$ip_file" --json > "$output_file"; then
        log_msg "INFO" "IP tracing complete, result saved to: $output_file"
    else
        log_msg "ERROR" "IP tracing failed"
    fi
}

generate_summary_report() {
    local prefix="$1"
    local output="$prefix.summary.txt"

    log_msg "INFO" "Generating summary report..."

    {
        echo "=========================================="
        echo "     Cowrie Honeypot Log Analysis Summary"
        echo "=========================================="
        echo ""
        echo "Generated: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Analysed log: $COWRIE_JSON_LOG"
        echo ""
        echo "==================== Attack Overview ===================="

        # Login attempt statistics
        if [ -f "$prefix.logins.tsv" ] && [ -s "$prefix.logins.tsv" ]; then
            local total_attempts=$(wc -l < "$prefix.logins.tsv")
            local failed_attempts=$(awk '$5 ~ /cowrie.login.failed/ {count++} END {print count+0}' "$prefix.logins.tsv")
            local success_attempts=$(awk '$5 ~ /cowrie.login.success/ {count++} END {print count+0}' "$prefix.logins.tsv")

            echo "Total login attempts: $total_attempts"
            echo "  |- failed: $failed_attempts"
            echo "  \\- succeeded: $success_attempts"

            if [ $total_attempts -gt 0 ]; then
                local success_rate=$(awk "BEGIN {printf \"%.2f\", ($success_attempts / $total_attempts) * 100}")
                echo "Success rate: $success_rate%"
            fi
        fi

        echo ""

        # Command execution statistics
        if [ -f "$prefix.commands.tsv" ]; then
            local total_cmds=$(wc -l < "$prefix.commands.tsv")
            echo "Total commands executed: $total_cmds"

            # Number of unique commands
            local unique_cmds=$(cut -f4 "$prefix.commands.tsv" | sort -u | wc -l)
            echo "Unique commands: $unique_cmds"
        fi

        echo ""

        # IP statistics
        if [ -f "$prefix.ips.txt" ]; then
            local total_ips=$(wc -l < "$prefix.ips.txt")
            echo "Number of source IPs: $total_ips"

            # Count internal/external IPs (assuming lookup results exist)
            if [ -f "$prefix.ip_enrichment.json" ]; then
                local internal_count=$(jq '[.[] | select(.is_internal == true)] | length' "$prefix.ip_enrichment.json")
                local external_count=$(jq '[.[] | select(.is_internal == false)] | length' "$prefix.ip_enrichment.json")
                echo "  |- internal IPs: $internal_count"
                echo "  \\- external IPs: $external_count"
            fi
        fi

        echo ""
        echo "==================== TOP 10 Usernames ===================="
        if [ -f "$prefix.top_usernames.txt" ]; then
            head -10 "$prefix.top_usernames.txt" | awk '{printf "  %6s x   %s\n", $1, $2}'
        fi

        echo ""
        echo "==================== TOP 10 Passwords ===================="
        if [ -f "$prefix.top_passwords.txt" ]; then
            head -10 "$prefix.top_passwords.txt" | awk '{printf "  %6s x   %s\n", $1, $2}'
        fi

        echo ""
        echo "==================== TOP 10 Commands ===================="
        if [ -f "$prefix.top_commands.txt" ]; then
            head -10 "$prefix.top_commands.txt" | awk '{printf "  %6s x   %s\n", $1, $2}'
        fi

        echo ""
        echo "==================== Source Geographic Distribution ===================="
        if [ -f "$prefix.ip_enrichment.json" ]; then
            echo "By country:"
            jq -r '.[] | select(.is_internal == false) | .country' "$prefix.ip_enrichment.json" | \
                sort | uniq -c | sort -rn | head -10 | awk '{printf "  %6s x   %s\n", $1, $2}'

            echo ""
            echo "Threat level distribution:"
            jq -r '.[] | .threat_level' "$prefix.ip_enrichment.json" | \
                sort | uniq -c | sort -rn | awk '{printf "  %6s x   %s\n", $1, $2}'
        fi

        echo ""
        echo "==================== Detailed Result Files ===================="
        echo "  - all login attempts: $prefix.logins.tsv"
        echo "  - successful logins: $prefix.successful_logins.tsv"
        echo "  - command executions: $prefix.commands.tsv"
        echo "  - IP list: $prefix.ips.txt"
        echo "  - IP tracing result: $prefix.ip_enrichment.json"
        echo "  - username stats: $prefix.top_usernames.txt"
        echo "  - password stats: $prefix.top_passwords.txt"
        echo "  - command stats: $prefix.top_commands.txt"
        echo ""
        echo "=========================================="

    } > "$output"

    log_msg "INFO" "Summary report generated: $output"

    # Print to the terminal
    echo ""
    cat "$output"
}

main() {
    print_banner

    log_msg "INFO" "========== Log analysis start =========="

    # Check dependencies
    check_dependencies

    # Check the log file
    if [ -z "$COWRIE_JSON_LOG" ] || [ ! -f "$COWRIE_JSON_LOG" ]; then
        log_msg "ERROR" "No Cowrie JSON log file found"
        log_msg "INFO" "Specify the log directory: $0 /path/to/cowrie/log/dir"
        exit 1
    fi

    log_msg "INFO" "Log file: $COWRIE_JSON_LOG"

    # Create the output directory
    mkdir -p "$OUTPUT_DIR"

    # Build the output file prefix (timestamp based)
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local output_prefix="$OUTPUT_DIR/analysis_$timestamp"

    log_msg "INFO" "Output directory: $OUTPUT_DIR"
    log_msg "INFO" "Output prefix: analysis_$timestamp"

    echo ""

    # Parse the log
    parse_cowrie_log "$COWRIE_JSON_LOG" "$output_prefix"

    echo ""

    # IP tracing
    if [ -s "$output_prefix.ips.txt" ]; then
        enrich_ips "$output_prefix.ips.txt" "$output_prefix.ip_enrichment.json"
    fi

    echo ""

    # Generate the summary report
    generate_summary_report "$output_prefix"

    echo ""

    # Generate visualisation charts
    if [ -x "$VISUALIZER" ]; then
        log_msg "INFO" "Generating data visualisation charts..."
        "$VISUALIZER" "$output_prefix"
        echo ""
    fi

    log_msg "INFO" "========== Analysis complete =========="

    # If the report generator exists, call it
    if [ -x "$REPORT_GENERATOR" ]; then
        echo ""
        log_msg "INFO" "Generating detailed report..."
        "$REPORT_GENERATOR" "$output_prefix"
    fi
}

main "$@"
