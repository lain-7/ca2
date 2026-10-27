#!/bin/bash
# ============================================================================
# Cowrie 蜜罐日志分析脚本
# 功能：
#   1. 解析 Cowrie JSON 日志
#   2. 提取登录尝试、成功登录、命令执行记录
#   3. 调用 IP 溯源工具获取攻击者信息
#   4. 生成结构化的分析报告
# ============================================================================

set -u

# ==================== 配置区 ====================
# 第一个参数可以是日志目录，也可以直接是某个 JSON 日志文件；不传则用默认目录。
COWRIE_LOG_INPUT="${1:-/home/cowrie/cowrie/var/log/cowrie}"
OUTPUT_DIR="./reports"                                     # 输出目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IP_TRACKER="$SCRIPT_DIR/ip_tracker.py"                     # IP 溯源脚本
REPORT_GENERATOR="$SCRIPT_DIR/report_generator.py"         # 报告生成器
VISUALIZER="$SCRIPT_DIR/visualizer.py"                     # 可视化脚本

# 解析日志文件：
#   - 传入文件 → 直接使用该文件
#   - 传入目录 → 取其中最新的 cowrie.json* 日志
if [ -f "$COWRIE_LOG_INPUT" ]; then
    COWRIE_JSON_LOG="$COWRIE_LOG_INPUT"
elif [ -d "$COWRIE_LOG_INPUT" ]; then
    COWRIE_JSON_LOG=$(find "$COWRIE_LOG_INPUT" -name "cowrie.json*" -type f | sort -r | head -1)
else
    COWRIE_JSON_LOG=""
fi

# ==================== 颜色定义 ====================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# ==================== 函数定义 ====================

print_banner() {
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║        Cowrie 蜜罐日志分析工具 v1.0                       ║"
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
        log_msg "ERROR" "缺少依赖: ${missing[*]}"
        log_msg "INFO" "请安装: sudo pacman -S jq python curl"
        exit 1
    fi

    # 检查 IP 溯源脚本
    if [ ! -x "$IP_TRACKER" ]; then
        log_msg "ERROR" "IP 溯源脚本不存在或不可执行: $IP_TRACKER"
        exit 1
    fi

    # 检查报告生成器
    if [ ! -f "$REPORT_GENERATOR" ]; then
        log_msg "WARN" "报告生成器不存在: $REPORT_GENERATOR"
        log_msg "INFO" "将跳过报告生成步骤"
    fi

    # 初始化 lib 目录
    local lib_dir="$SCRIPT_DIR/lib"
    if [ ! -d "$lib_dir" ]; then
        mkdir -p "$lib_dir" || {
            log_msg "WARN" "无法创建 lib 目录，缓存功能可能不可用"
        }
    fi
}

parse_cowrie_log() {
    local logfile="$1"
    local output_prefix="$2"

    log_msg "INFO" "解析 Cowrie 日志: $logfile"

    # 提取所有登录尝试
    log_msg "INFO" "提取登录尝试记录..."
    jq -r 'select(.eventid == "cowrie.login.failed" or .eventid == "cowrie.login.success") |
           [.timestamp, .src_ip, .username, .password, .eventid] | @tsv' \
           "$logfile" > "$output_prefix.logins.tsv" 2>/dev/null || true

    local login_count=$(wc -l < "$output_prefix.logins.tsv")
    log_msg "INFO" "发现 $login_count 次登录尝试"

    # 提取成功登录
    log_msg "INFO" "提取成功登录记录..."
    jq -r 'select(.eventid == "cowrie.login.success") |
           [.timestamp, .src_ip, .username, .password, .session] | @tsv' \
           "$logfile" > "$output_prefix.successful_logins.tsv" 2>/dev/null || true

    local success_count=$(wc -l < "$output_prefix.successful_logins.tsv")
    log_msg "INFO" "发现 $success_count 次成功登录"

    # 提取命令执行记录
    log_msg "INFO" "提取命令执行记录..."
    jq -r 'select(.eventid == "cowrie.command.input") |
           [.timestamp, .src_ip, .session, .input] | @tsv' \
           "$logfile" > "$output_prefix.commands.tsv" 2>/dev/null || true

    local cmd_count=$(wc -l < "$output_prefix.commands.tsv")
    log_msg "INFO" "发现 $cmd_count 条命令执行记录"

    # 提取唯一 IP 列表
    log_msg "INFO" "提取攻击源 IP..."
    jq -r 'select(.src_ip != null) | .src_ip' "$logfile" | sort -u > "$output_prefix.ips.txt" 2>/dev/null || true

    local ip_count=$(wc -l < "$output_prefix.ips.txt")
    log_msg "INFO" "发现 $ip_count 个唯一 IP 地址"

    # 统计高频用户名
    log_msg "INFO" "统计高频用户名..."
    jq -r 'select(.username != null) | .username' "$logfile" | \
        sort | uniq -c | sort -rn | head -20 > "$output_prefix.top_usernames.txt" 2>/dev/null || true

    # 统计高频密码
    log_msg "INFO" "统计高频密码..."
    jq -r 'select(.password != null) | .password' "$logfile" | \
        sort | uniq -c | sort -rn | head -20 > "$output_prefix.top_passwords.txt" 2>/dev/null || true

    # 统计高频命令
    log_msg "INFO" "统计高频命令..."
    jq -r 'select(.input != null) | .input' "$logfile" | \
        sort | uniq -c | sort -rn | head -20 > "$output_prefix.top_commands.txt" 2>/dev/null || true
}

enrich_ips() {
    local ip_file="$1"
    local output_file="$2"

    if [ ! -s "$ip_file" ]; then
        log_msg "WARN" "IP 列表为空，跳过溯源"
        return
    fi

    log_msg "INFO" "开始 IP 溯源分析..."
    log_msg "INFO" "这可能需要几分钟时间..."

    # 注意：仅把 JSON 结果写入文件，进度信息走 stderr 到终端，
    # 否则进度文本会混进 JSON 导致后续 jq 解析失败。
    if "$IP_TRACKER" --file "$ip_file" --json > "$output_file"; then
        log_msg "INFO" "IP 溯源完成，结果保存到: $output_file"
    else
        log_msg "ERROR" "IP 溯源失败"
    fi
}

generate_summary_report() {
    local prefix="$1"
    local output="$prefix.summary.txt"

    log_msg "INFO" "生成摘要报告..."

    {
        echo "=========================================="
        echo "     Cowrie 蜜罐日志分析摘要报告"
        echo "=========================================="
        echo ""
        echo "生成时间: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "分析日志: $COWRIE_JSON_LOG"
        echo ""
        echo "==================== 攻击概览 ===================="

        # 登录尝试统计
        if [ -f "$prefix.logins.tsv" ] && [ -s "$prefix.logins.tsv" ]; then
            local total_attempts=$(wc -l < "$prefix.logins.tsv")
            local failed_attempts=$(awk '$5 ~ /cowrie.login.failed/ {count++} END {print count+0}' "$prefix.logins.tsv")
            local success_attempts=$(awk '$5 ~ /cowrie.login.success/ {count++} END {print count+0}' "$prefix.logins.tsv")

            echo "总登录尝试: $total_attempts 次"
            echo "  ├─ 失败: $failed_attempts 次"
            echo "  └─ 成功: $success_attempts 次"

            if [ $total_attempts -gt 0 ]; then
                local success_rate=$(awk "BEGIN {printf \"%.2f\", ($success_attempts / $total_attempts) * 100}")
                echo "成功率: $success_rate%"
            fi
        fi

        echo ""

        # 命令执行统计
        if [ -f "$prefix.commands.tsv" ]; then
            local total_cmds=$(wc -l < "$prefix.commands.tsv")
            echo "命令执行总数: $total_cmds 条"

            # 唯一命令数
            local unique_cmds=$(cut -f4 "$prefix.commands.tsv" | sort -u | wc -l)
            echo "唯一命令数: $unique_cmds 个"
        fi

        echo ""

        # IP 统计
        if [ -f "$prefix.ips.txt" ]; then
            local total_ips=$(wc -l < "$prefix.ips.txt")
            echo "攻击源 IP 数量: $total_ips 个"

            # 统计内网/外网 IP（假设查询结果存在）
            if [ -f "$prefix.ip_enrichment.json" ]; then
                local internal_count=$(jq '[.[] | select(.is_internal == true)] | length' "$prefix.ip_enrichment.json")
                local external_count=$(jq '[.[] | select(.is_internal == false)] | length' "$prefix.ip_enrichment.json")
                echo "  ├─ 内网 IP: $internal_count 个"
                echo "  └─ 外网 IP: $external_count 个"
            fi
        fi

        echo ""
        echo "==================== TOP 10 用户名 ===================="
        if [ -f "$prefix.top_usernames.txt" ]; then
            head -10 "$prefix.top_usernames.txt" | awk '{printf "  %6s 次   %s\n", $1, $2}'
        fi

        echo ""
        echo "==================== TOP 10 密码 ===================="
        if [ -f "$prefix.top_passwords.txt" ]; then
            head -10 "$prefix.top_passwords.txt" | awk '{printf "  %6s 次   %s\n", $1, $2}'
        fi

        echo ""
        echo "==================== TOP 10 命令 ===================="
        if [ -f "$prefix.top_commands.txt" ]; then
            head -10 "$prefix.top_commands.txt" | awk '{printf "  %6s 次   %s\n", $1, $2}'
        fi

        echo ""
        echo "==================== 攻击源地理分布 ===================="
        if [ -f "$prefix.ip_enrichment.json" ]; then
            echo "按国家统计:"
            jq -r '.[] | select(.is_internal == false) | .country' "$prefix.ip_enrichment.json" | \
                sort | uniq -c | sort -rn | head -10 | awk '{printf "  %6s 个   %s\n", $1, $2}'

            echo ""
            echo "威胁等级分布:"
            jq -r '.[] | .threat_level' "$prefix.ip_enrichment.json" | \
                sort | uniq -c | sort -rn | awk '{printf "  %6s 个   %s\n", $1, $2}'
        fi

        echo ""
        echo "==================== 详细结果文件 ===================="
        echo "  - 所有登录尝试: $prefix.logins.tsv"
        echo "  - 成功登录: $prefix.successful_logins.tsv"
        echo "  - 命令执行: $prefix.commands.tsv"
        echo "  - IP 列表: $prefix.ips.txt"
        echo "  - IP 溯源结果: $prefix.ip_enrichment.json"
        echo "  - 用户名统计: $prefix.top_usernames.txt"
        echo "  - 密码统计: $prefix.top_passwords.txt"
        echo "  - 命令统计: $prefix.top_commands.txt"
        echo ""
        echo "=========================================="

    } > "$output"

    log_msg "INFO" "摘要报告生成完成: $output"

    # 打印到终端
    echo ""
    cat "$output"
}

main() {
    print_banner

    log_msg "INFO" "========== 日志分析开始 =========="

    # 检查依赖
    check_dependencies

    # 检查日志文件
    if [ -z "$COWRIE_JSON_LOG" ] || [ ! -f "$COWRIE_JSON_LOG" ]; then
        log_msg "ERROR" "未找到 Cowrie JSON 日志文件"
        log_msg "INFO" "请指定日志目录: $0 /path/to/cowrie/log/dir"
        exit 1
    fi

    log_msg "INFO" "日志文件: $COWRIE_JSON_LOG"

    # 创建输出目录
    mkdir -p "$OUTPUT_DIR"

    # 生成输出文件前缀（基于时间戳）
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local output_prefix="$OUTPUT_DIR/analysis_$timestamp"

    log_msg "INFO" "输出目录: $OUTPUT_DIR"
    log_msg "INFO" "输出前缀: analysis_$timestamp"

    echo ""

    # 解析日志
    parse_cowrie_log "$COWRIE_JSON_LOG" "$output_prefix"

    echo ""

    # IP 溯源
    if [ -s "$output_prefix.ips.txt" ]; then
        enrich_ips "$output_prefix.ips.txt" "$output_prefix.ip_enrichment.json"
    fi

    echo ""

    # 生成摘要报告
    generate_summary_report "$output_prefix"

    echo ""

    # 生成可视化图表
    if [ -x "$VISUALIZER" ]; then
        log_msg "INFO" "生成数据可视化图表..."
        "$VISUALIZER" "$output_prefix"
        echo ""
    fi

    log_msg "INFO" "========== 分析完成 =========="

    # 如果报告生成器存在，调用它
    if [ -x "$REPORT_GENERATOR" ]; then
        echo ""
        log_msg "INFO" "生成详细报告..."
        "$REPORT_GENERATOR" "$output_prefix"
    fi
}

main "$@"
