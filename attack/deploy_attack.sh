#!/bin/bash
# ============================================================================
# 攻击机（客户端 / VM B）一键环境部署  ——  Ubuntu 24.04 LTS / apt
#
# 作用：在攻击机上装好跑 simulate_attack.sh 所需的工具，并自检。
#       只负责“受控演练”——对你们自己的蜜罐发起模拟登录，不做别的。
#
# 与防守机分开：本脚本只装攻击侧依赖，不要在蜜罐机上运行。
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ATTACK_SCRIPT="$SCRIPT_DIR/simulate_attack.sh"
CREDS_FILE="$SCRIPT_DIR/payloads/common_creds.txt"

log()  { echo "[$(date '+%F %T')] [$1] ${*:2}"; }
die()  { log ERROR "$*"; exit 1; }

require_root() {
    [ "$(id -u)" -eq 0 ] || die "请用 root 运行：sudo $0"
}

install_packages() {
    command -v apt-get >/dev/null 2>&1 || die "本脚本面向 Ubuntu/Debian(apt)"
    log INFO "安装攻击模拟依赖：sshpass / openssh-client / coreutils ..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y sshpass openssh-client coreutils
}

prepare_scripts() {
    [ -f "$ATTACK_SCRIPT" ] || die "找不到 $ATTACK_SCRIPT"
    chmod +x "$ATTACK_SCRIPT"
    [ -f "$CREDS_FILE" ] || die "找不到凭据字典 $CREDS_FILE"
    log INFO "攻击脚本就绪，凭据字典 $(grep -c ':' "$CREDS_FILE") 组"
}

selfcheck() {
    log INFO "自检工具可用性..."
    for c in sshpass ssh timeout; do
        command -v "$c" >/dev/null 2>&1 && log INFO "  $c OK" || die "缺少 $c"
    done
}

main() {
    require_root
    install_packages
    prepare_scripts
    selfcheck
    cat <<EOF

============================================================
攻击机环境就绪。对你们自己的蜜罐发起受控演练：
    cd $SCRIPT_DIR
    ./simulate_attack.sh <蜜罐IP> <端口>

例如蜜罐在 VPS 的 22 端口（已切给 Cowrie）：
    ./simulate_attack.sh <蜜罐公网IP> 22

只对本组自己的蜜罐测试，不要对任何其他目标使用。
============================================================
EOF
}

main "$@"
