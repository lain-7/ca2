#!/bin/bash
# ============================================================================
# 防守机（蜜罐机）一键部署脚本  ——  Ubuntu 24.04 LTS / DigitalOcean 等 VPS
#
# 作用：在一台干净的 VPS 上手工复现 Cowrie 蜜罐环境，并对主机做基础加固。
#       不包含“还原学校提供的 .ova 虚拟机”那部分——VPS 上用不了 .ova，
#       这里是从零手工安装，更可控、可重建。
#
# 端口规划（最大化真实攻击捕获）：
#   22   —— 对公网暴露，经 nat 重定向到 2222，交给 Cowrie（抓真实扫描）
#   2222 —— Cowrie 实际监听端口；防火墙只放行由 22 重定向来的连接，
#           外部直连 2222 会被丢弃（避免暴露 Cowrie 默认端口这一识别特征）
#   2022 —— 你自己的管理 SSH（真实 sshd），仅密钥登录
#
# 两阶段防锁死：
#   第一阶段（默认）：装好 Cowrie + 工具，管理 SSH 额外加到 2022（22 仍可用），
#                     不动 22、不切 Cowrie 上线。跑完用 ssh -p 2022 验证能进。
#   第二阶段（--cutover）：确认 2022 能登录后再执行，去掉 22 上的真实 sshd，
#                     并把 22 重定向给 Cowrie。到此真实攻击才会进蜜罐。
# ============================================================================

set -euo pipefail

# ==================== 配置区 ====================
ADMIN_PORT=2022                 # 管理 SSH 新端口（切换后用它登录）
COWRIE_PORT=2222                # Cowrie 监听端口
PUBLIC_PORT=22                  # 对外暴露、重定向给 Cowrie 的端口
COWRIE_USER=cowrie              # 运行 Cowrie 的专用非 root 用户
COWRIE_VERSION=3.0.13           # 与原实验环境一致的 Cowrie 版本（PyPI）
COWRIE_HOME="/home/$COWRIE_USER"
COWRIE_DIR="$COWRIE_HOME/cowrie"
UFW_BEFORE="/etc/ufw/before.rules"
NAT_MARK="# cowrie-honeypot-nat"   # 在 before.rules 里做幂等标记

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ==================== 工具函数 ====================
log()  { echo "[$(date '+%F %T')] [$1] ${*:2}"; }
die()  { log ERROR "$*"; exit 1; }

require_root() {
    [ "$(id -u)" -eq 0 ] || die "请用 root 运行：sudo $0 $*"
}

require_ubuntu() {
    command -v apt-get >/dev/null 2>&1 || die "本脚本面向 Ubuntu/Debian(apt)，当前系统不支持"
}

# ==================== 第一阶段：安装与基础加固 ====================

install_packages() {
    log INFO "更新索引并安装依赖..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    # Cowrie 构建依赖 + 分析工具依赖(jq/curl) + 防火墙/审计
    apt-get install -y \
        git python3 python3-venv python3-dev \
        libssl-dev libffi-dev build-essential \
        jq curl ufw auditd
}

create_cowrie_user() {
    if id "$COWRIE_USER" >/dev/null 2>&1; then
        log INFO "用户 $COWRIE_USER 已存在，跳过创建"
    else
        log INFO "创建非 root 专用用户 $COWRIE_USER..."
        adduser --disabled-password --gecos "" "$COWRIE_USER"
    fi
}

install_cowrie() {
    # 旧版本脚本留下的是 git 源码检出（新版 Cowrie 布局已变，无法照旧使用）。
    # 该检出从未成功启动过，不含捕获数据，直接清理。
    if [ -d "$COWRIE_DIR/.git" ]; then
        log WARN "检测到旧脚本留下的 Cowrie 源码检出，清理后改用 pip 安装：$COWRIE_DIR"
        rm -rf "$COWRIE_DIR"
    fi
    log INFO "以 $COWRIE_USER 身份 pip 安装 Cowrie $COWRIE_VERSION（幂等）..."
    sudo -u "$COWRIE_USER" -H bash <<EOF
set -e
mkdir -p "$COWRIE_DIR"
cd "$COWRIE_DIR"
[ -x cowrie-env/bin/python ] || python3 -m venv cowrie-env
cowrie-env/bin/pip install --upgrade pip wheel
# 锁定与原实验环境一致的版本（tools/ 下的补丁也基于此版本）
cowrie-env/bin/pip install "cowrie==$COWRIE_VERSION"
EOF
    sudo -u "$COWRIE_USER" test -x "$COWRIE_DIR/cowrie-env/bin/cowrie" \
        || die "Cowrie 安装失败（缺 cowrie-env/bin/cowrie），请检查上面 pip 的报错"
}

configure_cowrie() {
    # Cowrie 3.x 的配置、pid、日志都相对工作目录：
    #   ./etc/cowrie.cfg  ./var/run/cowrie.pid  ./var/log/cowrie/
    # `cowrie init` 用包内默认配置生成 etc/cowrie.cfg 并建好 var/ 目录；
    # 未初始化的目录 `cowrie start` 会拒绝启动。默认 SSH 端口即 2222。
    log INFO "初始化 Cowrie 工作目录（cowrie init）..."
    sudo -u "$COWRIE_USER" -H bash <<EOF
set -e
cd "$COWRIE_DIR"
[ -f etc/cowrie.cfg ] || cowrie-env/bin/cowrie init
EOF
    sudo -u "$COWRIE_USER" test -f "$COWRIE_DIR/etc/cowrie.cfg" \
        || die "Cowrie 初始化失败（缺 etc/cowrie.cfg）"
    log INFO "如需自定义主机名等，编辑 $COWRIE_DIR/etc/cowrie.cfg 后 systemctl restart cowrie"
}

install_systemd_unit() {
    log INFO "安装 Cowrie systemd 服务（带进程加固）..."
    cat > /etc/systemd/system/cowrie.service <<EOF
[Unit]
Description=Cowrie SSH Honeypot
After=network.target

[Service]
Type=forking
User=$COWRIE_USER
Group=$COWRIE_USER
WorkingDirectory=$COWRIE_DIR
# cowrie 启动器用 execvp 按 PATH 查找 twistd，必须把虚拟环境 bin 放进 PATH
Environment=PATH=$COWRIE_DIR/cowrie-env/bin:/usr/local/bin:/usr/bin:/bin
Environment=AUTHBIND_ENABLED=no
ExecStart=$COWRIE_DIR/cowrie-env/bin/cowrie start
ExecStop=$COWRIE_DIR/cowrie-env/bin/cowrie stop
PIDFile=$COWRIE_DIR/var/run/cowrie.pid
Restart=on-failure

# —— 进程加固：即使蜜罐出问题也难以提权或污染系统 ——
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=$COWRIE_DIR
ProtectHome=false
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true
# 资源上限：防止被当成 DDoS 放大器时打满主机
LimitNOFILE=4096
CPUQuota=50%

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable cowrie.service
    systemctl restart cowrie.service || log WARN "Cowrie 启动失败，请手动检查：journalctl -u cowrie"
}

setup_analysis_tools() {
    log INFO "准备日志分析工具（赋可执行权限）..."
    chmod +x "$SCRIPT_DIR"/*.sh "$SCRIPT_DIR"/*.py 2>/dev/null || true
    log INFO "分析工具就绪：$SCRIPT_DIR/analyze_logs.sh"
    log INFO "Cowrie 日志路径：$COWRIE_DIR/var/log/cowrie/cowrie.json"
}

harden_ssh_phase1() {
    log INFO "为管理 SSH 增加端口 $ADMIN_PORT（保留 22，避免锁死）..."
    local cfg=/etc/ssh/sshd_config.d/99-honeypot-admin.conf
    cat > "$cfg" <<EOF
# 蜜罐主机管理 SSH：第一阶段同时监听 22 与 $ADMIN_PORT
Port 22
Port $ADMIN_PORT
PermitRootLogin prohibit-password
PasswordAuthentication no
PubkeyAuthentication yes
EOF
    log WARN "已设 PasswordAuthentication no —— 确保你已配置好 SSH 公钥，否则会登录不了！"
    systemctl restart ssh || systemctl restart sshd || die "sshd 重启失败，请检查配置"
}

firewall_base() {
    log INFO "配置 ufw：默认拒绝入站、放行管理与蜜罐端口..."
    ufw --force reset >/dev/null
    ufw default deny incoming
    ufw default allow outgoing          # 出站默认放行（收紧见文档，别在未验证时切断）
    ufw allow "$ADMIN_PORT"/tcp comment '管理 SSH'
    ufw allow 22/tcp comment '切换前为真实 sshd'
    # 不放行 $COWRIE_PORT：切换后由 cutover_filter 只放行重定向来的连接
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
第一阶段完成。现在：
  1) 另开一个终端，用新端口登录验证能进：
        ssh -p $ADMIN_PORT <user>@<本机IP>
  2) 确认能登录后，再回来执行第二阶段（把 22 让给蜜罐）：
        sudo $0 --cutover

此刻 22 端口仍是你的真实 sshd，Cowrie 在 $COWRIE_PORT。
真实攻击还不会进蜜罐，直到你完成 --cutover。
============================================================
EOF
}

# ==================== 第二阶段：切换 22 给蜜罐 ====================

cutover_ssh() {
    log INFO "移除 22 上的真实 sshd，仅保留管理端口 $ADMIN_PORT..."
    local cfg=/etc/ssh/sshd_config.d/99-honeypot-admin.conf
    cat > "$cfg" <<EOF
# 蜜罐主机管理 SSH：切换后仅监听 $ADMIN_PORT
Port $ADMIN_PORT
PermitRootLogin prohibit-password
PasswordAuthentication no
PubkeyAuthentication yes
EOF
    systemctl restart ssh || systemctl restart sshd || die "sshd 重启失败"
}

cutover_nat() {
    log INFO "设置 nat 重定向：公网 22 -> Cowrie $COWRIE_PORT..."
    if grep -q "$NAT_MARK" "$UFW_BEFORE"; then
        log INFO "nat 规则已存在，跳过"
        return
    fi
    # 在 before.rules 顶部插入 nat 表 PREROUTING 重定向
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
    # 重定向后的包到 INPUT 链时目的端口已是 $COWRIE_PORT，所以必须放行它；
    # 但只放行“原始目的端口是 $PUBLIC_PORT”的连接，外部直连 $COWRIE_PORT 一律丢弃。
    local tag="cowrie-redirect-only"
    local anchor='-A ufw-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT'
    local rule="-A ufw-before-input -p tcp --dport $COWRIE_PORT -m conntrack --ctstate DNAT --ctorigdstport $PUBLIC_PORT -m comment --comment $tag -j ACCEPT"

    # 清理旧版脚本留下的“直接放行 $COWRIE_PORT”规则
    ufw --force delete allow "$COWRIE_PORT"/tcp >/dev/null 2>&1 || true

    if grep -q -- "$tag" "$UFW_BEFORE"; then
        log INFO "2222 仅限重定向的过滤规则已存在，跳过"
    else
        grep -qxF -- "$anchor" "$UFW_BEFORE" \
            || die "before.rules 里找不到锚点行，请手动在 filter 段加入：$rule"
        log INFO "限制 $COWRIE_PORT 只接受由 $PUBLIC_PORT 重定向来的连接..."
        cp "$UFW_BEFORE" "$UFW_BEFORE.bak.$(date +%s)"
        sed -i "\|^${anchor}\$|a ${rule}" "$UFW_BEFORE"
    fi
    ufw reload
}

verify_cutover() {
    log INFO "当前监听端口："
    ss -tulnp 2>/dev/null | grep -E ":($ADMIN_PORT|$COWRIE_PORT|22)\b" || true
    cat <<EOF

============================================================
第二阶段完成：
  - 管理 SSH：端口 $ADMIN_PORT（ssh -p $ADMIN_PORT）
  - 公网 22：已重定向给 Cowrie，开始捕获真实攻击
  - 查看蜜罐实时日志：
        sudo tail -f $COWRIE_DIR/var/log/cowrie/cowrie.json
  - 分析日志：
        cd $SCRIPT_DIR && ./analyze_logs.sh $COWRIE_DIR/var/log/cowrie
提醒：定期把日志 scp 到别处备份，并留意服务商 abuse 邮件。
============================================================
EOF
}

cutover() {
    require_ubuntu
    log WARN "即将把 22 让给蜜罐。请确认你已能用 ssh -p $ADMIN_PORT 正常登录！"
    read -r -p "已验证 $ADMIN_PORT 可登录？输入 yes 继续： " ans
    [ "$ans" = "yes" ] || die "已取消。先验证管理端口再来。"
    cutover_ssh
    cutover_nat
    cutover_filter
    verify_cutover
}

usage() {
    cat <<EOF
用法：
  sudo $0              第一阶段：安装 Cowrie + 工具 + 基础加固（不动 22）
  sudo $0 --cutover    第二阶段：把 22 切给蜜罐（务必先验证 $ADMIN_PORT 能登录）
  $0 --help            显示本帮助
EOF
}

# ==================== 入口 ====================
main() {
    case "${1:-}" in
        ""|--phase1) require_root "$@"; phase1 ;;
        --cutover)   require_root "$@"; cutover ;;
        --help|-h)   usage ;;
        *)           usage; exit 1 ;;
    esac
}

main "$@"
