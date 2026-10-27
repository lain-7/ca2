#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
蜜罐日志分析报告生成器
功能：基于日志分析结果生成详细的 Markdown 格式报告
"""

import json
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
from collections import Counter

class ReportGenerator:
    """报告生成器"""

    def __init__(self, prefix: str):
        """
        初始化报告生成器

        Args:
            prefix: 分析结果文件前缀（不含扩展名）
        """
        self.prefix = prefix
        self.base_dir = Path(prefix).parent

        # 输入文件路径
        self.logins_file = Path(f"{prefix}.logins.tsv")
        self.success_file = Path(f"{prefix}.successful_logins.tsv")
        self.commands_file = Path(f"{prefix}.commands.tsv")
        self.ips_file = Path(f"{prefix}.ips.txt")
        self.ip_enrich_file = Path(f"{prefix}.ip_enrichment.json")
        self.top_users_file = Path(f"{prefix}.top_usernames.txt")
        self.top_pass_file = Path(f"{prefix}.top_passwords.txt")
        self.top_cmds_file = Path(f"{prefix}.top_commands.txt")

        # 输出文件
        self.output_md = Path(f"{prefix}.report.md")

    def load_data(self):
        """加载所有分析数据"""
        self.data = {}

        # 加载登录尝试
        if self.logins_file.exists():
            with open(self.logins_file, 'r') as f:
                lines = [line.strip().split('\t') for line in f if line.strip()]
                self.data['logins'] = [
                    {'timestamp': r[0], 'ip': r[1], 'username': r[2],
                     'password': r[3], 'result': r[4]}
                    for r in lines if len(r) >= 5
                ]
        else:
            self.data['logins'] = []

        # 加载成功登录
        if self.success_file.exists():
            with open(self.success_file, 'r') as f:
                lines = [line.strip().split('\t') for line in f if line.strip()]
                self.data['successful_logins'] = [
                    {'timestamp': r[0], 'ip': r[1], 'username': r[2],
                     'password': r[3], 'session': r[4]}
                    for r in lines if len(r) >= 5
                ]
        else:
            self.data['successful_logins'] = []

        # 加载命令执行
        if self.commands_file.exists():
            with open(self.commands_file, 'r') as f:
                lines = [line.strip().split('\t') for line in f if line.strip()]
                self.data['commands'] = [
                    {'timestamp': r[0], 'ip': r[1], 'session': r[2], 'command': r[3]}
                    for r in lines if len(r) >= 4
                ]
        else:
            self.data['commands'] = []

        # 加载 IP 溯源结果
        if self.ip_enrich_file.exists():
            with open(self.ip_enrich_file, 'r', encoding='utf-8') as f:
                self.data['ip_enrichment'] = json.load(f)
        else:
            self.data['ip_enrichment'] = []

    def generate_markdown(self):
        """生成 Markdown 报告"""
        lines = []

        # 标题
        lines.append("# Cowrie 蜜罐日志分析报告")
        lines.append("")
        lines.append(f"**生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")
        lines.append("---")
        lines.append("")

        # 执行摘要
        lines.append("## 1. 执行摘要 (Executive Summary)")
        lines.append("")

        total_attempts = len(self.data['logins'])
        success_count = len(self.data['successful_logins'])
        fail_count = total_attempts - success_count
        cmd_count = len(self.data['commands'])
        unique_ips = len(self.data['ip_enrichment'])

        lines.append(f"- **总登录尝试**: {total_attempts} 次")
        lines.append(f"  - 成功: {success_count} 次")
        lines.append(f"  - 失败: {fail_count} 次")
        if total_attempts > 0:
            success_rate = (success_count / total_attempts) * 100
            lines.append(f"  - 成功率: {success_rate:.2f}%")
        lines.append(f"- **命令执行总数**: {cmd_count} 条")
        lines.append(f"- **攻击源 IP 数量**: {unique_ips} 个")
        lines.append("")

        # 威胁评估
        lines.append("### 1.1 威胁评估")
        lines.append("")

        if self.data['ip_enrichment']:
            internal_count = sum(1 for ip in self.data['ip_enrichment'] if ip.get('is_internal'))
            external_count = unique_ips - internal_count

            lines.append(f"- 内网攻击源: {internal_count} 个")
            lines.append(f"- 外网攻击源: {external_count} 个")

            # 威胁等级分布
            threat_levels = Counter(ip.get('threat_level', 'low') for ip in self.data['ip_enrichment'])
            lines.append("")
            lines.append("**威胁等级分布**:")
            lines.append("")
            for level in ['high', 'medium', 'low']:
                count = threat_levels.get(level, 0)
                if count > 0:
                    lines.append(f"- {level.upper()}: {count} 个")
        lines.append("")

        # 攻击时间线
        lines.append("## 2. 攻击时间线 (Attack Timeline)")
        lines.append("")

        if self.data['logins']:
            # 提取日期范围
            timestamps = [login['timestamp'] for login in self.data['logins']]
            lines.append(f"- **首次攻击**: {min(timestamps)}")
            lines.append(f"- **最后攻击**: {max(timestamps)}")
            lines.append("")

        # 成功登录详情
        if self.data['successful_logins']:
            lines.append("### 2.1 成功登录记录")
            lines.append("")
            lines.append("| 时间 | 源 IP | 用户名 | 密码 |")
            lines.append("|------|-------|--------|------|")

            for login in self.data['successful_logins'][:20]:  # 最多显示 20 条
                lines.append(f"| {login['timestamp']} | {login['ip']} | "
                           f"`{login['username']}` | `{login['password']}` |")

            if len(self.data['successful_logins']) > 20:
                lines.append(f"")
                lines.append(f"*（省略 {len(self.data['successful_logins']) - 20} 条记录）*")
            lines.append("")

        # 凭据分析
        lines.append("## 3. 凭据分析 (Credential Analysis)")
        lines.append("")

        # 用户名统计
        lines.append("### 3.1 Top 15 用户名")
        lines.append("")

        username_counts = Counter(login['username'] for login in self.data['logins']
                                 if login.get('username'))
        if username_counts:
            lines.append("| 用户名 | 尝试次数 | 占比 |")
            lines.append("|--------|----------|------|")

            for username, count in username_counts.most_common(15):
                pct = (count / total_attempts) * 100 if total_attempts > 0 else 0
                lines.append(f"| `{username}` | {count} | {pct:.1f}% |")
        else:
            lines.append("*暂无用户名数据*")
        lines.append("")

        # 密码统计
        lines.append("### 3.2 Top 15 密码")
        lines.append("")

        password_counts = Counter(login['password'] for login in self.data['logins']
                                 if login.get('password'))
        if password_counts:
            lines.append("| 密码 | 尝试次数 | 占比 |")
            lines.append("|------|----------|------|")

            for password, count in password_counts.most_common(15):
                pct = (count / total_attempts) * 100 if total_attempts > 0 else 0
                display_pass = password if len(password) <= 30 else password[:30] + '...'
                lines.append(f"| `{display_pass}` | {count} | {pct:.1f}% |")
        else:
            lines.append("*暂无密码数据*")
        lines.append("")

        # 命令分析
        lines.append("## 4. 命令分析 (Command Analysis)")
        lines.append("")

        if self.data['commands']:
            lines.append(f"攻击者在蜜罐上总共执行了 **{len(self.data['commands'])}** 条命令。")
            lines.append("")

            lines.append("### 4.1 Top 20 命令")
            lines.append("")

            cmd_counts = Counter(cmd['command'] for cmd in self.data['commands']
                                if cmd.get('command'))
            if cmd_counts:
                lines.append("| 命令 | 执行次数 |")
                lines.append("|------|----------|")

                for command, count in cmd_counts.most_common(20):
                    display_cmd = command.replace('|', '\\|')
                    if len(display_cmd) > 80:
                        display_cmd = display_cmd[:80] + '...'
                    lines.append(f"| `{display_cmd}` | {count} |")
            else:
                lines.append("*暂无命令数据*")
            lines.append("")

            # 命令分类
            lines.append("### 4.2 命令分类")
            lines.append("")

            categories = {
                '侦察类': ['whoami', 'uname', 'hostname', 'ifconfig', 'ip addr', 'ps', 'w', 'last'],
                '文件探测': ['ls', 'cat', 'find', 'locate', 'head', 'tail'],
                '系统信息': ['df', 'free', 'cat /etc/os-release', 'cat /proc/cpuinfo'],
                '网络探测': ['netstat', 'ss', 'ping', 'wget', 'curl'],
                '权限提升': ['sudo', 'su', 'chmod +x'],
                '持久化': ['crontab', 'cat /root/.bash_history', 'echo'],
            }

            for category, keywords in categories.items():
                matching = [cmd for cmd in self.data['commands']
                          if any(kw in cmd['command'].lower() for kw in keywords)]
                if matching:
                    lines.append(f"- **{category}**: {len(matching)} 条")
            lines.append("")

        # IP 溯源分析
        lines.append("## 5. 攻击源分析 (Attack Source Analysis)")
        lines.append("")

        if self.data['ip_enrichment']:
            # 地理分布
            lines.append("### 5.1 地理分布")
            lines.append("")

            external_ips = [ip for ip in self.data['ip_enrichment'] if not ip.get('is_internal')]

            if external_ips:
                country_counts = Counter(ip.get('country', '未知') for ip in external_ips)

                lines.append("| 国家 | IP 数量 | 占比 |")
                lines.append("|------|---------|------|")

                for country, count in country_counts.most_common(10):
                    pct = (count / len(external_ips)) * 100 if external_ips else 0
                    lines.append(f"| {country} | {count} | {pct:.1f}% |")
                lines.append("")

            # ISP 分布
            lines.append("### 5.2 ISP/组织分布")
            lines.append("")

            isp_counts = Counter(ip.get('isp', '未知') for ip in external_ips if ip.get('isp'))

            if isp_counts:
                lines.append("| ISP/组织 | IP 数量 |")
                lines.append("|----------|---------|")

                for isp, count in isp_counts.most_common(10):
                    lines.append(f"| {isp} | {count} |")
                lines.append("")

            # 详细 IP 列表
            lines.append("### 5.3 详细 IP 信息")
            lines.append("")

            lines.append("| IP 地址 | 国家 | ISP | 威胁等级 |")
            lines.append("|---------|------|-----|----------|")

            for ip_info in self.data['ip_enrichment'][:30]:  # 最多显示 30 个
                ip = ip_info['ip']
                country = ip_info.get('country', '未知')
                isp = ip_info.get('isp', '未知')
                if len(isp) > 30:
                    isp = isp[:30] + '...'
                threat = ip_info.get('threat_level', 'low').upper()

                lines.append(f"| {ip} | {country} | {isp} | {threat} |")

            if len(self.data['ip_enrichment']) > 30:
                lines.append("")
                lines.append(f"*（省略 {len(self.data['ip_enrichment']) - 30} 个 IP）*")
            lines.append("")

        # 威胁分析
        lines.append("## 6. 威胁分析 (Threat Analysis)")
        lines.append("")

        if self.data['logins']:
            lines.append("### 6.1 攻击者能力评估")
            lines.append("")

            suspicious_keywords = ['wget', 'curl', 'nc', 'bash', 'python', '/tmp', 'chmod', 'sudo']
            suspicious_cmds = [cmd for cmd in self.data['commands']
                             if any(kw in cmd['command'].lower() for kw in suspicious_keywords)]

            lines.append(f"- **基础侦察活动**: 发现 {success_count} 次成功登录")
            lines.append(f"- **命令执行次数**: {cmd_count} 条")

            if suspicious_cmds:
                lines.append(f"- **高风险行为**: 检测到 {len(suspicious_cmds)} 条可疑命令")
                lines.append(f"  - 示例: {', '.join(f'`{c[:40]}`' for c in [cmd['command'] for cmd in suspicious_cmds[:3]])}")
            else:
                lines.append("- **高风险行为**: 未检测到明显的恶意活动")

            lines.append("")
            lines.append("### 6.2 对组织的风险")
            lines.append("")

            if external_ips:
                high_risk_ips = [ip for ip in external_ips if ip.get('threat_level') == 'high']
                medium_risk_ips = [ip for ip in external_ips if ip.get('threat_level') == 'medium']

                lines.append(f"- **已确认的威胁源**: {len(external_ips)} 个外网攻击源")
                if high_risk_ips:
                    lines.append(f"- **高风险 IP**: {len(high_risk_ips)} 个")
                if medium_risk_ips:
                    lines.append(f"- **中等风险 IP**: {len(medium_risk_ips)} 个")

            if username_counts:
                top_users = [u for u, _ in username_counts.most_common(3)]
                lines.append(f"- **目标账户**: 攻击者重点针对 {', '.join(f'`{u}`' for u in top_users)} 等账户")

            if success_count > 0:
                lines.append(f"- **成功入侵**: {success_count} 次成功登录（**严重风险**）")
                lines.append("  - 攻击者可能获得系统权限、访问敏感数据、安装恶意软件")
            else:
                lines.append("- **入侵防控**: 未发现成功入侵（防护措施有效）")

            lines.append("")

        # 安全建议
        lines.append("## 7. 安全建议 (Security Recommendations)")
        lines.append("")

        lines.append("基于本次蜜罐日志分析，我们提出以下安全建议：")
        lines.append("")

        lines.append("1. **强制实施强密码策略**")
        if password_counts:
            top_passwords = [p for p, _ in password_counts.most_common(5)]
            lines.append(f"   - 分析发现：高频弱密码 {', '.join(f'`{p}`' for p in top_passwords)}")
        lines.append("   - 要求最少 12 位，混合大小写字母、数字与特殊字符；定期更换；禁用常见词汇。")
        lines.append("   - 理由：本次日志中的尝试几乎全部是字典内的弱口令，强密码可直接让这类爆破失效。")
        lines.append("")

        lines.append("2. **禁用密码认证，改用 SSH 密钥**")
        lines.append("   - 在 `sshd_config` 中设置 `PasswordAuthentication no`，仅允许密钥登录。")
        lines.append("   - 理由：攻击者依赖的是密码猜测，密钥认证使暴力破解无从下手。")
        lines.append("")

        lines.append("3. **禁止 root 直接登录**")
        if username_counts:
            root_attempts = sum(c for u, c in username_counts.items() if u == 'root')
            if root_attempts:
                lines.append(f"   - 分析发现：`root` 被尝试 {root_attempts} 次，是最主要的目标账户之一。")
        lines.append("   - 设置 `PermitRootLogin no`，改用普通账户登录后再 `sudo` 提权。")
        lines.append("   - 理由：root 是攻击者的首要目标，禁用后即使凭据泄露也无法直接拿到最高权限。")
        lines.append("")

        lines.append("4. **部署失败登录封禁（fail2ban）**")
        lines.append("   - 对连续失败的来源 IP 自动临时封禁，并记录到审计日志。")
        lines.append("   - 理由：日志显示攻击来自固定来源的高频尝试，自动封禁能显著减缓这类扫描。")
        lines.append("")

        lines.append("5. **启用审计日志与定期更新**")
        lines.append("   - 开启 `auditd` 记录登录与命令执行，启用系统自动安全更新。")
        lines.append("   - 理由：及时的日志与补丁能缩短发现入侵的时间，并堵住已知漏洞。")
        if success_count > 0:
            lines.append(f"   - 注意：本次已出现 {success_count} 次成功登录，建议立即排查相关会话并重置口令。")
        lines.append("")

        # 附录
        lines.append("---")
        lines.append("")
        lines.append("## 附录 (Appendix)")
        lines.append("")
        lines.append("### A. 原始数据文件说明")
        lines.append("")
        lines.append("本次分析的详细数据文件包括：")
        lines.append("")
        lines.append(f"- `{self.logins_file.name}` - 所有登录尝试记录（TSV 格式）")
        lines.append(f"- `{self.success_file.name}` - 成功登录记录（TSV 格式）")
        lines.append(f"- `{self.commands_file.name}` - 命令执行记录（TSV 格式）")
        lines.append(f"- `{self.ips_file.name}` - 唯一攻击源 IP 列表")
        lines.append(f"- `{self.ip_enrich_file.name}` - IP 地理位置和威胁情报查询结果（JSON 格式）")
        lines.append("")
        lines.append("### B. 数据字段说明")
        lines.append("")
        lines.append("**登录尝试记录 (logins.tsv)**:")
        lines.append("| 字段 | 说明 |")
        lines.append("|------|------|")
        lines.append("| timestamp | 尝试时间戳 |")
        lines.append("| src_ip | 源 IP 地址 |")
        lines.append("| username | 尝试使用的用户名 |")
        lines.append("| password | 尝试使用的密码 |")
        lines.append("| eventid | 事件类型（cowrie.login.failed / cowrie.login.success） |")
        lines.append("")
        lines.append("**命令执行记录 (commands.tsv)**:")
        lines.append("| 字段 | 说明 |")
        lines.append("|------|------|")
        lines.append("| timestamp | 命令执行时间戳 |")
        lines.append("| src_ip | 源 IP 地址 |")
        lines.append("| session | 会话 ID |")
        lines.append("| input | 执行的命令 |")
        lines.append("")
        lines.append("### C. 分析工具说明")
        lines.append("")
        lines.append("本报告由以下工具生成：")
        lines.append("")
        lines.append("- **analyze_logs.sh** - 主日志分析脚本，自动解析 Cowrie JSON 日志")
        lines.append("- **ip_tracker.py** - IP 溯源工具，获取攻击源的地理位置和威胁情报")
        lines.append("- **report_generator.py** - 报告生成器，生成 Markdown 格式的详细分析报告")
        lines.append("")
        lines.append("### D. 执行命令示例")
        lines.append("")
        lines.append("```bash")
        lines.append("# 分析 Cowrie 日志并生成报告")
        lines.append("./analyze_logs.sh /path/to/cowrie/logs")
        lines.append("")
        lines.append("# 查看摘要报告")
        lines.append("cat reports/analysis_*/summary.txt")
        lines.append("")
        lines.append("# 查看详细报告")
        lines.append("cat reports/analysis_*/report.md")
        lines.append("")
        lines.append("# 手动查询 IP 信息")
        lines.append("./ip_tracker.py --json 192.168.1.1 8.8.8.8")
        lines.append("```")
        lines.append("")

        return '\n'.join(lines)

    def save_report(self):
        """保存报告到文件"""
        content = self.generate_markdown()

        with open(self.output_md, 'w', encoding='utf-8') as f:
            f.write(content)

        print(f"详细报告已生成: {self.output_md}")


def main():
    if len(sys.argv) < 2:
        print("用法: python3 report_generator.py <分析结果前缀>", file=sys.stderr)
        print("示例: python3 report_generator.py ./reports/analysis_20261026_123456", file=sys.stderr)
        sys.exit(1)

    prefix = sys.argv[1]

    generator = ReportGenerator(prefix)
    generator.load_data()
    generator.save_report()


if __name__ == '__main__':
    main()
