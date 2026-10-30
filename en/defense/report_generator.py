#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Honeypot log analysis report generator
Purpose: generate a detailed Markdown report from log analysis results
"""

import json
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
from collections import Counter

class ReportGenerator:
    """Report generator."""

    def __init__(self, prefix: str):
        """
        Initialise the report generator.

        Args:
            prefix: analysis result file prefix (without extension)
        """
        self.prefix = prefix
        self.base_dir = Path(prefix).parent

        # Input file paths
        self.logins_file = Path(f"{prefix}.logins.tsv")
        self.success_file = Path(f"{prefix}.successful_logins.tsv")
        self.commands_file = Path(f"{prefix}.commands.tsv")
        self.ips_file = Path(f"{prefix}.ips.txt")
        self.ip_enrich_file = Path(f"{prefix}.ip_enrichment.json")
        self.top_users_file = Path(f"{prefix}.top_usernames.txt")
        self.top_pass_file = Path(f"{prefix}.top_passwords.txt")
        self.top_cmds_file = Path(f"{prefix}.top_commands.txt")

        # Output file
        self.output_md = Path(f"{prefix}.report.md")

    def load_data(self):
        """Load all analysis data."""
        self.data = {}

        # Load login attempts
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

        # Load successful logins
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

        # Load command executions
        if self.commands_file.exists():
            with open(self.commands_file, 'r') as f:
                lines = [line.strip().split('\t') for line in f if line.strip()]
                self.data['commands'] = [
                    {'timestamp': r[0], 'ip': r[1], 'session': r[2], 'command': r[3]}
                    for r in lines if len(r) >= 4
                ]
        else:
            self.data['commands'] = []

        # Load IP tracing results
        if self.ip_enrich_file.exists():
            with open(self.ip_enrich_file, 'r', encoding='utf-8') as f:
                self.data['ip_enrichment'] = json.load(f)
        else:
            self.data['ip_enrichment'] = []

    def generate_markdown(self):
        """Generate the Markdown report."""
        lines = []

        # Title
        lines.append("# Cowrie Honeypot Log Analysis Report")
        lines.append("")
        lines.append(f"**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")
        lines.append("---")
        lines.append("")

        # Executive summary
        lines.append("## 1. Executive Summary")
        lines.append("")

        total_attempts = len(self.data['logins'])
        success_count = len(self.data['successful_logins'])
        fail_count = total_attempts - success_count
        cmd_count = len(self.data['commands'])
        unique_ips = len(self.data['ip_enrichment'])

        lines.append(f"- **Total login attempts**: {total_attempts}")
        lines.append(f"  - succeeded: {success_count}")
        lines.append(f"  - failed: {fail_count}")
        if total_attempts > 0:
            success_rate = (success_count / total_attempts) * 100
            lines.append(f"  - success rate: {success_rate:.2f}%")
        lines.append(f"- **Total commands executed**: {cmd_count}")
        lines.append(f"- **Number of source IPs**: {unique_ips}")
        lines.append("")

        # Threat assessment
        lines.append("### 1.1 Threat Assessment")
        lines.append("")

        if self.data['ip_enrichment']:
            internal_count = sum(1 for ip in self.data['ip_enrichment'] if ip.get('is_internal'))
            external_count = unique_ips - internal_count

            lines.append(f"- Internal sources: {internal_count}")
            lines.append(f"- External sources: {external_count}")

            # Threat level distribution
            threat_levels = Counter(ip.get('threat_level', 'low') for ip in self.data['ip_enrichment'])
            lines.append("")
            lines.append("**Threat level distribution**:")
            lines.append("")
            for level in ['high', 'medium', 'low']:
                count = threat_levels.get(level, 0)
                if count > 0:
                    lines.append(f"- {level.upper()}: {count}")
        lines.append("")

        # Attack timeline
        lines.append("## 2. Attack Timeline")
        lines.append("")

        if self.data['logins']:
            # Extract the date range
            timestamps = [login['timestamp'] for login in self.data['logins']]
            lines.append(f"- **First attack**: {min(timestamps)}")
            lines.append(f"- **Last attack**: {max(timestamps)}")
            lines.append("")

        # Successful login details
        if self.data['successful_logins']:
            lines.append("### 2.1 Successful Logins")
            lines.append("")
            lines.append("| Time | Source IP | Username | Password |")
            lines.append("|------|-----------|----------|----------|")

            for login in self.data['successful_logins'][:20]:  # show at most 20
                lines.append(f"| {login['timestamp']} | {login['ip']} | "
                           f"`{login['username']}` | `{login['password']}` |")

            if len(self.data['successful_logins']) > 20:
                lines.append(f"")
                lines.append(f"*({len(self.data['successful_logins']) - 20} more records omitted)*")
            lines.append("")

        # Credential analysis
        lines.append("## 3. Credential Analysis")
        lines.append("")

        # Username statistics
        lines.append("### 3.1 Top 15 Usernames")
        lines.append("")

        username_counts = Counter(login['username'] for login in self.data['logins']
                                 if login.get('username'))
        if username_counts:
            lines.append("| Username | Attempts | Share |")
            lines.append("|----------|----------|-------|")

            for username, count in username_counts.most_common(15):
                pct = (count / total_attempts) * 100 if total_attempts > 0 else 0
                lines.append(f"| `{username}` | {count} | {pct:.1f}% |")
        else:
            lines.append("*No username data*")
        lines.append("")

        # Password statistics
        lines.append("### 3.2 Top 15 Passwords")
        lines.append("")

        password_counts = Counter(login['password'] for login in self.data['logins']
                                 if login.get('password'))
        if password_counts:
            lines.append("| Password | Attempts | Share |")
            lines.append("|----------|----------|-------|")

            for password, count in password_counts.most_common(15):
                pct = (count / total_attempts) * 100 if total_attempts > 0 else 0
                display_pass = password if len(password) <= 30 else password[:30] + '...'
                lines.append(f"| `{display_pass}` | {count} | {pct:.1f}% |")
        else:
            lines.append("*No password data*")
        lines.append("")

        # Command analysis
        lines.append("## 4. Command Analysis")
        lines.append("")

        if self.data['commands']:
            lines.append(f"Attackers executed a total of **{len(self.data['commands'])}** commands on the honeypot.")
            lines.append("")

            lines.append("### 4.1 Top 20 Commands")
            lines.append("")

            cmd_counts = Counter(cmd['command'] for cmd in self.data['commands']
                                if cmd.get('command'))
            if cmd_counts:
                lines.append("| Command | Count |")
                lines.append("|---------|-------|")

                for command, count in cmd_counts.most_common(20):
                    display_cmd = command.replace('|', '\\|')
                    if len(display_cmd) > 80:
                        display_cmd = display_cmd[:80] + '...'
                    lines.append(f"| `{display_cmd}` | {count} |")
            else:
                lines.append("*No command data*")
            lines.append("")

            # Command categories
            lines.append("### 4.2 Command Categories")
            lines.append("")

            categories = {
                'Reconnaissance': ['whoami', 'uname', 'hostname', 'ifconfig', 'ip addr', 'ps', 'w', 'last'],
                'File discovery': ['ls', 'cat', 'find', 'locate', 'head', 'tail'],
                'System info': ['df', 'free', 'cat /etc/os-release', 'cat /proc/cpuinfo'],
                'Network probing': ['netstat', 'ss', 'ping', 'wget', 'curl'],
                'Privilege escalation': ['sudo', 'su', 'chmod +x'],
                'Persistence': ['crontab', 'cat /root/.bash_history', 'echo'],
            }

            for category, keywords in categories.items():
                matching = [cmd for cmd in self.data['commands']
                          if any(kw in cmd['command'].lower() for kw in keywords)]
                if matching:
                    lines.append(f"- **{category}**: {len(matching)}")
            lines.append("")

        # Attack source analysis
        lines.append("## 5. Attack Source Analysis")
        lines.append("")

        if self.data['ip_enrichment']:
            # Geographic distribution
            lines.append("### 5.1 Geographic Distribution")
            lines.append("")

            external_ips = [ip for ip in self.data['ip_enrichment'] if not ip.get('is_internal')]

            if external_ips:
                country_counts = Counter(ip.get('country', 'Unknown') for ip in external_ips)

                lines.append("| Country | IP count | Share |")
                lines.append("|---------|----------|-------|")

                for country, count in country_counts.most_common(10):
                    pct = (count / len(external_ips)) * 100 if external_ips else 0
                    lines.append(f"| {country} | {count} | {pct:.1f}% |")
                lines.append("")

            # ISP distribution
            lines.append("### 5.2 ISP / Organisation Distribution")
            lines.append("")

            isp_counts = Counter(ip.get('isp', 'Unknown') for ip in external_ips if ip.get('isp'))

            if isp_counts:
                lines.append("| ISP / Organisation | IP count |")
                lines.append("|--------------------|----------|")

                for isp, count in isp_counts.most_common(10):
                    lines.append(f"| {isp} | {count} |")
                lines.append("")

            # Detailed IP list
            lines.append("### 5.3 Detailed IP Information")
            lines.append("")

            lines.append("| IP address | Country | ISP | Threat level |")
            lines.append("|------------|---------|-----|--------------|")

            for ip_info in self.data['ip_enrichment'][:30]:  # show at most 30
                ip = ip_info['ip']
                country = ip_info.get('country', 'Unknown')
                isp = ip_info.get('isp', 'Unknown')
                if len(isp) > 30:
                    isp = isp[:30] + '...'
                threat = ip_info.get('threat_level', 'low').upper()

                lines.append(f"| {ip} | {country} | {isp} | {threat} |")

            if len(self.data['ip_enrichment']) > 30:
                lines.append("")
                lines.append(f"*({len(self.data['ip_enrichment']) - 30} more IPs omitted)*")
            lines.append("")

        # Threat analysis
        lines.append("## 6. Threat Analysis")
        lines.append("")

        if self.data['logins']:
            lines.append("### 6.1 Attacker Capability Assessment")
            lines.append("")

            suspicious_keywords = ['wget', 'curl', 'nc', 'bash', 'python', '/tmp', 'chmod', 'sudo']
            suspicious_cmds = [cmd for cmd in self.data['commands']
                             if any(kw in cmd['command'].lower() for kw in suspicious_keywords)]

            lines.append(f"- **Basic reconnaissance**: {success_count} successful logins observed")
            lines.append(f"- **Commands executed**: {cmd_count}")

            if suspicious_cmds:
                lines.append(f"- **High-risk behaviour**: {len(suspicious_cmds)} suspicious commands detected")
                lines.append(f"  - examples: {', '.join(f'`{c[:40]}`' for c in [cmd['command'] for cmd in suspicious_cmds[:3]])}")
            else:
                lines.append("- **High-risk behaviour**: no obvious malicious activity detected")

            lines.append("")
            lines.append("### 6.2 Risk to the Organisation")
            lines.append("")

            if external_ips:
                high_risk_ips = [ip for ip in external_ips if ip.get('threat_level') == 'high']
                medium_risk_ips = [ip for ip in external_ips if ip.get('threat_level') == 'medium']

                lines.append(f"- **Confirmed threat sources**: {len(external_ips)} external attack sources")
                if high_risk_ips:
                    lines.append(f"- **High-risk IPs**: {len(high_risk_ips)}")
                if medium_risk_ips:
                    lines.append(f"- **Medium-risk IPs**: {len(medium_risk_ips)}")

            if username_counts:
                top_users = [u for u, _ in username_counts.most_common(3)]
                lines.append(f"- **Targeted accounts**: attackers focused on accounts such as {', '.join(f'`{u}`' for u in top_users)}")

            if success_count > 0:
                lines.append(f"- **Successful intrusion**: {success_count} successful logins (**critical risk**)")
                lines.append("  - attackers may have gained system access, reached sensitive data, or installed malware")
            else:
                lines.append("- **Intrusion prevention**: no successful intrusion found (controls effective)")

            lines.append("")

        # Security recommendations
        lines.append("## 7. Security Recommendations")
        lines.append("")

        lines.append("Based on this honeypot log analysis, we make the following security recommendations:")
        lines.append("")

        lines.append("1. **Enforce a strong password policy**")
        if password_counts:
            top_passwords = [p for p, _ in password_counts.most_common(5)]
            lines.append(f"   - Observed: frequent weak passwords {', '.join(f'`{p}`' for p in top_passwords)}")
        lines.append("   - Require at least 12 characters, mixing upper/lower case letters, digits and symbols; rotate regularly; ban common words.")
        lines.append("   - Rationale: almost all attempts in this log were dictionary weak passwords, which a strong policy defeats outright.")
        lines.append("")

        lines.append("2. **Disable password authentication, use SSH keys**")
        lines.append("   - Set `PasswordAuthentication no` in `sshd_config` and allow key-based login only.")
        lines.append("   - Rationale: the attackers rely on password guessing; key authentication leaves brute force nothing to work with.")
        lines.append("")

        lines.append("3. **Disallow direct root login**")
        if username_counts:
            root_attempts = sum(c for u, c in username_counts.items() if u == 'root')
            if root_attempts:
                lines.append(f"   - Observed: `root` was tried {root_attempts} times, one of the main target accounts.")
        lines.append("   - Set `PermitRootLogin no`; log in as a normal account and escalate with `sudo`.")
        lines.append("   - Rationale: root is the attacker's prime target; disabling it means even leaked credentials cannot grant top privileges directly.")
        lines.append("")

        lines.append("4. **Deploy failed-login banning (fail2ban)**")
        lines.append("   - Temporarily ban source IPs with repeated failures and record them to the audit log.")
        lines.append("   - Rationale: the logs show high-frequency attempts from fixed sources; automatic banning markedly slows such scanning.")
        lines.append("")

        lines.append("5. **Enable audit logging and regular updates**")
        lines.append("   - Enable `auditd` to record logins and command execution, and turn on automatic security updates.")
        lines.append("   - Rationale: timely logs and patches shorten time-to-detection and close known vulnerabilities.")
        if success_count > 0:
            lines.append(f"   - Note: {success_count} successful logins already occurred; investigate the related sessions and reset credentials immediately.")
        lines.append("")

        # Appendix
        lines.append("---")
        lines.append("")
        lines.append("## Appendix")
        lines.append("")
        lines.append("### A. Raw Data Files")
        lines.append("")
        lines.append("The detailed data files from this analysis are:")
        lines.append("")
        lines.append(f"- `{self.logins_file.name}` - all login attempts (TSV)")
        lines.append(f"- `{self.success_file.name}` - successful logins (TSV)")
        lines.append(f"- `{self.commands_file.name}` - command executions (TSV)")
        lines.append(f"- `{self.ips_file.name}` - unique source IP list")
        lines.append(f"- `{self.ip_enrich_file.name}` - IP geolocation and threat intelligence results (JSON)")
        lines.append("")
        lines.append("### B. Field Definitions")
        lines.append("")
        lines.append("**Login attempts (logins.tsv)**:")
        lines.append("| Field | Description |")
        lines.append("|-------|-------------|")
        lines.append("| timestamp | attempt timestamp |")
        lines.append("| src_ip | source IP address |")
        lines.append("| username | username attempted |")
        lines.append("| password | password attempted |")
        lines.append("| eventid | event type (cowrie.login.failed / cowrie.login.success) |")
        lines.append("")
        lines.append("**Command executions (commands.tsv)**:")
        lines.append("| Field | Description |")
        lines.append("|-------|-------------|")
        lines.append("| timestamp | command execution timestamp |")
        lines.append("| src_ip | source IP address |")
        lines.append("| session | session ID |")
        lines.append("| input | command executed |")
        lines.append("")
        lines.append("### C. Analysis Tools")
        lines.append("")
        lines.append("This report was generated by the following tools:")
        lines.append("")
        lines.append("- **analyze_logs.sh** - main log analysis script, parses Cowrie JSON logs automatically")
        lines.append("- **ip_tracker.py** - IP tracing tool, obtains geolocation and threat intelligence for attack sources")
        lines.append("- **report_generator.py** - report generator, produces this detailed Markdown report")
        lines.append("")
        lines.append("### D. Example Commands")
        lines.append("")
        lines.append("```bash")
        lines.append("# Analyse Cowrie logs and generate a report")
        lines.append("./analyze_logs.sh /path/to/cowrie/logs")
        lines.append("")
        lines.append("# View the summary report")
        lines.append("cat reports/analysis_*/summary.txt")
        lines.append("")
        lines.append("# View the detailed report")
        lines.append("cat reports/analysis_*/report.md")
        lines.append("")
        lines.append("# Look up IP information manually")
        lines.append("./ip_tracker.py --json 192.168.1.1 8.8.8.8")
        lines.append("```")
        lines.append("")

        return '\n'.join(lines)

    def save_report(self):
        """Save the report to a file."""
        content = self.generate_markdown()

        with open(self.output_md, 'w', encoding='utf-8') as f:
            f.write(content)

        print(f"Detailed report generated: {self.output_md}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 report_generator.py <analysis result prefix>", file=sys.stderr)
        print("Example: python3 report_generator.py ./reports/analysis_20261026_123456", file=sys.stderr)
        sys.exit(1)

    prefix = sys.argv[1]

    generator = ReportGenerator(prefix)
    generator.load_data()
    generator.save_report()


if __name__ == '__main__':
    main()
