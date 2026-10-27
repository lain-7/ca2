#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
数据可视化模块
生成柱状图、饼图等图表用于日志分析报告
"""

import json
import sys
from pathlib import Path
from typing import Dict, List
from collections import Counter


class Visualizer:
    """数据可视化生成器"""

    def __init__(self, output_dir: str = "."):
        """
        初始化可视化生成器

        Args:
            output_dir: 输出目录
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_ascii_bar_chart(self, title: str, data: Dict[str, int],
                                max_width: int = 50) -> str:
        """
        生成 ASCII 柱状图

        Args:
            title: 图表标题
            data: 数据字典 {标签: 值}
            max_width: 最大宽度（字符数）

        Returns:
            ASCII 柱状图字符串
        """
        if not data:
            return f"{title}\n暂无数据\n"

        lines = [f"\n{title}", "=" * len(title)]

        max_value = max(data.values()) if data.values() else 1
        max_label_len = max(len(label) for label in data.keys()) if data else 0

        for label, value in sorted(data.items(), key=lambda x: -x[1])[:15]:
            bar_width = int((value / max_value) * max_width)
            bar = "█" * bar_width
            lines.append(f"{label:<{max_label_len}} | {bar} {value}")

        return "\n".join(lines) + "\n"

    def generate_ascii_pie_chart(self, title: str, data: Dict[str, int]) -> str:
        """
        生成 ASCII 饼图（实际上是百分比条形图）

        Args:
            title: 图表标题
            data: 数据字典 {标签: 值}

        Returns:
            ASCII 饼图字符串
        """
        if not data:
            return f"{title}\n暂无数据\n"

        total = sum(data.values())
        lines = [f"\n{title}", "=" * len(title)]

        for label, value in sorted(data.items(), key=lambda x: -x[1]):
            percentage = (value / total * 100) if total > 0 else 0
            bar_chars = int(percentage / 2)
            bar = "█" * bar_chars
            lines.append(f"{label:<15} {percentage:>6.1f}% {bar} ({value})")

        return "\n".join(lines) + "\n"

    def generate_html_bar_chart(self, title: str, data: Dict[str, int],
                               output_file: str = None) -> str:
        """
        生成 HTML 柱状图

        Args:
            title: 图表标题
            data: 数据字典 {标签: 值}
            output_file: 输出文件路径

        Returns:
            HTML 字符串或文件路径
        """
        if not data:
            html = f"<p>暂无数据: {title}</p>"
        else:
            sorted_data = sorted(data.items(), key=lambda x: -x[1])[:15]
            labels = [d[0].replace('"', '\\"') for d in sorted_data]
            values = [d[1] for d in sorted_data]

            html = f"""
<div style="margin: 20px 0; padding: 15px; border: 1px solid #ddd;">
    <h3>{title}</h3>
    <canvas id="chart_{title}" width="800" height="400"></canvas>
    <script>
        var ctx = document.getElementById('chart_{title}').getContext('2d');
        var chart = new Chart(ctx, {{
            type: 'bar',
            data: {{
                labels: {json.dumps(labels)},
                datasets: [{{
                    label: '次数',
                    data: {json.dumps(values)},
                    backgroundColor: 'rgba(75, 192, 192, 0.2)',
                    borderColor: 'rgba(75, 192, 192, 1)',
                    borderWidth: 1
                }}]
            }},
            options: {{
                responsive: true,
                scales: {{
                    y: {{
                        beginAtZero: true
                    }}
                }}
            }}
        }});
    </script>
</div>
"""

        if output_file:
            output_path = self.output_dir / output_file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html)
            return str(output_path)

        return html

    def generate_html_pie_chart(self, title: str, data: Dict[str, int],
                               output_file: str = None) -> str:
        """
        生成 HTML 饼图

        Args:
            title: 图表标题
            data: 数据字典 {标签: 值}
            output_file: 输出文件路径

        Returns:
            HTML 字符串或文件路径
        """
        if not data:
            html = f"<p>暂无数据: {title}</p>"
        else:
            sorted_data = sorted(data.items(), key=lambda x: -x[1])[:10]
            labels = [d[0].replace('"', '\\"') for d in sorted_data]
            values = [d[1] for d in sorted_data]
            colors = [
                "rgba(255, 99, 132, 0.7)",
                "rgba(54, 162, 235, 0.7)",
                "rgba(255, 206, 86, 0.7)",
                "rgba(75, 192, 192, 0.7)",
                "rgba(153, 102, 255, 0.7)",
                "rgba(255, 159, 64, 0.7)",
                "rgba(201, 203, 207, 0.7)",
                "rgba(255, 99, 132, 0.7)",
                "rgba(54, 162, 235, 0.7)",
                "rgba(255, 206, 86, 0.7)",
            ]

            html = f"""
<div style="margin: 20px 0; padding: 15px; border: 1px solid #ddd;">
    <h3>{title}</h3>
    <canvas id="chart_{title}" width="600" height="400"></canvas>
    <script>
        var ctx = document.getElementById('chart_{title}').getContext('2d');
        var chart = new Chart(ctx, {{
            type: 'pie',
            data: {{
                labels: {json.dumps(labels)},
                datasets: [{{
                    data: {json.dumps(values)},
                    backgroundColor: {json.dumps(colors[:len(values)])}
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{
                        position: 'right'
                    }}
                }}
            }}
        }});
    </script>
</div>
"""

        if output_file:
            output_path = self.output_dir / output_file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html)
            return str(output_path)

        return html

    def generate_summary_charts(self, prefix: str) -> Dict[str, str]:
        """
        基于分析结果生成所有图表

        Args:
            prefix: 分析结果文件前缀

        Returns:
            图表文件路径字典
        """
        results = {}
        prefix_path = Path(prefix)

        # 生成用户名统计图
        users_file = Path(f"{prefix}.top_usernames.txt")
        if users_file.exists():
            user_data = {}
            with open(users_file, 'r') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        count = int(parts[0])
                        user = ' '.join(parts[1:])
                        user_data[user] = count

            if user_data:
                chart = self.generate_ascii_bar_chart("用户名登录尝试统计", user_data)
                results['users_ascii'] = chart

        # 生成密码统计图
        pass_file = Path(f"{prefix}.top_passwords.txt")
        if pass_file.exists():
            pass_data = {}
            with open(pass_file, 'r') as f:
                for line in f:
                    parts = line.strip().split(None, 1)
                    if len(parts) >= 2:
                        count = int(parts[0])
                        pwd = parts[1]
                        pass_data[pwd] = count

            if pass_data:
                chart = self.generate_ascii_pie_chart("密码尝试分布", pass_data)
                results['passwords_ascii'] = chart

        # 生成命令统计图
        cmd_file = Path(f"{prefix}.top_commands.txt")
        if cmd_file.exists():
            cmd_data = {}
            with open(cmd_file, 'r') as f:
                for line in f:
                    parts = line.strip().split(None, 1)
                    if len(parts) >= 2:
                        count = int(parts[0])
                        cmd = parts[1]
                        if len(cmd) > 40:
                            cmd = cmd[:40] + "..."
                        cmd_data[cmd] = count

            if cmd_data:
                chart = self.generate_ascii_bar_chart("命令执行统计", cmd_data)
                results['commands_ascii'] = chart

        return results


def main():
    """命令行入口"""
    if len(sys.argv) < 2:
        print("用法: python3 visualizer.py <分析结果前缀>", file=sys.stderr)
        sys.exit(1)

    prefix = sys.argv[1]

    viz = Visualizer()
    charts = viz.generate_summary_charts(prefix)

    for chart_name, chart_content in charts.items():
        if isinstance(chart_content, str) and chart_content.startswith('\n'):
            print(chart_content)


if __name__ == '__main__':
    main()
