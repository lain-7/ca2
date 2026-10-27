#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
数据可视化模块
读取 analyze_logs.sh 生成的统计文件，在终端输出 ASCII 柱状图和占比图。
仅依赖 Python 标准库。
"""

import sys
from pathlib import Path
from typing import Dict


def read_count_file(path: Path) -> Dict[str, int]:
    """
    读取 "次数 标签" 格式的统计文件（uniq -c 的输出）。

    Args:
        path: 统计文件路径

    Returns:
        {标签: 次数} 字典；文件不存在时返回空字典
    """
    data: Dict[str, int] = {}
    if not path.exists():
        return data
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            parts = line.strip().split(None, 1)
            if len(parts) == 2 and parts[0].isdigit():
                data[parts[1]] = int(parts[0])
    return data


def bar_chart(title: str, data: Dict[str, int], top: int = 15, width: int = 40) -> str:
    """生成 ASCII 柱状图（按次数降序，最多 top 行）。"""
    if not data:
        return f"\n{title}\n{'=' * len(title)}\n（无数据）\n"

    items = sorted(data.items(), key=lambda kv: -kv[1])[:top]
    max_value = max(v for _, v in items)
    label_w = min(max(len(label) for label, _ in items), 24)

    lines = [f"\n{title}", "=" * len(title)]
    for label, value in items:
        shown = label if len(label) <= label_w else label[:label_w - 1] + "…"
        bar_len = int(value / max_value * width) if max_value else 0
        lines.append(f"{shown:<{label_w}} | {'█' * bar_len} {value}")
    return "\n".join(lines) + "\n"


def share_chart(title: str, data: Dict[str, int], top: int = 10) -> str:
    """生成 ASCII 占比图（显示各项所占百分比）。"""
    if not data:
        return f"\n{title}\n{'=' * len(title)}\n（无数据）\n"

    total = sum(data.values())
    items = sorted(data.items(), key=lambda kv: -kv[1])[:top]

    lines = [f"\n{title}", "=" * len(title)]
    for label, value in items:
        pct = (value / total * 100) if total else 0
        shown = label if len(label) <= 15 else label[:14] + "…"
        lines.append(f"{shown:<15} {pct:>5.1f}%  {'█' * int(pct / 2)} ({value})")
    return "\n".join(lines) + "\n"


def render_summary(prefix: str) -> str:
    """根据分析结果前缀，生成用户名、密码、命令三张图。"""
    blocks = []

    users = read_count_file(Path(f"{prefix}.top_usernames.txt"))
    if users:
        blocks.append(bar_chart("用户名登录尝试统计", users))

    passwords = read_count_file(Path(f"{prefix}.top_passwords.txt"))
    if passwords:
        blocks.append(share_chart("密码尝试分布", passwords))

    commands = read_count_file(Path(f"{prefix}.top_commands.txt"))
    if commands:
        blocks.append(bar_chart("命令执行统计", commands))

    return "\n".join(blocks)


def main():
    if len(sys.argv) < 2:
        print("用法: python3 visualizer.py <分析结果前缀>", file=sys.stderr)
        print("示例: python3 visualizer.py reports/analysis_20261027_143000", file=sys.stderr)
        sys.exit(1)

    output = render_summary(sys.argv[1])
    if output.strip():
        print(output)
    else:
        print("（没有可供绘图的统计数据）", file=sys.stderr)


if __name__ == '__main__':
    main()
