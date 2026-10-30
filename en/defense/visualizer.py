#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Data visualisation module
Reads the statistics files produced by analyze_logs.sh and prints ASCII bar and share charts in the terminal.
Standard library only.
"""

import sys
from pathlib import Path
from typing import Dict


def read_count_file(path: Path) -> Dict[str, int]:
    """
    Read a statistics file in "count label" format (output of uniq -c).

    Args:
        path: path to the statistics file

    Returns:
        {label: count} dict; empty dict if the file does not exist
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
    """Build an ASCII bar chart (sorted by count descending, at most top rows)."""
    if not data:
        return f"\n{title}\n{'=' * len(title)}\n(no data)\n"

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
    """Build an ASCII share chart (percentage of each item)."""
    if not data:
        return f"\n{title}\n{'=' * len(title)}\n(no data)\n"

    total = sum(data.values())
    items = sorted(data.items(), key=lambda kv: -kv[1])[:top]

    lines = [f"\n{title}", "=" * len(title)]
    for label, value in items:
        pct = (value / total * 100) if total else 0
        shown = label if len(label) <= 15 else label[:14] + "…"
        lines.append(f"{shown:<15} {pct:>5.1f}%  {'█' * int(pct / 2)} ({value})")
    return "\n".join(lines) + "\n"


def render_summary(prefix: str) -> str:
    """Build the username, password and command charts from an analysis result prefix."""
    blocks = []

    users = read_count_file(Path(f"{prefix}.top_usernames.txt"))
    if users:
        blocks.append(bar_chart("Login Attempts by Username", users))

    passwords = read_count_file(Path(f"{prefix}.top_passwords.txt"))
    if passwords:
        blocks.append(share_chart("Password Attempt Distribution", passwords))

    commands = read_count_file(Path(f"{prefix}.top_commands.txt"))
    if commands:
        blocks.append(bar_chart("Command Execution Counts", commands))

    return "\n".join(blocks)


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 visualizer.py <analysis result prefix>", file=sys.stderr)
        print("Example: python3 visualizer.py reports/analysis_20261027_143000", file=sys.stderr)
        sys.exit(1)

    output = render_summary(sys.argv[1])
    if output.strip():
        print(output)
    else:
        print("(no statistics available to plot)", file=sys.stderr)


if __name__ == '__main__':
    main()
