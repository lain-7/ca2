# SPDX-License-Identifier: BSD-3-Clause
# -*- coding: utf-8 -*-
"""改造 7：为 Cowrie 补充 sed 的实现（常用子集）。

背景
----
Cowrie 原本没有 commands/sed.py，因此执行 sed 会掉进"通用二进制"回落：

    -bash: /usr/bin/sed: cannot execute binary file: Exec format error

sed 是 POSIX 必备工具，真实系统不可能无法执行。这是决定性指纹。

实现范围
--------
只实现攻击者在蜜罐里最常敲的那部分（不是完整 sed）：

    sed -n 1p file          打印第 1 行
    sed -n 1,5p file        打印 1-5 行
    sed 's/a/b/' file       替换每行第一个
    sed 's/a/b/g' file      替换全部
    sed -n '/pat/p' file    打印匹配行
    sed 'N d' file          删除指定行
    sed '1,3d' file         删除 1-3 行
    sed -e ... -e ...       多个表达式
    管道输入                echo x | sed 's/x/y/'

不支持的东西（会明确报错，而不是静默失败）：
    分支命令 b/t、保持空间 h/H/g/G/x、地址范围组合、正则高级语法

为什么不用真 sed：蜜罐的整个设计就是"不执行真实二进制"。
如果真调用 /usr/bin/sed，就把宿主机的 sed 暴露给了攻击者，
同时失去所有日志记录能力。
"""

from __future__ import annotations

import re

from cowrie.shell.command import HoneyPotCommand

commands = {}


class Command_sed(HoneyPotCommand):
    """sed —— 流编辑器（常用子集）。"""

    def _parse_script(self, script: str) -> dict:
        """把 sed 脚本解析成一个简单的操作描述。

        支持用 ; 或换行分隔的多条命令，按顺序执行。
        """
        ops = []

        for part in re.split(r"[;\n]", script):
            part = part.strip()
            if not part:
                continue

            # ---- s/// 替换 ----
            m = re.match(r"^s(.)(.*?)\1(.*?)\1([gGiI0-9]*)$", part)
            if m:
                _delim, pattern, repl, flags = m.groups()
                ops.append({
                    "type": "sub",
                    "pattern": pattern,
                    "repl": repl,
                    "global": "g" in flags.lower(),
                    "ignorecase": "i" in flags.lower(),
                })
                continue

            # ---- [addr]d 删除 ----
            m = re.match(r"^(?:(\d+)(?:,(\d+))?)?d$", part)
            if m:
                ops.append({
                    "type": "delete",
                    "start": int(m.group(1)) if m.group(1) else None,
                    "end": int(m.group(2)) if m.group(2) else
                           (int(m.group(1)) if m.group(1) else None),
                })
                continue

            # ---- [addr]p 打印 ----
            m = re.match(r"^(?:(\d+)(?:,(\d+))?)?p$", part)
            if m:
                ops.append({
                    "type": "print",
                    "start": int(m.group(1)) if m.group(1) else None,
                    "end": int(m.group(2)) if m.group(2) else
                           (int(m.group(1)) if m.group(1) else None),
                })
                continue

            # ---- /pattern/p 打印匹配行 ----
            m = re.match(r"^/(.*?)/p$", part)
            if m:
                ops.append({"type": "print_match", "pattern": m.group(1)})
                continue

            # ---- /pattern/d 删除匹配行 ----
            m = re.match(r"^/(.*?)/d$", part)
            if m:
                ops.append({"type": "delete_match", "pattern": m.group(1)})
                continue

            # 不认识 → 记录下来，运行时报错
            ops.append({"type": "unknown", "raw": part})

        return {"ops": ops}

    def _line_in_range(self, lineno: int, start, end) -> bool:
        """判断行号是否落在 [start, end] 区间（1 起）。"""
        if start is None:
            return True
        if end is None:
            end = start
        return start <= lineno <= end

    def _apply(self, lines: list[str], script: dict) -> tuple[list[str], bool]:
        """执行脚本。返回 (输出行, 是否显式要求打印)。"""
        ops = script["ops"]

        # -n 模式：只有 p / print_match 会产生输出
        auto_print = not self.quiet

        result: list[str] = []
        delete_all = False

        for lineno, line in enumerate(lines, start=1):
            current = line
            deleted = False
            printed = False

            for op in ops:
                t = op["type"]

                if t == "sub":
                    flags = re.IGNORECASE if op["ignorecase"] else 0
                    try:
                        pattern = re.compile(op["pattern"], flags)
                    except re.error:
                        continue
                    count = 0 if op["global"] else 1
                    current = pattern.sub(op["repl"], current, count=count)

                elif t == "delete":
                    if self._line_in_range(lineno, op["start"], op["end"]):
                        deleted = True

                elif t == "delete_match":
                    try:
                        if re.search(op["pattern"], current):
                            deleted = True
                    except re.error:
                        pass

                elif t == "print":
                    if self._line_in_range(lineno, op["start"], op["end"]):
                        printed = True

                elif t == "print_match":
                    try:
                        if re.search(op["pattern"], current):
                            printed = True
                    except re.error:
                        pass

                elif t == "unknown":
                    self.errorWrite(
                        f"sed: -e expression #1, char 1: unknown command: "
                        f"`{op['raw'][:1]}'\n"
                    )
                    deleted = True

            if deleted:
                continue

            if current != line or printed:
                # 有替换或被显式要求打印，输出这一行
                result.append(current)
                if printed and auto_print:
                    pass  # 已经加进去了，避免重复
            elif auto_print:
                result.append(current)

        return result, not auto_print

    def call(self) -> None:
        self.quiet = False          # -n
        self.extended = False       # -E / -r
        self.in_place = False       # -i
        scripts: list[str] = []
        files: list[str] = []

        args = list(self.args)

        # ---- 解析选项 ----
        i = 0
        while i < len(args):
            a = args[i]
            if a == "-n":
                self.quiet = True
            elif a in ("-E", "-r", "--regexp-extended"):
                self.extended = True
            elif a.startswith("-i"):
                self.in_place = True
            elif a == "-e":
                i += 1
                if i < len(args):
                    scripts.append(args[i])
            elif a.startswith("-e") and len(a) > 2:
                scripts.append(a[2:])
            elif a == "--":
                files.extend(args[i + 1:])
                break
            elif a.startswith("-") and len(a) > 1 and not a[1].isdigit():
                # 合并的单字母选项，如 -ne
                for ch in a[1:]:
                    if ch == "n":
                        self.quiet = True
                    elif ch in ("E", "r"):
                        self.extended = True
                    elif ch == "i":
                        self.in_place = True
            else:
                files.append(a)
            i += 1

        # ---- 第一个非选项参数是脚本（没有 -e 时）----
        if not scripts:
            if not files:
                self.errorWrite("Usage: sed [OPTION]... {script-only-if-no-other-script} "
                                "[input-file]...\n")
                self.exit(1)
                return
            scripts.append(files.pop(0))

        if self.in_place:
            self.errorWrite(
                "sed: -i: in-place editing is not supported on this system\n"
            )
            self.exit(1)
            return

        script = self._parse_script(";".join(scripts))

        # ---- 取输入 ----
        if files:
            for fname in files:
                path = self.fs.resolve_path(fname, self.cwd)
                if not self.fs.exists(path) or not self.fs.isfile(path):
                    self.errorWrite(
                        f"sed: can't read {fname}: No such file or directory\n"
                    )
                    self.exit(1)
                    return
                data = self.fs.file_contents(path)
                text = data.decode("utf-8", errors="replace")
                lines = text.split("\n")
                if lines and lines[-1] == "":
                    lines.pop()
                out, _ = self._apply(lines, script)
                for ln in out:
                    self.write(ln + "\n")
        elif self.input_data is not None:
            text = self.input_data.decode("utf-8", errors="replace")
            lines = text.split("\n")
            if lines and lines[-1] == "":
                lines.pop()
            out, _ = self._apply(lines, script)
            for ln in out:
                self.write(ln + "\n")
        else:
            self.errorWrite("sed: no input files\n")
            self.exit(1)
            return

        self.exit(0)

    def lineReceived(self, line) -> None:
        # 支持通过管道/stdin 逐行喂入
        if not hasattr(self, "_stdin"):
            self._stdin = []
        self._stdin.append(line)

    def eofReceived(self) -> None:
        self.exit(0)


commands["/bin/sed"] = Command_sed
commands["/usr/bin/sed"] = Command_sed
commands["sed"] = Command_sed
