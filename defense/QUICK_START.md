# 防守分析工具 - 快速开始指南

本指南将帮你快速使用防守工具分析 Cowrie 蜜罐日志。

## 📋 前置要求

### 依赖工具
```bash
# Arch Linux
sudo pacman -S jq python curl

# Ubuntu/Debian
sudo apt install jq python3 curl
```

### 获取 Cowrie 日志
Cowrie 的日志文件通常位于：
```
/home/cowrie/cowrie/var/log/cowrie/cowrie.json
```

## 🚀 基础使用（3 步）

### 第 1 步：运行日志分析
```bash
# 使用默认日志路径
./analyze_logs.sh

# 或指定自定义路径
./analyze_logs.sh /path/to/cowrie/logs
```

**输出说明**:
- 终端显示摘要统计和可视化图表
- 生成 `reports/analysis_YYYYMMDD_HHMMSS/` 目录，包含：
  - `summary.txt` - 文本摘要报告
  - `report.md` - 详细 Markdown 报告
  - `*.tsv` 文件 - 原始数据（用于进一步分析）

### 第 2 步：查看摘要报告
```bash
# 显示最新的摘要报告
cat reports/analysis_*/summary.txt | tail -1
```

### 第 3 步：查看详细报告
```bash
# 在 Markdown 查看器中打开详细报告
cat reports/analysis_*/report.md

# 或转换为 HTML（如果安装了 pandoc）
pandoc reports/analysis_*/report.md -o report.html
```

## 🔍 详细分析功能

### 1. 登录尝试分析
自动提取和统计：
- 总登录尝试数
- 成功/失败次数
- 成功率百分比
- Top 10 用户名
- Top 10 密码

**输出文件**:
```
reports/analysis_*/logins.tsv          # 完整登录日志
reports/analysis_*/top_usernames.txt   # 用户名统计
reports/analysis_*/top_passwords.txt   # 密码统计
```

### 2. 命令执行分析
自动分类命令为：
- **侦察类** - whoami, uname, ps, w 等
- **文件探测** - ls, cat, find 等
- **系统信息** - df, free, /etc/os-release 等
- **网络探测** - netstat, ss, ping, curl 等
- **权限提升** - sudo, su, chmod 等
- **持久化** - crontab, bash_history, echo 等

**输出文件**:
```
reports/analysis_*/commands.tsv        # 完整命令日志
reports/analysis_*/top_commands.txt    # 命令统计
```

### 3. IP 溯源分析
自动查询每个攻击源 IP 的：
- 地理位置（国家、城市、ISP）
- 威胁等级评估（low / medium / high）
- 云服务标签识别
- 反向 DNS 主机名

**输出文件**:
```
reports/analysis_*/ip_enrichment.json  # IP 详细信息（JSON）
defense/lib/ip_cache.json              # IP 缓存（加快后续查询）
```

## 🎨 生成的图表

分析过程会自动生成以下 ASCII 图表：

### 1. 用户名统计柱状图
```
用户名登录尝试统计
===================
root     | ████████████████ 45
admin    | ██████████ 28
ubuntu   | ██████ 18
...
```

### 2. 密码分布饼图
```
密码尝试分布
============
password     100.0% █████████ (28)
123456       71.4% ██████ (20)
admin123     35.7% ███ (10)
...
```

### 3. 命令执行统计
```
命令执行统计
============
ls            | ███████████ 24
pwd           | ████████ 16
whoami        | ██████ 12
...
```

## 💡 高级用法

### 手动查询 IP 信息
```bash
# 查询单个 IP
./ip_tracker.py 8.8.8.8

# 查询多个 IP
./ip_tracker.py 192.168.1.1 8.8.8.8 1.1.1.1

# 从文件读取 IP 列表
./ip_tracker.py --file ips.txt

# 输出 JSON 格式（便于进一步处理）
./ip_tracker.py --json 8.8.8.8 > results.json

# 禁用缓存（强制重新查询）
./ip_tracker.py --no-cache 8.8.8.8
```

### 生成 HTML 可视化报告（高级）

如果需要生成更专业的 HTML 报告，可以手动调用可视化工具：
```bash
python3 visualizer.py reports/analysis_20261027_123456
```

### 批量分析历史日志
```bash
# 分析所有历史日志文件
for log in /path/to/cowrie/logs/cowrie.json*; do
    echo "分析: $log"
    ./analyze_logs.sh $(dirname "$log")
done
```

### 定期自动分析（Crontab）
```bash
# 每天凌晨 2 点自动分析
0 2 * * * /path/to/defense/analyze_logs.sh >> /var/log/honeypot_analysis.log 2>&1

# 每小时分析一次
0 * * * * /path/to/defense/analyze_logs.sh >> /var/log/honeypot_analysis.log 2>&1
```

## 📊 分析结果解读

### 成功率评估
```
成功登录 6 / 总尝试 24 = 25% 成功率
```
- **>50%** - 蜜罐防护极弱，有明显的弱密码
- **10-50%** - 蜜罐防护中等，有一些容易猜测的账户
- **<10%** - 蜜罐防护较好，攻击难度较大

### 威胁等级判断
基于 IP 信息自动评估：
- **LOW** - 内网 IP、已知云服务商、正常 ISP
- **MEDIUM** - 来自高危国家、主机名包含 scanner/bot 关键词
- **HIGH** - 预留字段，可扩展为包含 IP 信誉数据库

### 命令分析结论
观察攻击者执行的命令类型，推断其意图：
- 只有侦察类命令 → 信息收集阶段
- 包含文件探测和网络探测 → 环境探索阶段
- 包含权限提升或持久化命令 → 试图获取更高权限或建立后门

## 🐛 常见问题解决

### 问题 1：找不到 curl 工具
```bash
# 错误: 未找到 curl 工具
# 解决方案
sudo pacman -S curl      # Arch Linux
sudo apt install curl    # Ubuntu/Debian
```

### 问题 2：IP 查询速度慢
```bash
# IP 查询默认限速 1.5 秒/次（避免触发 API 限流）
# 如果只需要本地信息，可禁用 IP 查询
# 编辑 analyze_logs.sh，注释掉 enrich_ips 函数调用
```

### 问题 3：找不到 Cowrie 日志
```bash
# 检查 Cowrie 日志的实际位置
find / -name "cowrie.json" 2>/dev/null

# 确保有读取权限
ls -la /home/cowrie/cowrie/var/log/cowrie/
```

### 问题 4：权限被拒绝
```bash
# 确保脚本可执行
chmod +x analyze_logs.sh ip_tracker.py report_generator.py visualizer.py

# 如果需要读取 Cowrie 日志
sudo cat /home/cowrie/cowrie/var/log/cowrie/cowrie.json | ./analyze_logs.sh
```

## 📝 输出示例

运行 `./analyze_logs.sh` 后的典型输出：

```
╔════════════════════════════════════════════════════════════╗
║        Cowrie 蜜罐日志分析工具 v1.0                       ║
║        Honeypot Log Analysis Tool                          ║
╚════════════════════════════════════════════════════════════╝

[2026-10-27 14:30:00] [INFO] ========== 日志分析开始 ==========
[2026-10-27 14:30:00] [INFO] 日志文件: /home/cowrie/cowrie/var/log/cowrie/cowrie.json
[2026-10-27 14:30:01] [INFO] 发现 24 次登录尝试
[2026-10-27 14:30:01] [INFO] 发现 6 次成功登录
[2026-10-27 14:30:01] [INFO] 发现 85 条命令执行记录
[2026-10-27 14:30:01] [INFO] 发现 3 个唯一 IP 地址

正在查询 3 个唯一 IP...
[1/3] 查询 192.168.122.1...
[2/3] 查询 8.8.8.8...
[3/3] 查询 1.2.3.4...

================== 攻击概览 ==================
总登录尝试: 24 次
  ├─ 失败: 18 次
  └─ 成功: 6 次
成功率: 25.00%

命令执行总数: 85 条
唯一命令数: 18 个

...

用户名登录尝试统计
=================
root     | ████████████████ 12
admin    | ██████████ 8
ubuntu   | ████████ 6
...

[2026-10-27 14:30:05] [INFO] 生成摘要报告...
[2026-10-27 14:30:05] [INFO] 摘要报告生成完成: ./reports/analysis_20261027_143000.summary.txt
[2026-10-27 14:30:06] [INFO] ========== 分析完成 ==========
[2026-10-27 14:30:06] [INFO] 生成详细报告...
详细报告已生成: ./reports/analysis_20261027_143000.report.md
```

## 📚 文件结构

```
defense/
├── analyze_logs.sh          # 主分析脚本（建议先从这里开始）
├── ip_tracker.py            # IP 溯源工具
├── report_generator.py      # 报告生成器
├── visualizer.py            # 可视化工具
├── lib/                      # 库目录（自动生成）
│   └── ip_cache.json        # IP 查询缓存
├── reports/                  # 分析报告输出（自动生成）
│   └── analysis_YYYYMMDD_HHMMSS/
│       ├── summary.txt
│       ├── report.md
│       ├── logins.tsv
│       ├── commands.tsv
│       └── ...
├── README.md                # 详细文档
├── QUICK_START.md           # 快速开始（本文件）
└── test_data/               # 测试数据（可选）
```

## ✅ 检查清单

运行分析前，确认以下条件：

- [ ] 已安装 jq、python3、curl
- [ ] Cowrie 日志文件存在且可读
- [ ] 网络连接正常（用于 IP 溯源）
- [ ] 磁盘空间充足（输出报告）
- [ ] 脚本具有可执行权限

## 🤝 获取帮助

如遇问题，检查：
1. `./analyze_logs.sh` 输出的错误信息
2. 本文件的"常见问题解决"部分
3. 详细文档 `README.md`

---

**最后更新**: 2026-10-27  
**工具版本**: 1.0  
**作者**: Cowrie 防守分析小组
