# 防守方日志分析 - 使用指南

这是防守分析工具集的快速使用指南。适合直接上手，快速完成 CA2 作业的**任务 4（日志分析）**部分。

## ⚡ 3 分钟快速开始

### 1️⃣ 确保依赖已安装
```bash
# 检查是否有 jq, python3, curl
which jq python3 curl

# 如果缺少，安装它们：
# Arch Linux
sudo pacman -S jq python curl

# Ubuntu/Debian
sudo apt install jq python3 curl
```

### 2️⃣ 运行日志分析
```bash
cd defense/
./analyze_logs.sh /path/to/cowrie/logs
```

**不知道 Cowrie 日志在哪里？** 通常是：
```
/home/cowrie/cowrie/var/log/cowrie
```

或让脚本自动查找：
```bash
./analyze_logs.sh  # 不加参数，脚本会查找默认位置
```

### 3️⃣ 查看分析结果
```bash
# 摘要报告（纯文本）
cat reports/analysis_*/summary.txt

# 详细报告（Markdown 格式）
cat reports/analysis_*/report.md

# 或用编辑器打开
vim reports/analysis_*/report.md
```

## 📊 你会得到什么

运行完后，自动生成的分析结果包括：

### 📈 可视化数据
- **用户名统计柱状图** - 哪些账户被最常尝试
- **密码分布饼图** - 最流行的弱密码
- **命令执行统计** - 攻击者最常执行的命令

### 📋 详细统计数据
- 登录尝试总数、成功次数、成功率
- Top 15 用户名
- Top 15 密码
- Top 20 命令

### 🌍 IP 地理位置分析
- 攻击源 IP 的国家、城市、ISP
- 威胁等级评估（LOW/MEDIUM/HIGH）
- 云服务识别（Google、AWS 等）

### 🛡️ 安全建议
生成的报告包含 6 条针对性的安全建议：
1. 强密码策略
2. SSH 访问控制
3. 多因素认证
4. 入侵检测部署
5. 定期安全更新
6. 网络隔离（如需要）

每条建议都包括：
- ❓ **为什么需要** - 分析发现的依据
- 🎯 **具体措施** - 可执行的步骤
- 📊 **预期效果** - 改进程度

## 📁 输出文件说明

```
reports/
└── analysis_20261027_143000/          ← 生成的分析目录（带时间戳）
    ├── summary.txt                    ← 【主要】摘要报告（纯文本）
    ├── report.md                      ← 【主要】详细报告（Markdown）
    │
    ├── logins.tsv                     ← 【原始数据】所有登录尝试
    ├── successful_logins.tsv          ← 【原始数据】成功登录
    ├── commands.tsv                   ← 【原始数据】命令执行
    ├── ips.txt                        ← 【原始数据】唯一 IP 列表
    │
    ├── top_usernames.txt              ← 【统计数据】用户名排行
    ├── top_passwords.txt              ← 【统计数据】密码排行
    ├── top_commands.txt               ← 【统计数据】命令排行
    └── ip_enrichment.json             ← 【IP 溯源】地理位置和威胁情报
```

**推荐用于报告的文件**：
- `summary.txt` - 放在 Word 报告的"日志分析"章节
- `report.md` - 转换为 HTML 或复制内容到报告

## 🔧 常见操作

### 将 Markdown 报告转换为 Word 格式
```bash
# 需要先安装 pandoc
sudo apt install pandoc

# 转换为 Word
pandoc reports/analysis_*/report.md -o report.docx

# 转换为 HTML（用浏览器打开）
pandoc reports/analysis_*/report.md -o report.html
```

### 查询特定 IP 的详细信息
```bash
# 单个 IP
./ip_tracker.py 8.8.8.8

# 多个 IP
./ip_tracker.py 192.168.1.1 8.8.8.8 1.1.1.1

# 从文件读取 IP 列表
cat reports/analysis_*/ips.txt | ./ip_tracker.py --file /dev/stdin

# JSON 格式（便于数据处理）
./ip_tracker.py --json 8.8.8.8 | python3 -m json.tool
```

### 分析多个日志文件
```bash
# 分析最新的日志
./analyze_logs.sh

# 分析特定日期范围的日志（如果有多个 cowrie.json 文件）
./analyze_logs.sh /path/to/cowrie/logs/cowrie.json.2026-10-25
```

## ⚠️ 注意事项

### IP 查询速度
- 首次查询会比较慢（需要联网查询 IP 信息）
- 之后的相同 IP 查询会很快（使用本地缓存）
- 自动限速避免 API 限流（1.5 秒/个 IP）

### 数据隐私
- IP 溯源会向 ip-api.com 发送 IP 地址
- 日志中包含凭据和命令信息，请妥善保管
- 生产环境推荐使用本地 GeoIP 数据库

### 网络要求
- 需要网络连接才能进行 IP 溯源
- 如果无法访问 ip-api.com，脚本会自动跳过该步骤
- 可用 `--no-cache` 强制重新查询

## 📚 深入了解

想了解更多细节？查看：

| 文件 | 用途 |
|------|------|
| `QUICK_START.md` | 详细的快速开始指南 |
| `README.md` | 完整的工具文档 |
| `TOOLS_OVERVIEW.md` | 工具架构和工作原理 |

## 🎯 对应作业要求

本工具集完全满足 **CA2 Task 4（日志分析）** 的要求：

- ✅ 登录分析
  - 总登录尝试数
  - 最常被使用的用户名（Top 15）
  - 最常被使用的密码（Top 15）
  - 成功登录次数和成功率

- ✅ 命令分析
  - 最常被执行的命令（Top 20）
  - 命令分类和目的说明

- ✅ 威胁分析
  - 攻击者能从被攻陷的系统中学到什么
  - 对组织有哪些风险

- ✅ 数据可视化（至少 3 个）
  - 📊 柱状图（用户名、命令统计）
  - 📈 饼图（密码分布、威胁等级）
  - 📉 ASCII 图表（终端输出）

- ✅ 安全建议
  - 6 条安全建议
  - 每条附带具体解释和实施措施

## ❓ 有问题？

### 脚本无法运行
```bash
# 检查权限
chmod +x *.sh *.py

# 检查依赖
which jq python3 curl

# 查看详细错误
bash -x analyze_logs.sh
```

### IP 查询失败
```bash
# 检查网络连接
ping -c 1 ip-api.com

# 禁用 IP 查询重试（编辑 analyze_logs.sh，注释 enrich_ips 函数调用）
```

### 日志文件错误
```bash
# 检查文件是否存在
ls -la /home/cowrie/cowrie/var/log/cowrie/

# 检查文件格式（应该是 JSON 格式）
head -1 /path/to/cowrie.json | jq .
```

---

**记住**：这些工具的目的是**自动化和加快分析过程**。你仍然需要理解分析结果，并基于发现的数据编写自己的分析文本和建议。

祝你的小组作业顺利！🎓
