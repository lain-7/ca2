# 防守分析工具 (Defense Analysis)

本目录包含用于分析 Cowrie 蜜罐日志、溯源攻击 IP、生成安全报告的工具。

## 目录结构

```
defense/
├── analyze_logs.sh          # 主日志分析脚本
├── ip_tracker.py            # IP 地理位置和威胁情报查询
├── report_generator.py      # 详细报告生成器
├── lib/                     # 公共库和缓存
│   └── ip_cache.json        # IP 查询缓存（运行时生成）
└── reports/                 # 分析报告输出目录（运行时生成）
```

## 功能特性

- ✅ 解析 Cowrie JSON 日志
- ✅ 提取登录尝试、成功登录、命令执行记录
- ✅ IP 地理位置溯源（国家、城市、ISP）
- ✅ 威胁等级评估
- ✅ 生成统计图表数据
- ✅ 导出 Markdown 格式详细报告
- ✅ 中文输出和注释

## 依赖项

```bash
# Arch Linux
sudo pacman -S jq python curl

# Ubuntu/Debian
sudo apt install jq python3 curl
```

Python 标准库即可，无需额外 pip 包。

## 使用方法

### 1. 完整分析流程

```bash
# 自动查找最新的 Cowrie 日志
./analyze_logs.sh /home/cowrie/cowrie/var/log/cowrie

# 或者让脚本使用默认路径
./analyze_logs.sh
```

### 2. 单独使用 IP 溯源工具

```bash
# 查询单个 IP
./ip_tracker.py 8.8.8.8

# 查询多个 IP
./ip_tracker.py 8.8.8.8 1.1.1.1 192.168.1.1

# 从文件读取 IP 列表
./ip_tracker.py --file ip_list.txt

# 输出 JSON 格式
./ip_tracker.py --json 8.8.8.8 > result.json

# 禁用缓存（每次都重新查询）
./ip_tracker.py --no-cache 8.8.8.8
```

### 3. 单独生成报告

```bash
# 基于已有分析结果生成详细报告
./report_generator.py ./reports/analysis_20261026_120000
```

## 输出文件

每次运行 `analyze_logs.sh` 会生成一组带时间戳的文件：

```
reports/
└── analysis_20261026_120000.*
    ├── logins.tsv                # 所有登录尝试（TSV 格式）
    ├── successful_logins.tsv     # 成功登录记录
    ├── commands.tsv              # 命令执行记录
    ├── ips.txt                   # 唯一 IP 列表
    ├── ip_enrichment.json        # IP 溯源结果（JSON）
    ├── top_usernames.txt         # 高频用户名统计
    ├── top_passwords.txt         # 高频密码统计
    ├── top_commands.txt          # 高频命令统计
    ├── summary.txt               # 摘要报告（纯文本）
    └── report.md                 # 详细报告（Markdown）
```

## 分析报告内容

生成的 Markdown 报告包含以下章节：

1. **执行摘要** - 登录尝试统计、成功率、命令数量、IP 数量
2. **攻击时间线** - 首次/最后攻击时间、成功登录详情
3. **凭据分析** - Top 15 用户名和密码统计
4. **命令分析** - Top 20 命令、命令分类（侦察/文件探测/网络探测等）
5. **攻击源分析** - 地理分布、ISP 分布、威胁等级、详细 IP 信息
6. **安全建议** - 基于分析结果的针对性建议

## IP 溯源说明

### 数据来源

使用 **ip-api.com** 免费 API（无需注册）：

- 查询限制：每分钟 45 次请求
- 脚本自动添加延迟（1.5 秒/次）避免超限
- 支持缓存机制减少重复查询

### 返回信息

- **地理位置**：国家、地区、城市
- **网络信息**：ISP、组织、AS 号
- **主机名**：反向 DNS 查询结果
- **威胁等级**：low / medium / high（基于规则自动评估）
- **标签**：private（内网）、cloud（云服务）、scanner（扫描器）、high-risk-region（高危地区）

### 威胁评估规则

- **内网 IP** → `low`
- **来自高危国家** (CN, RU, KP, IR) → `medium`
- **主机名包含 scanner/bot/crawler** → `medium`
- **其他** → `low`

### 缓存机制

- 查询结果缓存到 `lib/ip_cache.json`
- 下次查询相同 IP 直接读缓存，无需重复请求
- 使用 `--no-cache` 参数可跳过缓存

## 命令分析分类

脚本会自动将命令归类到以下类别：

| 类别 | 关键词 | 说明 |
|------|--------|------|
| 侦察类 | whoami, uname, hostname, ps, w | 身份和系统信息探测 |
| 文件探测 | ls, cat, find, locate | 文件系统侦察 |
| 系统信息 | df, free, /etc/os-release | 系统资源和配置 |
| 网络探测 | netstat, ss, ping, wget, curl | 网络连接和下载 |
| 权限提升 | sudo, su, chmod +x | 提权尝试 |
| 持久化 | crontab, .bash_history | 后门和痕迹 |

## 示例输出

### 终端输出（摘要报告）

```
╔════════════════════════════════════════════════════════════╗
║        Cowrie 蜜罐日志分析工具 v1.0                       ║
║        Honeypot Log Analysis Tool                          ║
╚════════════════════════════════════════════════════════════╝

[2026-10-26 12:00:00] [INFO] ========== 日志分析开始 ==========
[2026-10-26 12:00:00] [INFO] 日志文件: /home/cowrie/cowrie/var/log/cowrie/cowrie.json
[2026-10-26 12:00:01] [INFO] 发现 24 次登录尝试
[2026-10-26 12:00:01] [INFO] 发现 6 次成功登录
[2026-10-26 12:00:01] [INFO] 发现 85 条命令执行记录
[2026-10-26 12:00:01] [INFO] 发现 3 个唯一 IP 地址

正在查询 3 个唯一 IP...
[1/3] 查询 192.168.122.1...
[2/3] 查询 8.8.8.8...
[3/3] 查询 1.2.3.4...

==================== 攻击概览 ====================
总登录尝试: 24 次
  ├─ 失败: 18 次
  └─ 成功: 6 次
成功率: 25.00%

命令执行总数: 85 条
唯一命令数: 18 个

攻击源 IP 数量: 3 个
  ├─ 内网 IP: 1 个
  └─ 外网 IP: 2 个

==================== TOP 10 用户名 ====================
       6 次   root
       5 次   admin
       4 次   ubuntu
...

详细报告已生成: ./reports/analysis_20261026_120000.report.md
```

### IP 溯源输出

```
============================================================
IP 地址: 1.2.3.4
主机名: unknown-1-2-3-4.example.com
国家: 美国 (US)
地区: California
城市: Los Angeles
ISP: Example ISP Inc.
组织: EXAMPLE-AS
AS 号: AS12345
威胁等级: LOW
标签: cloud
```

## 故障排查

### jq 命令未找到

```bash
# 检查是否安装
which jq

# 安装
sudo pacman -S jq
```

### IP 查询失败

```bash
# 手动测试 API
curl -s "http://ip-api.com/json/8.8.8.8"

# 检查网络连接
ping -c 3 ip-api.com
```

### Cowrie 日志路径错误

```bash
# 查找实际路径
sudo find / -name "cowrie.json" 2>/dev/null

# 指定正确路径
./analyze_logs.sh /path/to/cowrie/log/dir
```

### Python 版本问题

脚本需要 **Python 3.6+**：

```bash
# 检查版本
python3 --version

# 如果版本过低，升级系统或使用 pyenv
```

## 高级用法

### 自动化定期分析

创建 cron 任务每天分析一次：

```bash
# 编辑 crontab
crontab -e

# 添加任务（每天凌晨 2 点执行）
0 2 * * * /path/to/defense/analyze_logs.sh /home/cowrie/cowrie/var/log/cowrie >> /var/log/honeypot_analysis.log 2>&1
```

### 集成到监控系统

```bash
# 输出 JSON 格式供其他工具使用
./ip_tracker.py --file ips.txt --json | jq '.[] | select(.threat_level == "high")'
```

### 批量处理历史日志

```bash
# 分析所有历史日志
for log in /home/cowrie/cowrie/var/log/cowrie/cowrie.json*; do
    echo "分析: $log"
    ./analyze_logs.sh $(dirname "$log")
done
```

## API 速率限制

ip-api.com 免费服务的限制：

- **45 次请求/分钟**（脚本已设置 1.5 秒延迟）
- **HTTPS 需要付费**（脚本使用 HTTP）
- **商业用途需购买许可**

如需更高配额，考虑：

1. 注册 [ipapi.co](https://ipapi.co/)（免费 1000 次/天）
2. 使用 [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) 本地数据库
3. 购买 ip-api.com 高级版

## 技术细节

- **日志解析**：使用 `jq` 处理 Cowrie JSON 格式日志
- **IP 查询**：通过 `curl` 调用 REST API，避免依赖 Python requests 库
- **反向 DNS**：使用 Python `socket.gethostbyaddr()`
- **缓存机制**：JSON 文件存储，自动去重和过期管理
- **速率限制**：自动添加延迟，避免触发 API 限流

## 隐私和安全

⚠️ **注意事项**

- IP 查询会向第三方 API 发送 IP 地址
- 建议仅在**测试/内网环境**使用
- **生产环境**建议使用本地 GeoIP 数据库
- 报告中可能包含敏感信息（密码、命令），请妥善保管

## 参考资料

- [Cowrie 日志格式文档](https://cowrie.readthedocs.io/en/latest/LOGFILE.html)
- [ip-api.com API 文档](https://ip-api.com/docs)
- [jq 手册](https://stedolan.github.io/jq/manual/)
- [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)

## 贡献与反馈

如有问题或改进建议，请联系项目组成员。
