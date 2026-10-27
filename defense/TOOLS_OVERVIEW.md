# 防守分析工具集完整说明

## 概述

本防守工具集包含四个核心组件，用于 Cowrie SSH 蜜罐的日志分析、威胁评估和报告生成。

## 工具架构

```
Cowrie 日志（JSON）
    ↓
[analyze_logs.sh] ← 主控脚本，协调所有工具
    ├─→ [jq] 解析日志，提取关键信息
    ├─→ [ip_tracker.py] IP 溯源与威胁评估
    ├─→ [visualizer.py] 数据可视化（图表生成）
    ├─→ [report_generator.py] 生成详细分析报告
    └─→ [reports/] 输出分析结果
```

## 四个核心工具详解

### 1. analyze_logs.sh（主分析脚本）

**职责**：协调所有工具，自动化完整的分析流程。

**功能流程**：
```
初始化 → 检查依赖 → 解析日志 → IP 溯源 → 生成图表 → 生成报告
```

**关键特性**：
- 自动定位 Cowrie 日志文件
- 流式处理大型日志文件（节省内存）
- 自动重试机制（网络超时时）
- 详细的进度日志输出

**使用方法**：
```bash
# 使用默认日志路径
./analyze_logs.sh

# 指定自定义路径
./analyze_logs.sh /path/to/cowrie/logs

# 支持符号链接和通配符
./analyze_logs.sh /mnt/logs/cowrie.json*
```

**输出结构**：
```
reports/
└── analysis_20261027_143000/
    ├── logins.tsv                  ← 所有登录尝试
    ├── successful_logins.tsv       ← 成功登录
    ├── commands.tsv                ← 命令执行
    ├── ips.txt                     ← 唯一 IP 列表
    ├── ip_enrichment.json          ← IP 溯源结果
    ├── top_usernames.txt           ← 用户名统计
    ├── top_passwords.txt           ← 密码统计
    ├── top_commands.txt            ← 命令统计
    ├── summary.txt                 ← 摘要报告
    └── report.md                   ← 详细报告
```

---

### 2. ip_tracker.py（IP 溯源工具）

**职责**：查询 IP 地理位置和威胁情报。

**数据来源**：
- **地理位置**: ip-api.com（免费 API，无需 KEY）
- **反向 DNS**: Python socket 库
- **威胁评估**: 本地规则引擎

**API 限制**：
- 免费版本：45 请求/分钟
- 脚本自动限速：1.5 秒/请求

**功能**：
```
IP 地址
  ├─ 内网/外网判断
  ├─ 地理位置查询（国家、城市、ISP）
  ├─ 反向 DNS 查询（主机名）
  └─ 威胁等级评估
      ├─ LOW - 内网、已知云服务、正常 ISP
      ├─ MEDIUM - 高危国家、扫描器主机名
      └─ HIGH - 预留扩展（可接入 IP 信誉库）
```

**独立使用方法**：
```bash
# 查询单个 IP
./ip_tracker.py 8.8.8.8

# 批量查询
./ip_tracker.py 8.8.8.8 1.1.1.1 192.168.1.1

# 从文件读取 IP（每行一个）
./ip_tracker.py --file ips.txt

# JSON 输出（便于下游处理）
./ip_tracker.py --json 8.8.8.8 > results.json

# 强制重新查询（禁用缓存）
./ip_tracker.py --no-cache 8.8.8.8
```

**缓存机制**：
- 查询结果自动保存至 `defense/lib/ip_cache.json`
- 相同 IP 的查询在 24 小时内使用缓存
- 可用 `--no-cache` 强制刷新

**威胁评估规则**：
```python
if is_internal_ip(ip):
    threat_level = "low"
elif country_code in ["CN", "RU", "KP", "IR"]:
    threat_level = "medium"
elif "scanner" in hostname or "bot" in hostname:
    threat_level = "medium"
else:
    threat_level = "low"
```

**输出格式**（JSON）：
```json
{
  "ip": "8.8.8.8",
  "is_internal": false,
  "hostname": "dns.google",
  "country": "美国",
  "country_code": "US",
  "region": "California",
  "city": "Los Angeles",
  "isp": "Google",
  "org": "Google",
  "as": "AS15169",
  "threat_level": "low",
  "tags": ["cloud"]
}
```

---

### 3. visualizer.py（数据可视化）

**职责**：生成 ASCII 图表和 HTML 图表。

**功能**：
```
分析结果（TSV/TXT）
        ↓
[visualizer.py]
        ├─ 柱状图（用户名、命令统计）
        ├─ 饼图（密码分布、威胁等级分布）
        └─ HTML 图表（使用 Chart.js）
```

**独立使用**：
```bash
# 从分析结果文件生成图表
./visualizer.py reports/analysis_20261027_143000

# 输出 ASCII 图表到终端
./visualizer.py reports/analysis_20261027_143000 | less
```

**生成的图表类型**：

#### 柱状图（Top 15）
```
用户名登录尝试统计
=================
root     | ████████████████ 45
admin    | ██████████ 28
ubuntu   | ██████ 18
test     | ████ 12
guest    | ██ 5
```

#### 饼图（百分比分布）
```
密码尝试分布
============
password     100.0% █████████ (28)
123456        71.4% ██████ (20)
admin123      35.7% ███ (10)
student123    28.6% ██ (8)
welcome       21.4% ██ (6)
```

#### 命令统计
```
命令执行统计
============
ls             | ████████████████ 24
pwd            | ████████ 16
whoami         | ██████ 12
cat /etc/passwd| ████████ 16
```

---

### 4. report_generator.py（报告生成）

**职责**：将分析数据转换成专业的 Markdown 报告。

**生成的报告包含**：

| 章节 | 内容 |
|------|------|
| 执行摘要 | 关键统计数据和威胁评估 |
| 攻击时间线 | 首次/最后攻击时间、成功登录详情 |
| 凭据分析 | Top 15 用户名和密码统计 |
| 命令分析 | Top 20 命令及其分类 |
| 威胁分析 | 攻击者能力评估、组织风险 |
| 安全建议 | 6 条针对性的安全建议 |
| 附录 | 数据字段说明、工具使用说明 |

**独立使用**：
```bash
# 基于分析结果生成报告
./report_generator.py reports/analysis_20261027_143000

# 输出文件
reports/analysis_20261027_143000/report.md
```

**报告特点**：
- ✅ Markdown 格式，支持转换为 HTML/PDF
- ✅ 包含可执行的代码示例
- ✅ 针对性的安全建议（基于实际分析结果）
- ✅ 详细的附录和使用说明
- ✅ 中文支持，符合学术报告规范

---

## 工作流示例

### 场景 1：快速分析（3 分钟）

```bash
# 1. 运行主脚本（自动调用所有工具）
./analyze_logs.sh

# 2. 查看摘要报告
cat reports/analysis_*/summary.txt

# 完成！
```

### 场景 2：深度分析（10 分钟）

```bash
# 1. 运行分析
./analyze_logs.sh /path/to/logs

# 2. 查看报告
cat reports/analysis_*/report.md

# 3. 手动查询特定 IP
./ip_tracker.py --json 192.168.1.100 | jq '.[0].threat_level'

# 4. 转换为 HTML（如果安装了 pandoc）
pandoc reports/analysis_*/report.md -o report.html
```

### 场景 3：持续监控（自动化）

```bash
# 编辑 crontab
crontab -e

# 添加定时任务（每小时运行）
0 * * * * /path/to/defense/analyze_logs.sh >> /var/log/honeypot_analysis.log 2>&1

# 定时检查高风险 IP
0 2 * * * /path/to/defense/ip_tracker.py --file /path/to/ips.txt --json | jq '.[] | select(.threat_level == "high")' > /var/log/high_risk_ips.json
```

---

## 数据流和依赖关系

```
┌─────────────────────────────────────────────────────┐
│           Cowrie JSON Log File                      │
└──────────────────────────┬──────────────────────────┘
                           │ (通过 jq 解析)
        ┌──────────────────┼──────────────────┐
        ↓                  ↓                  ↓
    logins.tsv      commands.tsv         ips.txt
        │                │                   │
        └────────────────┼───────────────────┘
                         ↓
              (按类别统计和排序)
        ┌────────────────────────────────┐
        ├─→ top_usernames.txt ────────┐  │
        ├─→ top_passwords.txt      ┌──┼──┤
        ├─→ top_commands.txt       │  │  │
        └─→ successful_logins.tsv  │  │  │
                                   ↓  ↓  ↓
                          [visualizer.py]
                              ↓  │  │
                         ASCII 图 │  │
                              │  │  │
                              └──┼──┘
                                 ↓
                    successful_logins.tsv
                           + ips.txt
                    ────────→[ip_tracker.py]
                                  ↓
                         ip_enrichment.json
                              + cache
                         ╱─────────────────╲
                        ↓                   ↓
          [report_generator.py]    [visualizer.py]
                        ↓                   ↓
          report.md（Markdown）  HTML 图表（可视化）
          + summary.txt（摘要）  + ASCII 图表
```

---

## 性能指标

| 操作 | 耗时 | 备注 |
|------|------|------|
| 解析 10K 登录记录 | < 1 秒 | 使用 jq 流式处理 |
| IP 溯源（10 个 IP） | ~15 秒 | 包含 API 速率限制延迟 |
| 生成图表 | < 1 秒 | 本地处理，无网络依赖 |
| 生成完整报告 | < 2 秒 | 纯 Python 处理 |
| **完整分析耗时** | **~20 秒** | 包含网络请求 |

---

## 扩展和定制

### 添加新的威胁评估规则

编辑 `ip_tracker.py` 的 `enrich_ip()` 方法：

```python
# 现有规则
if result['country_code'] in high_risk_countries:
    result['threat_level'] = 'medium'

# 添加新规则
if result['isp'] in known_botnet_isps:
    result['threat_level'] = 'high'
    result['tags'].append('botnet')
```

### 添加新的命令分类

编辑 `report_generator.py` 的命令分类字典：

```python
categories = {
    '侦察类': ['whoami', 'uname', 'hostname', ...],
    '文件探测': ['ls', 'cat', 'find', ...],
    '新类别': ['新关键词1', '新关键词2', ...],  # ← 添加
}
```

### 接入外部威胁情报库

扩展 `ip_tracker.py` 的 `query_ip_api()` 方法：

```python
def query_abuseipdb(self, ip):
    """查询 AbuseIPDB 威胁情报"""
    # 需要 API KEY
    # 返回更详细的滥用报告

def enrich_ip(self, ip):
    # 现有 ip-api.com 查询...
    result = self.query_ip_api(ip)
    
    # 新增 AbuseIPDB 查询
    abuse_info = self.query_abuseipdb(ip)
    if abuse_info:
        result['abuse_score'] = abuse_info['abuseConfidenceScore']
        if abuse_info['abuseConfidenceScore'] > 75:
            result['threat_level'] = 'high'
```

---

## 故障排查和调试

### 启用详细日志输出

```bash
# 修改 analyze_logs.sh，添加 set -x
set -x

./analyze_logs.sh /path/to/logs 2>&1 | tee debug.log
```

### 测试 jq 命令

```bash
# 测试 jq 过滤语法
jq 'select(.eventid == "cowrie.login.success")' test_sample.json

# 测试 TSV 转换
jq '[.username, .password] | @tsv' test_sample.json
```

### 测试 IP 查询（离线模式）

```bash
# 仅使用缓存，不发送网络请求
grep '8.8.8.8' defense/lib/ip_cache.json | jq
```

### 检查文件权限

```bash
ls -la defense/
# 应该看到 rwxr-xr-x for .sh 和 .py 文件
```

---

## 许可和归属

本工具集为 ITSD010 CA2 小组作业开发，采用 MIT 许可证。

欢迎提交问题报告和改进建议！

---

**最后更新**: 2026-10-27  
**版本**: 1.0  
**支持**: Python 3.6+, Bash 4.0+
