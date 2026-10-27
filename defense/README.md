# 防守方：Cowrie 日志分析工具

运行在**蜜罐机（VM A）**上，用于分析 Cowrie 捕获的攻击日志：统计登录尝试与命令、
追踪攻击源 IP、生成中文分析报告。对应 CA2 的任务 4（日志分析）与任务 5（安全建议）。

> 攻击机（VM B）上的模拟脚本在 `../attack/`，两边的脚本不要混用。

## 工具清单

| 文件 | 作用 |
|------|------|
| `analyze_logs.sh` | 主脚本，解析日志并依次调用下面三个工具 |
| `ip_tracker.py` | 查询攻击源 IP 的地理位置、ISP，并做威胁等级评估 |
| `visualizer.py` | 在终端输出 ASCII 柱状图 / 占比图 |
| `report_generator.py` | 生成 Markdown 格式的详细分析报告 |

## 依赖

```bash
# Arch Linux
sudo pacman -S jq python curl
# Ubuntu / Debian
sudo apt install jq python3 curl
```

Python 用标准库即可，无需 pip 安装额外包。

## 使用

```bash
cd defense/

# 1. 分析日志（传入 Cowrie 日志目录，不传则用默认路径）
./analyze_logs.sh /home/cowrie/cowrie/var/log/cowrie

# 2. 查看终端摘要与图表，报告写在 reports/ 下
cat reports/analysis_*.summary.txt
cat reports/analysis_*.report.md
```

没有真实日志时，可用仓库里的样例日志先跑通流程（第一个参数可直接是文件）：

```bash
./analyze_logs.sh test_sample.json
```

## 输出文件

每次运行生成一组带时间戳的文件（前缀 `reports/analysis_YYYYMMDD_HHMMSS`）：

| 文件 | 内容 |
|------|------|
| `.summary.txt` | 纯文本摘要（登录/命令/IP 概览 + 图表） |
| `.report.md` | 完整 Markdown 报告（摘要、时间线、凭据、命令、威胁、建议） |
| `.logins.tsv` | 全部登录尝试 |
| `.successful_logins.tsv` | 成功登录记录 |
| `.commands.tsv` | 命令执行记录 |
| `.ips.txt` | 去重后的攻击源 IP |
| `.ip_enrichment.json` | IP 溯源结果（JSON） |
| `.top_usernames.txt` / `.top_passwords.txt` / `.top_commands.txt` | 频次统计 |

## IP 溯源说明

- 数据来自 [ip-api.com](https://ip-api.com/) 免费接口，无需注册，限 45 次/分钟，脚本已自动限速。
- 结果缓存在 `lib/ip_cache.json`，相同 IP 不重复查询（`--no-cache` 可跳过缓存）。
- 威胁等级为规则判断：内网→low；高风险国家或主机名含 scanner/bot→medium。仅供参考，不是权威情报。
- 可单独使用：`./ip_tracker.py --json 8.8.8.8 1.1.1.1`

## 注意事项

- 实验在内网隔离环境进行，“公网 IP 溯源”是对真实场景的模拟演示。
- 日志与报告含攻击者凭据、命令等信息，请妥善保管，勿随日志外发。
- IP 查询会把 IP 发送给第三方接口；离线或敏感环境建议改用本地 GeoIP 库。
