# CA2 蜜罐项目：Cowrie 部署、识别与加固

> ITSD010 Computing and Cybersecurity Fundamentals — CA2 小组作业
> Singapore Institute of Management · Diploma in Information Technology
> October 2026 Term

---

## 这是什么

本仓库记录了一次完整的蜜罐工程实践：**部署 Cowrie → 识别它的破绽 → 逐步加固 → 量化改进效果**。

与常见的"装个蜜罐然后截图"不同，这个项目的核心是一条闭环：

```
  写检测器  ──→  量出暴露分数
      ↑                │
      │                ↓
  重新测量  ←──  针对性改造
```

每一步改造都有**可复现的分数对照**，数据存在 `reports/`。

---

## 项目结构

```
.
├── docs/                          文档
│   ├── 蜜罐识别器设计与检测报告.md    检测器原理、五层模型、评分机制（2.3 万字）
│   ├── 蜜罐改造记录.md              逐步改造过程与分数对照（1.4 万字）
│   └── 虚拟机环境说明.md            OVA 迁移到 KVM 的全部改动与理由
│
├── attack/                        **攻击方工具**
│   ├── simulate_attack.sh         SSH 暴力破解和侦察命令模拟
│   ├── payloads/                  攻击载荷（凭据字典）
│   └── README.md                  攻击工具使用说明
│
├── defense/                       **防守方工具**
│   ├── analyze_logs.sh            Cowrie 日志分析主脚本
│   ├── ip_tracker.py              IP 地理位置溯源和威胁评估
│   ├── visualizer.py              终端 ASCII 图表
│   ├── report_generator.py        生成详细 Markdown 分析报告
│   └── README.md                  防守工具使用说明
│
├── tools/                         **蜜罐改造工具**
│   ├── honeypot_detect.py         蜜罐识别器（核心）
│   ├── measure.sh                 一键测量并记录分数
│   ├── probe.py                   交互式命令探测（人工检查用）
│   │
│   ├── rebuild_fs.py              Cowrie 假文件系统重建
│   ├── add_fs_paths.py            补全假文件系统路径
│   ├── patch_underline.py         去除终端控制序列
│   ├── patch_headtail.py          head/tail 数字简写支持
│   ├── patch_uptime_nic.py        uptime 与网卡名修正
│   ├── register_cmd.py            注册新的命令模块
│   ├── add_import.py              给文件补 import
│   │
│   ├── cowrie_commands/           新增的 Cowrie 命令实现
│   │   ├── df.py                  df（完整实现）
│   │   ├── sed.py                 sed（常用子集）
│   │   └── systemtools.py         top / ss / ip / systemctl
│   │
│   └── (诊断工具)
│       ├── dump_fs.py             导出 fs.pickle 内容
│       ├── check_bin.py           检查 /bin /sbin 结构
│       ├── check_ciphers.py       列出 Twisted 支持的算法
│       ├── find_esc.py            按字节搜索转义序列
│       ├── trace_modes.py         追踪终端模式调用栈
│       └── trace_write.py         追踪 SSH 写入路径
│
└── reports/                       测量数据与分析报告
    ├── detect_honeypot.json       蜜罐（改造后）
    ├── detect_realsshd.json       对照组：真实 OpenSSH
    ├── step01~06_*.json           六步改造的逐步对照
    └── analysis_*/                日志分析报告（运行时生成）
```

**文档目录** (`docs/`)：

- `蜜罐识别器设计与检测报告.md` - 检测器原理、五层模型、评分机制（2.3 万字）
- `蜜罐改造记录.md` - 逐步改造过程与分数对照（1.4 万字）
- `虚拟机环境说明.md` - OVA 迁移到 KVM 的全部改动与理由
- `攻防演练使用指南.md` - **完整攻防流程**（30 分钟上手）

---

## 两条使用路径

### 路径 A：蜜罐改造与检测（检测器角度）

**目标**：理解蜜罐的暴露特征，学习加固方法。

```bash
# 1. 连接到蜜罐，运行检测器
python3 tools/honeypot_detect.py 192.168.122.123 2222 root admin

# 2. 查看改造文档，理解每一步改动
cat docs/蜜罐改造记录.md

# 3. 对比改造前后的分数
jq .score reports/step01_hostname.json  # 改造前
jq .score reports/detect_honeypot.json  # 改造后
```

**适合人群**：想深入理解蜜罐技术、SSH 协议、终端仿真的同学。

### 路径 B：攻防演练与日志分析（安全分析角度）

**目标**：模拟真实攻击，分析攻击者行为，生成安全报告。

```bash
# 1. 模拟攻击
cd attack/
./simulate_attack.sh 192.168.122.123 2222

# 2. 分析日志
cd ../defense/
./analyze_logs.sh /path/to/cowrie/logs

# 3. 查看报告
cat reports/analysis_*/summary.txt
```

**适合人群**：想快速完成 CA2 Task 3-4（Attack Simulation & Log Analysis）的同学。

**详细流程**：见 [`docs/攻防演练使用指南.md`](docs/攻防演练使用指南.md)

---

## 快速开始

### 路径 A 依赖

```bash
# Python 3.9+ 和 paramiko
pip install paramiko
```

### 路径 B 依赖

```bash
# Arch Linux
sudo pacman -S sshpass openssh jq python curl

# Ubuntu/Debian
sudo apt install sshpass openssh-client jq python3 curl
```

### 运行检测器（路径 A）

```bash
# 完整检测
python3 tools/honeypot_detect.py --host 192.168.122.252 --port 2222 --verbose

# 输出 JSON（便于自动化对比）
python3 tools/honeypot_detect.py --host 192.168.122.252 --port 2222 --json

# 只做协议层和认证层，不登录（最隐蔽）
python3 tools/honeypot_detect.py --host 192.168.122.252 --port 2222 --passive
```

退出码：`0` = 识别为蜜罐，`1` = 未识别，`2` = 连接失败。

---

## 核心结果

### 检测器效果

| 目标 | 暴露指数 | 命中情况 |
|---|---|---|
| Cowrie（改造前） | **100** / 原始分 313 | 4 决定性 / 12 强 / 6 弱 |
| Cowrie（改造后） | **100** / 原始分 **118** | 1 决定性 / 5 强 / 2 弱 |
| 真实 OpenSSH（对照） | **10** | 0 决定性 / 0 强 / 1 弱 |

**对照组用的是同一台机器上的真实 sshd**（同 IP、同网段、同时刻）。唯一变量是服务端实现，所以这组数据能证明检测器分析的是**系统行为**，不是"端口非标准"这类外部特征。

### 改造曲线

| 步骤 | 改造内容 | 原始分 | 文件系统 | 命令行为 | 终端 |
|---|---|---|---|---|---|
| 基线 | — | 313 | 62 | 118 | 21 |
| 1 | 统一主机名 | 313 | 62 | 118 | 21 |
| 2 | 重建假文件系统 | 243 | **0** | 110 | 21 |
| 3 | 去终端控制序列 | 228 | 0 | 110 | **6** |
| 4 | 实现 df | 178 | 0 | **60** | 6 |
| 5 | uptime + 网卡名 | 160 | 0 | **42** | 6 |
| 6 | 补 sed/top/ss/ip/systemctl | **118** | 0 | **0** | 6 |

**原始分下降 62%，文件系统层和命令行为层完全清零。**

> **为什么"指数"一直显示 100？**
> 评分模型有"决定性项命中则最低 70"的兜底规则，而认证层那条（接受任意随机密码）是蜜罐的定义性特征，不可能消除。所以指数永远撞在 100 的天花板上。
> 为此脚本额外输出**原始分**（未封顶的权重总和），才是衡量改造进展的正确指标。

---

## 五层检测模型

| 层 | 检测内容 | 可修复性 |
|---|---|---|
| **协议层** | SSH 算法集（AEAD / CBC / ETM / md5）、exec 通道 | 极难（需换 SSH 栈） |
| **认证层** | 是否接受任意随机密码 | 不可修复（蜜罐定义） |
| **文件系统层** | 主机名一致性、容器标记、时间戳、配置文件内容 | 容易 |
| **命令行为层** | head/tail 语法、df/sed 可执行性、现代工具是否存在 | 中等 |
| **终端行为层** | 控制序列、bracketed paste | 中等 |

每层内部，证据按强度分级：

- **决定性**：真实系统上不可能出现 → 单条命中即定案
- **强信号**：真实系统出现概率极低 → 2 条以上命中即判定
- **弱信号**：可能是配置差异 → 需多条同时命中

---

## 核心结论

### 1. 中等交互蜜罐有明确的伪装天花板

低成本改造能消除 180 分，但再往下就是架构问题。协议层（82 分）和认证层（30 分）都不是配置能解决的。

**结论：中等交互蜜罐可以被做得更难识别，但无法完全隐形。**

### 2. 检测分数 ≠ 真实度

协议层有约 34 分理论上可以通过"裁剪算法集"消掉（去掉 CBC、md5）。但裁剪后的结果是一个没有 AEAD、没有 ETM、也没有 CBC 的 SSH 服务端 —— 检测器给分更低，稍有经验的攻击者反而更怀疑。

**针对检测器优化不等于提高真实度。** 这是把指标当成目标的典型陷阱。

### 3. 认证层的暴露应该被接受

蜜罐的存在意义是"被攻破"。要求它不暴露"接受任意密码"，等于要求它不要工作。正确做法是承认这一层，用网络隔离和日志外送来承担"被识破之后"的风险。

---

## 威胁分析摘要

项目过程中系统排查了六类威胁，均有实测验证：

| 威胁 | 结论 | 原因 |
|---|---|---|
| 从蜜罐逃逸到主机 | 不成立 | 57 个命令模块无 `eval`/`exec`/`subprocess` |
| 横向移动至内网 | 不成立 | 网络隔离（但依赖宿主防火墙，属隐式防护） |
| 利用已知 CVE | 不成立 | 唯一 CVE（CVE-2025-34469，DoS）本版本已修补 |
| 作为 Botnet 节点 | 不成立 | 无代码执行 + 无持久化 |
| 作为 DDoS 放大器 | 不成立 | 出站限速 5 次/60 秒/主机，峰值约 8 RPS |
| Output 插件出站 | 部分成立 | 配置驱动，攻击者不可控 |

**真正的风险面在部署配置**：蜜罐主机的独立 SSH 服务与账号复用、代码/配置/日志同权（都是 `cowrie` 用户且 group-writable）、进程未启用 `NoNewPrivs`/seccomp。

详见 `docs/蜜罐识别器设计与检测报告.md` 第九章。

---

## 实验环境

| 组件 | 配置 |
|---|---|
| 宿主机 | Arch Linux，KVM/QEMU（libvirt） |
| 蜜罐 VM | Ubuntu 26.04 Server，2 vCPU / 2G，NAT 网络 `192.168.122.252` |
| 蜜罐软件 | Cowrie 3.0.13（pip 安装） |
| 蜜罐端口 | 2222（Cowrie）/ 22（真实 sshd，对照组） |

**改造前的干净状态有快照**：`baseline-2026-10-26`，可一键回滚。

---

## 声明

本项目所有测试均在**本组自建的隔离虚拟环境**中进行，未对任何外部系统发起扫描或攻击。蜜罐未暴露至公网。

代码与文档由本组成员编写，用于 ITSD010 CA2 小组作业。

---

## 参考

- Nawrocki, Wählisch, Schmidt, Keil & Schönfelder (2016). *A survey on honeypot software and data analysis*. arXiv:1608.06249
- Ylonen & Lonvick (2006). *The Secure Shell (SSH) protocol architecture*. RFC 4251
- Cowrie 官方文档：https://docs.cowrie.org/
