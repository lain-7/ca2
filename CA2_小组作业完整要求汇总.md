# ITSD010 Computing and Cybersecurity Fundamentals（计算与网络安全基础）
## CA2 小组作业（Group Assignment）完整要求汇总 —— 2026 年 10 月学期（Oct 2026 Term）

> 信息整合自以下四份文件：
> 1. 《CA2 Oct 2026.pdf》—— 作业任务书（Instruction for CA2 Group Assignment）
> 2. 《Cowrie Setup Guide.pdf》—— 虚拟机与蜜罐搭建指南
> 3. Canvas 页面《CA002 Group Assignment Submission & Feedback》—— 小组作业提交要求
> 4. Canvas 页面《CA002 Presentation Submission & Feedback》—— 汇报提交要求

---

## 第一部分：作业总览（Assessment Overview）

- **总分**：100 分，占课程总评成绩的 **40%**（constitutes 40% of the overall assessment）。
- **小组规模**：每组 **3 至 5 名成员**（groups of 3 to 5 members）。
- **核心任务**：在受控虚拟环境中部署 **Cowrie SSH 蜜罐（Cowrie SSH Honeypot）**，模拟攻击活动，收集安全日志（security logs），并分析攻击者行为（attacker behaviour）。
- **无需编程**（No programming is required）。

### 四大交付物（FOUR Deliverables，必须全部完成）

| # | 交付物（Deliverable） | 分值 | 占总评 |
|---|---|---|---|
| 1 | 书面项目报告（Written Project Report） | 25 分 | 10% |
| 2 | 蜜罐部署与证据（Honeypot Deployment and Evidence） | 40 分（35 + 5 附加分） | 16% |
| 3 | 带截图的用户指南（User Guide with Screenshots） | 10 分 | 4% |
| 4 | 口头汇报（Oral Presentation） | 25 分 | 10% |
| | **合计** | **100** | |

### 学生需要完成的六件事
1. 搭建两台 Ubuntu 虚拟机（Virtual Machines）。
2. 在 VM A 上配置 Cowrie 蜜罐。
3. 从 VM B 发起 SSH 登录尝试（SSH login attempts）。
4. 收集并分析安全日志。
5. 撰写网络安全报告（cybersecurity report）。
6. 展示（汇报）小组的发现（present their findings）。

### 作业重点（The assignment focuses on）
- 网络安全意识（Cybersecurity awareness）
- 安全监控（Security monitoring）
- 基础 Linux 管理（Basic Linux administration）
- 日志分析（Log analysis）
- 安全建议（Security recommendations）

---

## 第二部分：案例背景（The Case）

一家小公司最近遭遇了多次针对其服务器的可疑登录尝试（suspicious login attempts）。公司管理层希望了解：
- 攻击者如何尝试获取未授权访问（unauthorised access）；
- 哪些用户名（usernames）和密码（passwords）最常被针对；
- 攻击者在成功进入系统后会进行哪些活动。

作为初级网络安全分析师团队（junior cybersecurity analysts），你们小组的任务是部署一套蜜罐系统并调查攻击者行为。公司需要一个简单的监控方案，能够：
- 记录登录尝试（Record login attempts）；
- 捕获使用的用户名和密码（Capture usernames and passwords used）；
- 记录攻击者执行的命令（Log commands executed by attackers）；
- 生成网络安全分析结论（Generate cybersecurity findings）；
- 提出安全改进建议（Recommend security improvements）。

---

## 第三部分：项目要求（Project Requirement）

### 网络环境（Network Environment）
- **VM A（服务器 / Server）**：Ubuntu Server，安装 Cowrie Honeypot 和 SSH 服务（SSH Service）。
- **VM B（客户端 / Client）**：Ubuntu Desktop/Server，用于连接蜜罐、模拟登录尝试、执行命令。

### 任务 1：网络安全调研（Task 1: Cybersecurity Research）
调研以下概念：
- **蜜罐（Honeypots）**：定义（Definition）、用途（Purpose）、优点（Benefits）、局限性（Limitations）。
- **SSH**：什么是 SSH？常见用途（Common uses）、安全风险（Security risks）。

**交付物**：一段简短论述，约 **500 字**（approximately 500 words）。

### 任务 2：部署蜜罐（Task 2: Deploy the Honeypot）
- 配置 VM A，安装 Ubuntu。
- 提供截图（screenshots）展示：VM 配置（VM configuration）、Cowrie 安装（Cowrie installation）、Cowrie 成功运行（Cowrie running successfully）。
- **必需证据（Required evidence）**：`cowrie start`、`cowrie status`。
- **⚠️ 严禁使用云服务部署虚拟机，也不得将蜜罐公开暴露到互联网**（Do not deploy the VM using cloud services or make it publicly accessible）。

### 任务 3：模拟 SSH 登录尝试（Task 3: Simulate SSH Login Attempts）
使用 VM B 完成至少 **20 次登录尝试（20 Login Attempts）**：
- 示例用户名：`admin`、`root`、`administrator`、`student`、`guest`
- 示例密码：`password`、`123456`、`admin123`、`student123`、`welcome`
- 示例命令：`ssh admin@<ip-address> -p 2222`
- 登录后执行简单命令：`ls`、`pwd`、`whoami`、`uname -a`
- 目的是生成用于分析的日志数据。
- **只允许对本组自己的蜜罐进行测试**（must only perform testing against their own group's honeypot）。

### 任务 4：日志分析（Task 4: Log Analysis）
分析 Cowrie 捕获的信息，回答：
- **登录分析（Login Analysis）**：登录尝试总数；最常被使用的用户名；最常被使用的密码；成功登录次数（successful logins）。
- **命令分析（Command Analysis）**：最常被执行的命令（Most common commands）；这些命令的目的。
- **威胁结论（Threat Findings）**：攻击者能从被攻陷的系统中学到什么？对组织（organisation）有哪些风险？

**呈现要求**：至少 **一个表格（table）**、**一个柱状图（bar chart）**、**一个饼图（pie chart）**。

### 任务 5：安全建议（Task 5: Security Recommendations）
提供至少 **5 条安全建议（Security Recommendations）**，每条必须附简短解释（brief explanation）。示例：
- 强密码策略（Strong password policies）
- 多因素认证（Multi-factor authentication, MFA）
- 禁止 root 直接登录（Disable direct root login）
- 定期打补丁（Regular patching）

### 附加功能（Additional Feature，最多 5 分加分 / bonus marks）
可任选一项实现：
- 攻击者 IP 地址的地理位置分析（Geo-location analysis of attacker IP addresses）
- 可视化仪表盘（Visualization dashboard）
- 每日攻击摘要报告（Daily attack summary report）
- 与真实世界网络攻击统计数据对比（Comparison with real-world cyberattack statistics）

### 建议的小组角色分工（Suggested Group Roles）

| 角色（Role） | 职责（Responsibility） |
|---|---|
| 成员 1 | 项目组长与文档（Project Leader & Documentation） |
| 成员 2 | 虚拟机安装与网络配置（VM Installation & Network Setup） |
| 成员 3 | Cowrie 安装（Cowrie Installation） |
| 成员 4 | 攻击模拟（Attack Simulation） |
| 成员 5 | 日志分析与汇报（Log Analysis & Presentation） |

---

## 第四部分：报告与用户指南要求（Report & User Guide Requirements）

### 项目报告（Project Report）须包含
1. 封面（Cover Page）
2. 引言（Introduction）
3. 蜜罐调研（Honeypot Research）
4. 系统搭建（System Setup）
5. 日志分析（Log Analysis）
6. 结论与讨论（Findings and Discussion）
7. 安全建议（Security Recommendations）
8. 总结（Conclusion）

需包含截图和解释（Include screenshots and explanations）。

### 用户指南（User Guide）须逐步展示
1. 启动 Cowrie（Starting Cowrie）
2. 连接到蜜罐（Connecting to the Honeypot）
3. 生成登录尝试（Generating Login Attempts）
4. 查看日志（Viewing Logs）
5. 停止 Cowrie（Stopping Cowrie）

### 蜜罐部署证据（Honeypot Deployment Evidence，报告与用户指南中均需要）
- VM 搭建截图（Screenshots of VM setup）
- Cowrie 安装截图（Screenshots of Cowrie installation）
- 成功登录尝试的截图（Screenshots showing successful login attempts）
- 日志文件截图（Screenshots of log files）

### 口头汇报（Presentation）
- **所有成员必须出席**（All members must be present）。
- 汇报应包括：项目概述（Project overview）、演示（Demonstration）、发现（Findings）、建议（Recommendations）。

### 报告与指南的格式要求（Instructions for CA2 Report and User Guides）
- **封面**：须包含学校名称（及校徽 logo）、专业（programme）和模块名称（module name）、学期与年份、提交日期，全部**居中**（centralised）。
- 封面上按注册名单写**完整姓名（FULL Name）和学号（Student number）**。学生应自行保留一份提交作业的副本。
- **报告长度**：最少 **1,500 字**（Minimum 1,500 words）。
- **引用（Referencing）**：须为调研材料、网络安全资源、查阅的网站提供引用，推荐 **APA 引用格式（APA referencing format）**。
- **字体与行距（Font and Spacing）**：Times New Roman，字号 12，1.5 倍行距。

### 迟交扣分（Penalty Marks for Late Submission）
- 迟交一天（by one day / within 24 hours）：从总分中扣除 **20%**。
- 迟交超过一天（more than one day / 24 hours）：**不予评分（NOT be graded / graded zero）**。

### 抄袭与串通（Plagiarism and Collusion）
- 不允许重复使用旧作业、提交以前学期的项目，或大量抄袭来源（尤其是互联网）。
- 提交的报告必须体现是学生本人的成果；没有演算过程或合理解释不予给分。
- 抄袭与串通属严重违纪（serious offences），所有案例将移交管理部门（administration）处理；如涉嫌抄袭或串通，成绩将被暂扣（withheld），直至调查完成。

### 重要日期（Important Dates）
- **CA2 小组作业截止（Group Assignment Deadline）：2026 年 11 月 10 日上午 11:59**（10th November 2026 11.59 a.m.）。
- 通过 **Canvas** 提交项目；必须完成提交，报告才会被评分。
- **讲师联系方式（Lecturer Contact）**：如有任何问题，请通过你的 SIM 邮箱（SIM email）联系讲师。

---

## 第五部分：评分细则（Marking Rubric）

> 注：原 PDF 中评分表的部分描述文字在提取时缺失/不完整，以下按可读内容整理；各档从高到低为 Excellent（优秀）→ Very Good（良好）→ Good（中等）→ Acceptable（可接受）→ Weak（薄弱）。

### 1. 项目报告（Project Report，25 分）

| 评分项（Criteria） | 优秀档要点 | 薄弱档表现 |
|---|---|---|
| 引言与对蜜罐的理解（Introduction & Understanding of Honeypots） | 对蜜罐、SSH、网络安全风险和目标有详细且准确的解释 | 解释极少或不准确（minimal or inaccurate） |
| 文档记录（Documentation） | 清晰记录所有搭建步骤，描述全面并附截图 | 几乎没有搭建文档（very little setup documentation） |
| 日志分析与解读（Log Analysis & Interpretation） | 对登录尝试、密码、命令和攻击模式（attack patterns）进行详细分析与解读 | 几乎没有有意义的分析（little or no meaningful analysis） |
| 安全建议（Security Recommendations） | 建议实用、论证充分，且有分析发现支撑 | 建议很少或不相关（few or irrelevant） |
| 报告的清晰度与呈现（Clarity & Presentation of Report） | 组织极佳、专业、清晰易懂 | 组织混乱、难以阅读（poorly organised, difficult to follow） |

### 2. 蜜罐部署与证据（Honeypot Deployment & Evidence，40 分）

| 评分项 | 优秀档要点 | 薄弱档表现 |
|---|---|---|
| 虚拟机搭建（Virtual Machine Setup） | 两台 VM 均正确配置、网络连通（network connectivity established）、搭建过程完整记录 | 搭建不完整或无法运行（incomplete or non-functional） |
| Cowrie 安装（Cowrie Installation） | 安装成功并提供了所有必需证据 | Cowrie 无法运行或证据不足（not functioning or insufficient evidence） |
| 攻击模拟（Attack Simulation） | 完成所有必需的登录尝试并生成有意义的活动日志 | 攻击模拟活动不足（Insufficient attack simulation activities） |
| 证据收集（Evidence Collection） | 截图全面，覆盖所有主要活动和系统状态 | 证据很少或没有（Little or no evidence） |
| 技术准确性（Technical Accuracy） | 对蜜罐的部署与运行展现出优秀的理解 | 技术理解差（poor technical understanding） |

### 3. 用户指南（User Guides，10 分）

| 评分项 | 优秀档要点 | 薄弱档表现 |
|---|---|---|
| 分步说明（Step-by-Step Instructions） | 全程说明清晰、有逻辑 | 说明不清楚（Instructions are unclear） |
| 截图示例（Screenshot Samples） | 截图覆盖所有主要步骤 | 截图很少或没有 |
| 操作步骤的准确性（Accuracy of Procedures） | 所有步骤准确且易于跟随 | 存在许多错误（Many inaccuracies） |
| 示例输入与输出（Sample Inputs and Outputs） | 提供并解释了详细的命令和日志示例 | 示例很少或没有（Few or no examples） |
| 专业呈现（Professional Presentation） | 格式良好，适合非技术用户使用 | 格式糟糕（poorly formatted） |

### 4. 口头汇报（Oral Presentation，25 分）

| 评分项 | 优秀档要点 | 薄弱档表现 |
|---|---|---|
| 表达清晰度（Clarity of Presentation） | 清晰、自信、结构分明 | 部分方面缺乏清晰度（lacks clarity in some areas） |
| 系统演示（Demonstration of System） | 小组自信且准确地演示完整的蜜罐系统 | 没有有意义的演示（No meaningful demonstration） |
| 内容与发现（Content & Findings） | 发现有洞察力、解释充分且有依据 | 发现不清楚或缺乏支撑（unclear or unsupported） |
| 问答环节（Questions & Answers） | 准确且自信地回答所有问题 | 无法回答问题（Unable to answer questions） |
| 团队参与（Team Participation） | 所有成员平等且有效地参与 | 小组参与度极低（Minimal group participation） |

---

## 第六部分：Cowrie 搭建指南（Cowrie Setup Guide 全文）

### A. 虚拟机搭建（VM Setup Guide）
1. 从以下地址下载并安装 **Oracle VirtualBox**：
   - https://www.virtualbox.org/wiki/Downloads
   - https://mega.nz/file/sNsGiBJC#6PHAChdguWYNgtfGzYz3WAdfGAerg8yJc-DYKua6jio
2. 从云存储下载 ZIP 文件并解压，应得到 **两个 .ova 文件**（解压密码：**ditccf**）。
3. 在 VirtualBox 中，进入 **File → Import Appliance（文件 → 导入虚拟电脑）**。
4. 点击“**Choose a virtual appliance file to import**（选择要导入的虚拟电脑文件）”，选择 .ova 文件并开始导入。
5. 两台 VM 都导入后，右键每台 VM 选择 **Settings（设置）**，切换到 **Expert Mode（专家模式）** 并选择 **Network（网络）**，确认以下设置：
   - **Attached to（连接方式）**：Bridged Adapter（桥接网卡）
   - **Name（名称）**：你电脑的 Wi-Fi 适配器（Your computer's Wi-Fi adapter）
   - **Promiscuous Mode（混杂模式）**：Allow VMs（允许虚拟机）

### B. Cowrie 服务器使用指南（Cowrie User Guide）
1. 启动 VM 前，确保你连接的是**家庭或私有网络**（home or private network），且该网络**不需要域认证**（does not require domain authentication）。
2. 启动 Cowrie VM。
3. 使用用户名 **ubuntucowrie**、密码 **123456** 登录。
4. 运行 `ip addr` 获取 Cowrie VM 的 IP 地址；记录分配给 **enp0s3** 网卡的 IP（后面要用）。
5. 从 root 用户切换到 cowrie 用户：`sudo su - cowrie`
6. 进入 Cowrie 目录：`cd ~/cowrie-honeypot`
7. 激活 Cowrie 虚拟环境（virtual environment）：`source cowrie-env/bin/activate`
8. 管理 Cowrie 蜜罐服务的命令：
   - `cowrie start` —— 启动蜜罐
   - `cowrie status` —— 查看蜜罐状态
   - `cowrie stop` —— 停止蜜罐
9. 实时监控 Cowrie 日志：
   - `tail -f var/log/cowrie/cowrie.log`
   - `tail -f var/log/cowrie/cowrie.json`
10. 保持 Cowrie 服务器运行，然后转到客户端 VM。

### C. 客户端 VM 使用指南（Client VM User Guide）
1. 确认 Cowrie 蜜罐服务已在服务器上运行。
2. 启动 Client VM（登录用户：**ubuntuclient**）。
3. 验证与 Cowrie 服务器的网络连通性：`ping -c 4 x.x.x.x`
   （⚠️ 将 x.x.x.x 替换为 Cowrie 服务器的 IP 地址，确保连接已建立。）
4. 从 Client VM 手动发起 SSH 登录尝试。

**示例 SSH 登录命令（Example SSH Login Commands）：**
```
ssh root@x.x.x.x -p 2222
ssh admin@x.x.x.x -p 2222
ssh ubuntu@x.x.x.x -p 2222
ssh test@x.x.x.x -p 2222
```
（将 x.x.x.x 替换为 Cowrie 服务器的 IP。密码可随意输入——蜜罐会捕获凭据（credentials）并允许登录尝试。）

**登录后的示例命令（Example Commands After Login）：**
```
whoami
pwd
uname -a
id
ls -la
cat /etc/passwd
ps aux
netstat -tulnp
```

**测试文件下载监控（Testing File Download Monitoring）：**
```
wget http://example.com/test.sh
curl http://example.com/file.txt
```

5. 完成登录尝试并执行命令后，回到 Cowrie 服务器查看日志记录。
6. 若要将日志文件从 VM 传输到本地电脑，使用 **SCP 连接（SCP connection）**。

---

## 第七部分：Canvas 提交要求

### 7.1 小组作业提交（CA002 Group Assignment Submission & Feedback）
- **截止时间（Due）**：**11 月 10 日（Nov 10）上午 11:59**
- **提交方式**：文件上传（file upload）
- **接受的文件类型**：doc、docx、java、pdf、zip、png、jpg、jpeg
- **开放提交时间**：10 月 1 日 0:00 — 11 月 11 日上午 11:59

#### 提交规范
- 请使用提供的模板指导报告写作：**Guide Template for Assignment（作业指南模板）**（Canvas 页面可下载）。
- 请仔细遵循指引，**不遵循指引将被扣分（penalty marks deduction）**。
- CA 必须用 **MS Word** 撰写，并保存为 **FamilynameFirstname.docx** 格式（姓+名），示例：`TanMeiMeiSally.docx`、`PremaSubroyan.docx`（省略 D/O、S/O）。
- 文档扩展名可以是 ".doc"（97-2003 格式）或 ".docx"。
- 文件必须兼容**抄袭检测（Plagiarism Detection）**：上传的文件**不能**设有密码保护（password protected）、加密（encrypted）、隐藏（hidden）、系统文件（system files）或只读（read only）。可接受的文件类型：
  - Microsoft Word（DOC 和 DOCX）
  - Microsoft Excel（XLS 和 XLSX）
  - Microsoft PowerPoint（PPT 和 PPTS）
  - 纯文本（TXT）
  - 富文本格式（RTF）
  - 便携文档格式（PDF）
- 提交的文档必须**超过 20 个单词**、**小于 40MB**（约两百万字符）、**不超过 400 页**，且不能每个字母之间都有空格（如：l i k e t h i s）。
- Canvas 提交系统允许在截止日期前**多次提交**；**每次新的提交会覆盖（overwrite）之前提交的文件**，因此每次提交都必须包含全部文件以保证完整性（completeness）。

#### 声明（DECLARATION）
在线提交本作业即表示我们/我声明已阅读并理解以下陈述：
- (a) 本项目作业是我们/我的原创作品（original work），除已注明出处（due acknowledgment）的部分外，没有任何部分抄袭自其他来源或由他人代写。
- (b) 我们/我理解以下概念的含义：
  - **什么是抄袭（Plagiarism）**：将他人作品的全部或部分以原样或高度近似的形式当作自己的成果使用，且未注明原作者。作业中抄袭的例子包括：未注明出处地使用其他作者的措辞（phrases）、事实和插图（facts and illustrations）、统计数据（statistics）和汇编材料（assembled materials）。
  - **什么是串通（Collusion）**：经他人同意使用其作品或想法，却未在自己的作品中正式注明。虽然学生可以自由地与任何人讨论想法和小组项目，但在撰写报告时，每个学生/每个小组都必须用自己的语言完成各自的报告。不同小组的报告中出现相同的短语、段落、文本章节或插图（且未注明出处）即构成串通。
- (c) 我们/我理解抄袭和/或串通是严重违纪行为（serious offence）。被发现抄袭、串通或允许自己作品被抄袭的学生，将受到 SIM 大学纪律程序（disciplinary procedures）的处理。

#### 确保提交成功
- 页面标注「**IMPORTANT: Click Here**」链接（关于确认提交成功的指引）。

#### 获取帮助（Getting Help）
- 提交前，请仔细阅读学生门户（Student Portal）、课程概览（Course Overview）、考核概览（Assessment Overview）、CA 时间表（CA Schedule）、考试时间表（Examination Schedule）以及 Canvas 中的信息。
- 如有问题：先查看 Canvas Help 板块；如仍需 Canvas 提交方面的帮助，点击页面中的链接按步骤联系服务台（Service Desk）；非 Canvas 问题，请使用你的学生 mymail 账户发送邮件至 **students@sim.edu.sg**（不接受其他邮箱账户发来的邮件）。
- 请在进一步提问前确保已通读所有说明。

#### 迟交扣分（Penalty Marks for Late Submission）
- 24 小时内：从总分中扣除 **20%**。
- 超过 24 小时：提交记 **零分（graded zero）**。

#### 同伴互评（Peer Evaluation，仅适用于小组作业）
- 为促进团队合作（team spirit），**仅当你有证据证明某位组员未为作业做出贡献时**（ONLY IF YOU HAVE EVIDENCE THAT ANY OF THE GROUP MEMBERS HAVE NOT CONTRIBUTED HIS/HER PART），才使用同伴互评表（Peer Evaluation Form，Canvas 页面可下载）。
- 将该表于 **2026 年 11 月 12 日下午 2 点前**发送至 **he10@sim.edu.sg**。

#### 学术诚信（Academic Integrity）
- 学生须遵守所有学术诚信准则（academic integrity guidelines）及作业任务书的具体要求；页面附有《Academic Integrity Guide》信息图（infographic），总结了须避免的主要学术不端行为（academic misconduct）。

#### 学术诚信与 AI 工具使用声明（Declaration of Academic Integrity and Use of AI Tools）
提交本作业即确认：
- 我已遵守所有学术诚信准则和作业要求；
- 本作品为原创，符合所有学术诚信与 AI 使用规则（AI use rules）；
- 我对本次提交负全部责任，并已在需要时提供 AI 提示词记录（AI prompt records）。

**确认（Acknowledgement）：**
- 我理解虚假、不完整或误导性的声明（false, incomplete, or misleading declaration）可能导致 SIM 学术不端程序（academic misconduct procedures）下的纪律处分；
- 我理解未能提供所需声明和 AI 提示词记录可能导致本作业**不予评分（not being marked）**。

### 7.2 汇报提交（CA002 Presentation Submission & Feedback）
- **截止时间（Due）**：**11 月 21 日（Nov 21）上午 11:59**
- **提交方式**：文件上传（file upload）
- **接受的文件类型**：pdf、doc、docx、ppt、pptx、xls、xlsx、txt、rtf、mp4
- **开放提交时间**：10 月 1 日 0:00 — 11 月 22 日上午 11:59
- **Canvas 提交窗口会在截止日期前一周开放**（Canvas submission will be open one week before the deadline）；截止前允许多次提交。

其余要求与小组作业提交页一致，包括：
- 使用 **Guide Template for Assignment** 模板，仔细遵循指引否则扣分；
- 文件命名 **FamilynameFirstname.docx**（姓+名，省略 D/O、S/O），扩展名 .doc 或 .docx；
- 抄袭检测兼容性要求（可接受类型为 DOC/DOCX、XLS/XLSX、PPT/PPTX、TXT、RTF、PDF、**视频 MP4**）；
- 文档须超过 20 词、小于 40MB、不超过 400 页、字母间不能有空格；
- 相同的**原创性声明（DECLARATION）**：原创声明、抄袭（Plagiarism）与串通（Collusion）定义、违纪后果；
- 「IMPORTANT: Click Here」确认提交成功指引；
- 获取帮助途径（Canvas Help、Service Desk、students@sim.edu.sg，须用学生 mymail 账户）；
- 迟交扣分：24 小时内扣 **20%**，超过 24 小时记**零分**；
- 《Academic Integrity Guide》信息图要求；
- **学术诚信与 AI 工具使用声明**及确认条款（未提供声明和 AI 提示词记录可能导致不予评分）。

---

## 附：关键时间节点一览

| 事项 | 时间 |
|---|---|
| 提交开放 | 2026 年 10 月 1 日 0:00 |
| **小组作业（报告等）截止** | **2026 年 11 月 10 日 上午 11:59** |
| 小组作业提交通道关闭 | 2026 年 11 月 11 日 上午 11:59 |
| 同伴互评表提交截止（发送至 he10@sim.edu.sg） | 2026 年 11 月 12 日 下午 2:00 |
| **汇报（Presentation）截止** | **2026 年 11 月 21 日 上午 11:59** |
| 汇报提交通道关闭 | 2026 年 11 月 22 日 上午 11:59 |
