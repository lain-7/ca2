# 攻击模拟工具 (Attack Simulation)

本目录包含用于模拟黑客对 SSH 蜜罐攻击的工具。

## 目录结构

```
attack/
├── simulate_attack.sh      # 主攻击模拟脚本
├── payloads/               # 攻击载荷
│   └── common_creds.txt    # 常见用户名密码字典
└── logs/                   # 攻击日志（运行时生成）
```

## 功能特性

- ✅ SSH 暴力破解模拟
- ✅ 成功登录后的侦察命令执行
- ✅ 详细的攻击日志记录
- ✅ 彩色终端输出
- ✅ 可配置的延迟和目标

## 依赖项

```bash
# Arch Linux
sudo pacman -S sshpass openssh coreutils

# Ubuntu/Debian
sudo apt install sshpass openssh-client coreutils
```

## 使用方法

### 基本用法

```bash
# 使用默认配置（目标：192.168.122.123:2222）
./simulate_attack.sh

# 指定目标 IP 和端口
./simulate_attack.sh 192.168.122.123 2222
```

### 修改攻击字典

编辑 `payloads/common_creds.txt`，格式为 `username:password`：

```
root:123456
admin:admin
user:password
```

### 调整攻击参数

编辑 `simulate_attack.sh` 的配置区：

```bash
DELAY_BETWEEN_ATTEMPTS=2     # 每次登录尝试间隔（秒）
DELAY_BETWEEN_COMMANDS=1     # 命令执行间隔（秒）
```

## 输出文件

- `logs/attack_YYYYMMDD_HHMMSS.log` - 完整攻击日志
- `logs/successful_logins.log` - 成功登录的凭据

## 模拟的攻击行为

1. **连通性测试** - 检查目标端口是否开放
2. **暴力破解** - 使用字典尝试登录
3. **侦察命令** - 成功登录后执行以下命令：
   - 身份确认：`whoami`, `id`
   - 系统信息：`uname -a`, `cat /etc/os-release`
   - 网络配置：`ifconfig`, `ip addr`, `netstat`
   - 进程信息：`ps aux`, `w`, `last`
   - 文件探测：`ls -la /home`, `ls -la /root`
   - 系统资源：`df -h`, `free -m`
   - 历史记录：`cat /root/.bash_history`
   - 配置文件：`find / -name '*.conf'`

## 安全说明

⚠️ **仅用于授权测试**

- 此工具仅用于在授权环境下测试自己的蜜罐
- 未经授权对他人系统进行攻击是违法行为
- 请遵守当地法律法规和学术诚信规范

## 示例输出

```
╔════════════════════════════════════════════════════════════╗
║          SSH 蜜罐攻击模拟工具 v1.0                        ║
║          Attack Simulation Script                          ║
╚════════════════════════════════════════════════════════════╝

[2026-10-26 12:00:00] [INFO] ========== 攻击模拟开始 ==========
[2026-10-26 12:00:00] [INFO] 目标: 192.168.122.123:2222
[2026-10-26 12:00:00] [INFO] 字典: ./payloads/common_creds.txt
✓ 目标端口可达
[2026-10-26 12:00:01] [INFO] 加载凭据: 18 组

[*] 开始暴力破解...

✗ 登录失败: root:123456
✗ 登录失败: root:password
✓ 登录成功: root:admin

[+] 发现 1 个有效凭据

[*] 模拟黑客侦察行为...
[1/18] 执行: whoami
[2/18] 执行: uname -a
...

✓ 侦察完成: 15/18 命令成功
[2026-10-26 12:05:30] [INFO] ========== 攻击模拟结束 ==========
```

## 故障排查

### 连接超时

```bash
# 检查目标是否可达
ping -c 3 192.168.122.123

# 检查端口是否开放
nc -zv 192.168.122.123 2222
```

### sshpass 错误

```bash
# 检查是否安装
which sshpass

# 手动测试
sshpass -p 'password' ssh -p 2222 root@192.168.122.123
```

### 权限问题

```bash
# 确保脚本可执行
chmod +x simulate_attack.sh
```

## 技术细节

- 使用 `sshpass` 非交互式传递密码
- `-o StrictHostKeyChecking=no` 跳过主机密钥验证
- `-o ConnectTimeout=5` 设置 5 秒连接超时
- `timeout 10` 限制每次 SSH 会话最长 10 秒
- 所有失败尝试和成功登录都记录到日志

## 参考资料

- [Cowrie 蜜罐文档](https://github.com/cowrie/cowrie)
- [SSH 暴力破解防护](https://www.ssh.com/academy/ssh/attack)
- [常见弱密码列表](https://github.com/danielmiessler/SecLists)
