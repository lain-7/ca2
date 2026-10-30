# Attack Simulation

This directory contains tools that simulate an attacker against the SSH honeypot.

## Directory structure

```
attack/
├── simulate_attack.sh      # main attack simulation script
├── payloads/               # attack payloads
│   └── common_creds.txt    # common username/password list
└── logs/                   # attack logs (generated at runtime)
```

## Features

- SSH credential-guessing simulation
- Reconnaissance commands after a successful login
- Detailed attack logging
- Coloured terminal output
- Configurable delays and target

## Dependencies

```bash
# Arch Linux
sudo pacman -S sshpass openssh coreutils

# Ubuntu/Debian
sudo apt install sshpass openssh-client coreutils
```

## Usage

### Basic usage

```bash
# specify the honeypot IP, port defaults to 22 (Cowrie uses 22 on the VPS)
./simulate_attack.sh <honeypot IP>

# specify IP and port explicitly
./simulate_attack.sh <honeypot IP> 22       # VPS environment
./simulate_attack.sh 192.168.122.123 2222   # old VirtualBox environment, Cowrie on 2222
```

> Note: do not add `-o BatchMode=yes` to ssh -- it disables the password prompt, so sshpass
> cannot feed the password and every login "fails". The script is already fixed accordingly.

### Change the credential list

Edit `payloads/common_creds.txt`, in `username:password` format:

```
root:123456
admin:admin
user:password
```

### Adjust attack parameters

Edit the configuration section of `simulate_attack.sh`:

```bash
DELAY_BETWEEN_ATTEMPTS=2     # delay between login attempts (seconds)
DELAY_BETWEEN_COMMANDS=1     # delay between commands (seconds)
```

## Output files

- `logs/attack_YYYYMMDD_HHMMSS.log` - full attack log
- `logs/successful_logins.log` - credentials of successful logins

## Simulated attacker behaviour

1. **Reachability test** - check whether the target port is open
2. **Credential guessing** - try to log in using the wordlist
3. **Reconnaissance commands** - after a successful login, run:
   - identity: `whoami`, `id`
   - system info: `uname -a`, `cat /etc/os-release`
   - network config: `ifconfig`, `ip addr`, `netstat`
   - process info: `ps aux`, `w`, `last`
   - file discovery: `ls -la /home`, `ls -la /root`
   - system resources: `df -h`, `free -m`
   - history: `cat /root/.bash_history`
   - config files: `find / -name '*.conf'`

## Security note

**For authorised testing only.**

- This tool is only for testing your own honeypot in an authorised environment.
- Attacking systems you are not authorised to test is illegal.
- Follow local laws and academic integrity rules.

## Example output

```
╔════════════════════════════════════════════════════════════╗
║          SSH Honeypot Attack Simulator v1.0                ║
║          Attack Simulation Script                          ║
╚════════════════════════════════════════════════════════════╝

[2026-10-26 12:00:00] [INFO] ========== Attack simulation start ==========
[2026-10-26 12:00:00] [INFO] Target: 192.168.122.123:2222
[2026-10-26 12:00:00] [INFO] Wordlist: ./payloads/common_creds.txt
[ok] target port reachable
[2026-10-26 12:00:01] [INFO] Loaded credentials: 18 pairs

[*] Starting credential sweep...

[x] login failed: root:123456
[x] login failed: root:password
[ok] login succeeded: root:admin

[+] Found 1 valid credential(s)

[*] Simulating reconnaissance behaviour...
[1/18] running: whoami
[2/18] running: uname -a
...

[ok] reconnaissance done: 15/18 commands succeeded
[2026-10-26 12:05:30] [INFO] ========== Attack simulation end ==========
```

## Troubleshooting

### Connection timeout

```bash
# check whether the target is reachable
ping -c 3 192.168.122.123

# check whether the port is open
nc -zv 192.168.122.123 2222
```

### sshpass errors

```bash
# check it is installed
which sshpass

# test manually
sshpass -p 'password' ssh -p 2222 root@192.168.122.123
```

### Permission issues

```bash
# make sure the script is executable
chmod +x simulate_attack.sh
```

## Technical details

- Uses `sshpass` to pass the password non-interactively
- `-o StrictHostKeyChecking=no` skips host key verification
- `-o ConnectTimeout=5` sets a 5-second connection timeout
- `timeout 10` caps each SSH session at 10 seconds
- All failed attempts and successful logins are recorded to the log

## References

- [Cowrie honeypot docs](https://github.com/cowrie/cowrie)
- [SSH brute-force protection](https://www.ssh.com/academy/ssh/attack)
- [Common weak password lists](https://github.com/danielmiessler/SecLists)
