# Defender: Cowrie log analysis tools

Runs on the **honeypot machine (VM A)** to analyse the attack logs Cowrie captures: count login
attempts and commands, trace source IPs, and generate an analysis report. Corresponds to CA2
Task 4 (log analysis) and Task 5 (security recommendations).

> The simulation scripts on the attacker machine (VM B) are in `../attack/`; do not mix the two sides.

## Tool list

| File | Purpose |
|------|---------|
| `analyze_logs.sh` | main script, parses the logs and calls the three tools below in turn |
| `ip_tracker.py` | looks up the geolocation and ISP of source IPs and does a threat-level assessment |
| `visualizer.py` | prints ASCII bar / share charts in the terminal |
| `report_generator.py` | generates a detailed Markdown analysis report |

## Dependencies

```bash
# Arch Linux
sudo pacman -S jq python curl
# Ubuntu / Debian
sudo apt install jq python3 curl
```

Python uses only the standard library; no extra pip packages are needed.

## Usage

```bash
cd defense/

# 1. Analyse logs (pass the Cowrie log directory, or omit for the default path)
./analyze_logs.sh /home/cowrie/cowrie/var/log/cowrie

# 2. View the terminal summary and charts; the reports are written under reports/
cat reports/analysis_*.summary.txt
cat reports/analysis_*.report.md
```

With no real logs, use the sample log in the repository to run through the flow first (the first argument can be a file directly):

```bash
./analyze_logs.sh test_sample.json
```

## Output files

Each run produces a timestamped set of files (prefix `reports/analysis_YYYYMMDD_HHMMSS`):

| File | Content |
|------|---------|
| `.summary.txt` | plain-text summary (login/command/IP overview + charts) |
| `.report.md` | full Markdown report (summary, timeline, credentials, commands, threats, recommendations) |
| `.logins.tsv` | all login attempts |
| `.successful_logins.tsv` | successful logins |
| `.commands.tsv` | command executions |
| `.ips.txt` | deduplicated source IPs |
| `.ip_enrichment.json` | IP tracing results (JSON) |
| `.top_usernames.txt` / `.top_passwords.txt` / `.top_commands.txt` | frequency counts |

## IP tracing notes

- Data comes from the free [ip-api.com](https://ip-api.com/) API; no registration, limited to 45/min, and the script rate-limits automatically.
- Results are cached in `lib/ip_cache.json`, so the same IP is not looked up twice (`--no-cache` skips the cache).
- The threat level is a rule-based judgement: internal -> low; high-risk country or hostname containing scanner/bot -> medium. For reference only, not authoritative intelligence.
- Can be used standalone: `./ip_tracker.py --json 8.8.8.8 1.1.1.1`

## Caveats

- The experiment runs in an isolated LAN environment; "public IP tracing" is a demonstration simulating a real scenario.
- The logs and reports contain attacker credentials, commands and similar information; keep them safe and do not send them out with the logs.
- IP lookups send the IP to a third-party API; in offline or sensitive environments, use a local GeoIP database instead.
