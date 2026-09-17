# python-log-analyzer

A beginner-friendly Python tool that analyzes SSH authentication logs, counts login events, and identifies IP addresses with repeated failed login attempts — a common indicator of brute-force attacks.

---

## Why This Project Exists

Security teams analyze authentication logs every day to detect suspicious activity on servers. This project simulates that workflow using Python, demonstrating practical skills directly relevant to Blue Team, SOC Analyst, and Security Engineer roles.

---

## What It Does

- Reads an SSH `auth.log` file line by line
- Counts **successful** and **failed** login attempts
- Identifies **IP addresses** with repeated failures (potential brute-force attackers)
- Prints a clear **summary table** to the terminal
- Optionally exports results to a **JSON report** for further analysis or integration with other tools

---

## Requirements

- Python 3.7 or higher
- No third-party libraries required — uses only Python's standard library

---

## How to Run

### 1. Clone the repository

```bash
git clone https://github.com/Venom-077/python-log-analyzer.git
cd python-log-analyzer
```

### 2. Run with the included sample log

```bash
python log_analyzer.py
```

### 3. Run with a custom log file

```bash
python log_analyzer.py --log /path/to/your/auth.log
```

### 4. Export results to JSON

```bash
python log_analyzer.py --export report.json
```

---

## Example Output

```
[*] Analyzing log file: sample_data/auth.log

=======================================================
     SSH LOG ANALYSIS SUMMARY
=======================================================
  Total successful logins  : 5
  Total failed attempts    : 12
=======================================================

  Successful logins by IP:
    192.168.1.10          2 login(s)
    192.168.1.20          2 login(s)
    192.168.1.30          1 login(s)
=======================================================

  Failed attempts by IP:
    10.0.0.55             7 attempt(s)  ⚠  SUSPICIOUS
    203.0.113.42          5 attempt(s)  ⚠  SUSPICIOUS
    198.51.100.7          2 attempt(s)
=======================================================

  ⚠  2 suspicious IP(s) detected
     (>= 3 failed attempts)
    10.0.0.55  →  7 failures
    203.0.113.42  →  5 failures
=======================================================
```

---

## How to Run the Tests

```bash
python -m pytest tests/ -v
```

Or without pytest:

```bash
python -m unittest discover tests/
```

---

## Project Structure

```
python-log-analyzer/
├── README.md                  ← This file
├── log_analyzer.py            ← Main Python script
├── .gitignore                 ← Tells Git which files to ignore
├── sample_data/
│   └── auth.log               ← Fictional sample log for testing
└── tests/
    └── test_log_analyzer.py   ← Automated tests
```

---

## Skills Demonstrated

| Skill | Where |
|---|---|
| Python scripting | `log_analyzer.py` |
| Regex (pattern matching) | `PATTERN_FAILED`, `PATTERN_SUCCESS` |
| File I/O | `parse_log_file()` |
| CLI argument parsing | `argparse` in `main()` |
| JSON export | `export_json()` |
| Security log analysis | Core project purpose |
| Brute-force detection | `find_suspicious_ips()` |
| Automated testing | `tests/test_log_analyzer.py` |
| Git & GitHub | Repository management |

---

## How to Improve This Project

Ideas for future enhancements:

- [ ] Add geolocation lookup for suspicious IPs
- [ ] Generate an HTML report with charts
- [ ] Add real-time log monitoring (tail mode)
- [ ] Integrate with Slack or email alerts
- [ ] Support Windows Event Log format

---

## ⚠ Ethical Use Notice

**This tool must only be used on systems you own or are explicitly authorized to administer.**

- Do not run this tool against logs from systems without written authorization.
- Do not use this tool to collect data on individuals without consent.
- Unauthorized access to computer systems or logs is illegal in most jurisdictions.

This project uses entirely fictional sample data. No real IP addresses, usernames, or server data are included.

---

## Author

**Amit Sadhu**  
M.Sc. IT — Network Security, Gujarat University  
GitHub:@amit-sadhu https://github.com/amit-sadhu

---

## License

MIT License — free to use, modify, and share with attribution.
