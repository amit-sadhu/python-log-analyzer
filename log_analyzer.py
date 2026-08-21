"""
log_analyzer.py
---------------
SSH Authentication Log Analyzer

Author  : Amit Sadhu (GitHub: Venom-077)
Purpose : Reads an SSH auth log file, counts successful and failed login
          attempts, identifies IPs with repeated failures, prints a summary,
          and optionally exports results to a JSON report.

ETHICAL USE NOTICE:
  Only run this tool against log files from systems you own or are
  explicitly authorized to administer. Unauthorized log access or
  network scanning is illegal and unethical.
"""

import re
import json
import argparse
from collections import defaultdict
from datetime import datetime


# ──────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ──────────────────────────────────────────────────────────────────────────────

# How many failed attempts from one IP before we flag it as suspicious
SUSPICIOUS_THRESHOLD = 3

# Regex patterns to detect log lines
# re.compile() turns a pattern string into a fast, reusable search object
PATTERN_FAILED = re.compile(r"Failed password for .+ from (\d+\.\d+\.\d+\.\d+)")
PATTERN_SUCCESS = re.compile(r"Accepted (?:password|publickey) for .+ from (\d+\.\d+\.\d+\.\d+)")


# ──────────────────────────────────────────────────────────────────────────────
# CORE FUNCTIONS
# ──────────────────────────────────────────────────────────────────────────────

def parse_log_file(filepath: str) -> dict:
    """
    Read a log file line by line and count login events.

    Parameters
    ----------
    filepath : str
        Path to the SSH auth log file (e.g. 'sample_data/auth.log')

    Returns
    -------
    dict with keys:
        'success_count'  – total successful logins
        'failed_count'   – total failed login attempts
        'failed_ips'     – dict mapping IP → number of failures
        'success_ips'    – dict mapping IP → number of successes
    """
    # defaultdict(int) is like a normal dict but automatically starts any
    # new key at 0, so we can just do counts[ip] += 1 without checking first
    failed_ips  = defaultdict(int)
    success_ips = defaultdict(int)

    try:
        with open(filepath, "r") as log_file:
            for line in log_file:
                # Check if this line is a FAILED login
                failed_match = PATTERN_FAILED.search(line)
                if failed_match:
                    ip = failed_match.group(1)   # group(1) = first capture group = the IP
                    failed_ips[ip] += 1
                    continue                      # no need to check success pattern

                # Check if this line is a SUCCESSFUL login
                success_match = PATTERN_SUCCESS.search(line)
                if success_match:
                    ip = success_match.group(1)
                    success_ips[ip] += 1

    except FileNotFoundError:
        print(f"[ERROR] File not found: {filepath}")
        raise

    return {
        "success_count": sum(success_ips.values()),
        "failed_count" : sum(failed_ips.values()),
        "failed_ips"   : dict(failed_ips),
        "success_ips"  : dict(success_ips),
    }


def find_suspicious_ips(failed_ips: dict, threshold: int = SUSPICIOUS_THRESHOLD) -> dict:
    """
    Return only those IPs whose failed-login count meets or exceeds threshold.

    A high number of failures from one IP may indicate:
      - A brute-force attack (automated password guessing)
      - A misconfigured legitimate client (unlikely but possible)

    Parameters
    ----------
    failed_ips : dict   IP → failure count
    threshold  : int    Minimum failures to consider suspicious

    Returns
    -------
    dict  IP → failure count, sorted from most to fewest failures
    """
    suspicious = {
        ip: count
        for ip, count in failed_ips.items()
        if count >= threshold
    }
    # Sort by count descending so the worst offender appears first
    return dict(sorted(suspicious.items(), key=lambda x: x[1], reverse=True))


def print_summary(results: dict, suspicious_ips: dict) -> None:
    """
    Print a formatted summary table to the terminal.
    """
    divider = "=" * 55

    print(f"\n{divider}")
    print("     SSH LOG ANALYSIS SUMMARY")
    print(divider)
    print(f"  Total successful logins  : {results['success_count']}")
    print(f"  Total failed attempts    : {results['failed_count']}")
    print(divider)

    if results["success_ips"]:
        print("\n  Successful logins by IP:")
        for ip, count in sorted(results["success_ips"].items()):
            print(f"    {ip:<20}  {count} login(s)")

    print(divider)

    if results["failed_ips"]:
        print("\n  Failed attempts by IP:")
        for ip, count in sorted(results["failed_ips"].items(),
                                 key=lambda x: x[1], reverse=True):
            flag = "  ⚠  SUSPICIOUS" if ip in suspicious_ips else ""
            print(f"    {ip:<20}  {count} attempt(s){flag}")

    print(divider)

    if suspicious_ips:
        print(f"\n  ⚠  {len(suspicious_ips)} suspicious IP(s) detected")
        print(f"     (>= {SUSPICIOUS_THRESHOLD} failed attempts)")
        for ip, count in suspicious_ips.items():
            print(f"    {ip}  →  {count} failures")
    else:
        print("\n  ✓  No suspicious IPs detected.")

    print(f"{divider}\n")


def export_json(results: dict, suspicious_ips: dict, output_path: str) -> None:
    """
    Write the analysis results to a JSON file.

    JSON (JavaScript Object Notation) is a lightweight data format that is
    easy for both humans and programs to read. Security tools often use JSON
    for reports because it can be imported into SIEMs and dashboards.
    """
    report = {
        "generated_at"    : datetime.now().isoformat(),
        "summary": {
            "total_successes": results["success_count"],
            "total_failures" : results["failed_count"],
        },
        "successful_ips"  : results["success_ips"],
        "failed_ips"      : results["failed_ips"],
        "suspicious_ips"  : suspicious_ips,
        "threshold_used"  : SUSPICIOUS_THRESHOLD,
    }

    with open(output_path, "w") as f:
        json.dump(report, f, indent=4)

    print(f"[✓] Report exported to: {output_path}")


# ──────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────────────────────────────────────

def main():
    """
    Parse command-line arguments and run the analyzer.
    argparse lets users pass options like --log and --export when running
    the script from the terminal.
    """
    parser = argparse.ArgumentParser(
        description="Analyze SSH authentication logs for suspicious activity."
    )
    parser.add_argument(
        "--log",
        default="sample_data/auth.log",
        help="Path to the auth log file (default: sample_data/auth.log)"
    )
    parser.add_argument(
        "--export",
        metavar="OUTPUT.json",
        help="Optional: export results to a JSON file (e.g. --export report.json)"
    )

    args = parser.parse_args()

    print(f"[*] Analyzing log file: {args.log}")
    results       = parse_log_file(args.log)
    suspicious    = find_suspicious_ips(results["failed_ips"])

    print_summary(results, suspicious)

    if args.export:
        export_json(results, suspicious, args.export)


if __name__ == "__main__":
    # This block runs only when you execute the script directly:
    #   python log_analyzer.py
    # It does NOT run when another file imports this script (e.g. in tests).
    main()
