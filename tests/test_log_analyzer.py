"""
tests/test_log_analyzer.py
--------------------------
Automated tests for log_analyzer.py

These tests check that the functions work correctly without you having to
run the full program manually every time. Running tests is a professional
software practice — it proves your code behaves as expected.

Run with:
    python -m pytest tests/
or simply:
    python -m unittest discover tests/
"""

import unittest
import os
import tempfile

# We import the functions we want to test from our main script.
# This is why the if __name__ == "__main__" guard in log_analyzer.py matters —
# importing it here does NOT run main(), it only loads the functions.
from log_analyzer import parse_log_file, find_suspicious_ips, SUSPICIOUS_THRESHOLD


class TestParseLogFile(unittest.TestCase):
    """Tests for the parse_log_file() function."""

    def setUp(self):
        """
        setUp() runs before every individual test.
        We create a temporary log file with known content so our tests are
        predictable and don't depend on the real sample_data/auth.log file.
        """
        # tempfile creates a temporary file that is automatically cleaned up
        self.temp_file = tempfile.NamedTemporaryFile(
            mode="w", suffix=".log", delete=False
        )
        self.temp_file.write(
            "Aug 20 10:01:12 server sshd[1]: Accepted password for alice from 192.168.1.1 port 1001 ssh2\n"
            "Aug 20 10:02:00 server sshd[2]: Failed password for invalid user root from 10.0.0.1 port 2001 ssh2\n"
            "Aug 20 10:02:01 server sshd[3]: Failed password for invalid user root from 10.0.0.1 port 2002 ssh2\n"
            "Aug 20 10:02:02 server sshd[4]: Failed password for invalid user root from 10.0.0.1 port 2003 ssh2\n"
            "Aug 20 10:05:00 server sshd[5]: Accepted publickey for bob from 192.168.1.2 port 3001 ssh2\n"
        )
        self.temp_file.close()

    def tearDown(self):
        """tearDown() runs after every test to clean up the temp file."""
        os.unlink(self.temp_file.name)

    def test_success_count(self):
        """There should be exactly 2 successful logins in our test data."""
        results = parse_log_file(self.temp_file.name)
        self.assertEqual(results["success_count"], 2)

    def test_failed_count(self):
        """There should be exactly 3 failed attempts in our test data."""
        results = parse_log_file(self.temp_file.name)
        self.assertEqual(results["failed_count"], 3)

    def test_failed_ip_recorded(self):
        """The failing IP 10.0.0.1 should appear in failed_ips."""
        results = parse_log_file(self.temp_file.name)
        self.assertIn("10.0.0.1", results["failed_ips"])

    def test_failed_ip_count(self):
        """10.0.0.1 should have exactly 3 failures."""
        results = parse_log_file(self.temp_file.name)
        self.assertEqual(results["failed_ips"]["10.0.0.1"], 3)

    def test_success_ips_recorded(self):
        """Both successful IPs should be captured."""
        results = parse_log_file(self.temp_file.name)
        self.assertIn("192.168.1.1", results["success_ips"])
        self.assertIn("192.168.1.2", results["success_ips"])

    def test_file_not_found_raises(self):
        """Passing a non-existent file should raise FileNotFoundError."""
        with self.assertRaises(FileNotFoundError):
            parse_log_file("/nonexistent/path/auth.log")


class TestFindSuspiciousIPs(unittest.TestCase):
    """Tests for the find_suspicious_ips() function."""

    def test_above_threshold_is_flagged(self):
        """An IP with failures >= threshold must appear in suspicious list."""
        failed_ips = {"10.0.0.1": 5, "10.0.0.2": 1}
        result = find_suspicious_ips(failed_ips, threshold=3)
        self.assertIn("10.0.0.1", result)

    def test_below_threshold_not_flagged(self):
        """An IP with failures below threshold must NOT appear."""
        failed_ips = {"10.0.0.1": 5, "10.0.0.2": 1}
        result = find_suspicious_ips(failed_ips, threshold=3)
        self.assertNotIn("10.0.0.2", result)

    def test_empty_input_returns_empty(self):
        """No failed IPs means no suspicious IPs."""
        result = find_suspicious_ips({})
        self.assertEqual(result, {})

    def test_sorted_by_count_descending(self):
        """The worst offender (highest count) should come first."""
        failed_ips = {"1.1.1.1": 3, "2.2.2.2": 10, "3.3.3.3": 5}
        result = find_suspicious_ips(failed_ips, threshold=3)
        counts = list(result.values())
        self.assertEqual(counts, sorted(counts, reverse=True))


if __name__ == "__main__":
    unittest.main()
