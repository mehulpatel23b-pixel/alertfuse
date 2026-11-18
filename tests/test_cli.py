"""End-to-end tests for the command line interface."""

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from alertfuse.cli import build_parser, main, parse_window

BASE = 1_763_456_400.0


def record(minute=0, rule="SSH Brute Force", severity="high", tool="edr", user="alice", host="ws01", ip="10.0.0.5"):
    return {
        "timestamp": "2026-11-18T09:{:02d}:00Z".format(minute),
        "rule": {"name": rule},
        "severity": severity,
        "source_tool": tool,
        "user": {"name": user},
        "host": {"name": host},
        "source": {"ip": ip},
    }


class WindowParseTests(unittest.TestCase):
    def test_units(self):
        self.assertEqual(parse_window("30s"), 30)
        self.assertEqual(parse_window("15m"), 900)
        self.assertEqual(parse_window("2h"), 7200)
        self.assertEqual(parse_window("1d"), 86400)

    def test_bare_number_is_seconds(self):
        self.assertEqual(parse_window("45"), 45)

    def test_uppercase_accepted(self):
        self.assertEqual(parse_window("10M"), 600)

    def test_invalid_rejected(self):
        with self.assertRaises(Exception):
            parse_window("soon")
        with self.assertRaises(Exception):
            parse_window("")

    def test_zero_rejected(self):
        with self.assertRaises(Exception):
            parse_window("0m")


class CliRunTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def write(self, name, payload):
        path = os.path.join(self.tmp, name)
        with open(path, "w", encoding="utf-8") as handle:
            if isinstance(payload, str):
                handle.write(payload)
            else:
                json.dump(payload, handle)
        return path

    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_fuses_duplicates(self):
        path = self.write("a.json", [record(0), record(1), record(2)])
        code, out, _ = self.run_cli([path])
        self.assertEqual(code, 0)
        self.assertIn("3 alerts -> 1 incident", out)

    def test_json_report_written(self):
        path = self.write("a.json", [record(0), record(1)])
        out_path = os.path.join(self.tmp, "report.json")
        code, _, _ = self.run_cli([path, "--json", out_path])
        self.assertEqual(code, 0)
        with open(out_path, encoding="utf-8") as handle:
            payload = json.load(handle)
        self.assertEqual(payload["incidents"][0]["alert_count"], 2)

    def test_fail_on_high_returns_one(self):
        path = self.write("a.json", [record(0, severity="high")])
        code, _, _ = self.run_cli([path, "--fail-on", "high"])
        self.assertEqual(code, 1)

    def test_fail_on_critical_passes_when_only_high(self):
        path = self.write("a.json", [record(0, severity="high", tool="edr")])
        code, _, _ = self.run_cli([path, "--fail-on", "critical"])
        self.assertEqual(code, 0)

    def test_allowlist_suppresses(self):
        path = self.write("a.json", [record(0, rule="Noisy Scan", tool="vulnscanner")])
        allow = self.write(
            "allow.json",
            {"suppress": [{"match": {"source": "vulnscanner"}, "reason": "known scanner"}]},
        )
        code, out, _ = self.run_cli([path, "--allowlist", allow])
        self.assertEqual(code, 0)
        self.assertIn("suppressed (not triaged)", out)

    def test_bad_allowlist_is_usage_error(self):
        path = self.write("a.json", [record(0)])
        allow = self.write("allow.json", "{not json")
        code, _, err = self.run_cli([path, "--allowlist", allow])
        self.assertEqual(code, 2)
        self.assertIn("allowlist", err)

    def test_missing_file_is_usage_error(self):
        with self.assertRaises(SystemExit):
            self.run_cli([os.path.join(self.tmp, "nope.json")])

    def test_ndjson_input(self):
        lines = "\n".join(json.dumps(record(i)) for i in range(3))
        path = self.write("a.ndjson", lines)
        code, out, _ = self.run_cli([path])
        self.assertEqual(code, 0)
        self.assertIn("3 alerts -> 1 incident", out)

    def test_multiple_files_combined(self):
        first = self.write("a.json", [record(0, tool="edr")])
        second = self.write("b.json", [record(1, tool="waf")])
        code, out, _ = self.run_cli([first, second])
        self.assertEqual(code, 0)
        self.assertIn("2 alerts -> 1 incident", out)
        self.assertIn("edr, waf", out)

    def test_limit_caps_displayed(self):
        payload = [record(0, host="ws01"), record(1, host="db01", user="bob")]
        path = self.write("a.json", payload)
        code, out, _ = self.run_cli([path, "--limit", "1"])
        self.assertEqual(code, 0)
        self.assertIn("#1", out)
        self.assertNotIn("#2", out)

    def test_quiet_still_writes_json(self):
        path = self.write("a.json", [record(0)])
        out_path = os.path.join(self.tmp, "r.json")
        code, out, _ = self.run_cli([path, "--quiet", "--json", out_path])
        self.assertEqual(code, 0)
        self.assertEqual(out.strip(), "")
        self.assertTrue(os.path.exists(out_path))

    def test_alerts_without_timestamps_warn(self):
        path = self.write("a.json", [{"rule": "no time"}, record(0)])
        code, _, err = self.run_cli([path])
        self.assertEqual(code, 0)
        self.assertIn("no usable timestamp", err)

    def test_no_parseable_alerts_is_error(self):
        path = self.write("a.json", [{"rule": "no time"}])
        code, _, err = self.run_cli([path])
        self.assertEqual(code, 2)
        self.assertIn("parseable timestamp", err)

    def test_empty_input_returns_zero(self):
        path = self.write("a.json", [])
        code, _, _ = self.run_cli([path])
        self.assertEqual(code, 0)

    def test_ist_timezone_flag(self):
        path = self.write("a.json", [record(0)])
        code, out, _ = self.run_cli([path, "--tz", "ist"])
        self.assertEqual(code, 0)
        # 09:00 UTC is 14:30 IST
        self.assertIn("14:30:00", out)

    def test_min_shared_two_keeps_incidents_apart(self):
        payload = [
            record(0, rule="A", host="ws01", user="alice", ip="10.0.0.5"),
            record(1, rule="B", host="ws02", user="alice", ip="10.0.0.6"),
        ]
        path = self.write("a.json", payload)
        code, out, _ = self.run_cli([path, "--min-shared", "2"])
        self.assertEqual(code, 0)
        self.assertIn("2 alerts -> 2 incidents", out)

    def test_window_flag_splits_long_gap(self):
        payload = [record(0), record(30)]
        path = self.write("a.json", payload)
        code, out, _ = self.run_cli([path, "--window", "5m"])
        self.assertEqual(code, 0)
        self.assertIn("2 alerts -> 2 incidents", out)

    def test_negative_limit_rejected(self):
        path = self.write("a.json", [record(0)])
        with self.assertRaises(SystemExit):
            self.run_cli([path, "--limit", "-1"])

    def test_parser_prog_name(self):
        self.assertEqual(build_parser().prog, "alertfuse")


if __name__ == "__main__":
    unittest.main()
