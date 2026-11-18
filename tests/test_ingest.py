"""Tests for timestamp parsing and record loading."""

import json
import unittest

from alertfuse.ingest import load_alerts, load_json_records, parse_timestamp


class TimestampTests(unittest.TestCase):
    def test_epoch_seconds(self):
        self.assertEqual(parse_timestamp(1_700_000_000), 1_700_000_000.0)

    def test_epoch_milliseconds_scaled(self):
        self.assertEqual(parse_timestamp(1_700_000_000_000), 1_700_000_000.0)

    def test_epoch_string(self):
        self.assertEqual(parse_timestamp("1700000000"), 1_700_000_000.0)

    def test_iso_with_z(self):
        self.assertEqual(parse_timestamp("2026-11-18T09:00:00Z"), 1794992400.0)

    def test_iso_with_offset(self):
        self.assertEqual(parse_timestamp("2026-11-18T14:30:00+05:30"), 1794992400.0)

    def test_iso_with_space_separator(self):
        self.assertEqual(parse_timestamp("2026-11-18 09:00:00"), 1794992400.0)

    def test_naive_iso_assumed_utc(self):
        self.assertEqual(parse_timestamp("2026-11-18T09:00:00"), 1794992400.0)

    def test_syslog_style_without_seconds(self):
        self.assertEqual(parse_timestamp("2026-11-18T09:00"), 1794992400.0)

    def test_invalid_returns_none(self):
        for value in ("", "yesterday", None, True, "not a date"):
            self.assertIsNone(parse_timestamp(value), value)

    def test_zero_and_negative_rejected(self):
        self.assertIsNone(parse_timestamp(0))
        self.assertIsNone(parse_timestamp(-5))

    def test_out_of_range_date_returns_none(self):
        self.assertIsNone(parse_timestamp("2026-13-45T09:00:00"))


class LoadRecordsTests(unittest.TestCase):
    def test_json_array(self):
        records = load_json_records('[{"a": 1}, {"a": 2}]')
        self.assertEqual(len(records), 2)

    def test_single_object(self):
        self.assertEqual(len(load_json_records('{"a": 1}')), 1)

    def test_nested_alerts_key(self):
        payload = json.dumps({"alerts": [{"a": 1}, {"a": 2}, {"a": 3}]})
        self.assertEqual(len(load_json_records(payload)), 3)

    def test_nested_results_wrapper(self):
        payload = json.dumps({"data": {"events": [{"a": 1}]}})
        self.assertEqual(len(load_json_records(payload)), 1)

    def test_ndjson(self):
        text = '{"a": 1}\n{"a": 2}\n\n{"a": 3}\n'
        self.assertEqual(len(load_json_records(text)), 3)

    def test_ndjson_skips_broken_lines(self):
        text = '{"a": 1}\nnot json\n{"a": 2}\n'
        self.assertEqual(len(load_json_records(text)), 2)

    def test_empty_input(self):
        self.assertEqual(load_json_records("   "), [])

    def test_non_dict_entries_dropped(self):
        self.assertEqual(len(load_json_records("[1, 2, \"x\"]")), 0)


class LoadAlertsTests(unittest.TestCase):
    def test_basic_mapping(self):
        records = [{
            "timestamp": "2026-11-18T09:00:00Z",
            "rule": {"name": "Suspicious PowerShell"},
            "severity": "high",
            "source_tool": "edr",
            "user": {"name": "alice"},
            "host": {"name": "WS01.corp.local"},
        }]
        alerts = load_alerts(records)
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.rule, "Suspicious PowerShell")
        self.assertEqual(alert.severity, "high")
        self.assertEqual(alert.source, "edr")
        self.assertEqual(alert.entities["host"], ["ws01"])

    def test_alerts_sorted_by_time(self):
        records = [
            {"timestamp": "2026-11-18T09:10:00Z", "rule": "B", "severity": "low"},
            {"timestamp": "2026-11-18T09:00:00Z", "rule": "A", "severity": "low"},
        ]
        alerts = load_alerts(records)
        self.assertEqual([a.rule for a in alerts], ["A", "B"])

    def test_missing_timestamp_skipped(self):
        records = [
            {"rule": "No time", "severity": "high"},
            {"timestamp": "2026-11-18T09:00:00Z", "rule": "Timed", "severity": "low"},
        ]
        alerts = load_alerts(records)
        self.assertEqual([a.rule for a in alerts], ["Timed"])

    def test_missing_rule_gets_placeholder(self):
        alerts = load_alerts([{"timestamp": "2026-11-18T09:00:00Z"}])
        self.assertEqual(alerts[0].rule, "unclassified")

    def test_missing_severity_defaults_low(self):
        alerts = load_alerts([{"timestamp": "2026-11-18T09:00:00Z", "rule": "X"}])
        self.assertEqual(alerts[0].severity, "low")

    def test_default_source_applied(self):
        alerts = load_alerts(
            [{"timestamp": "2026-11-18T09:00:00Z", "rule": "X"}], default_source="wazuh"
        )
        self.assertEqual(alerts[0].source, "wazuh")

    def test_index_preserved_from_input(self):
        records = [
            {"timestamp": "2026-11-18T09:05:00Z", "rule": "B"},
            {"timestamp": "2026-11-18T09:00:00Z", "rule": "A"},
        ]
        alerts = load_alerts(records)
        self.assertEqual(alerts[0].index, 1)
        self.assertEqual(alerts[1].index, 0)

    def test_alternative_time_keys(self):
        alerts = load_alerts([{"@timestamp": "2026-11-18T09:00:00Z", "title": "T"}])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule, "T")


if __name__ == "__main__":
    unittest.main()
