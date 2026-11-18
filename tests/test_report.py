"""Tests for text and JSON reporting."""

import json
import unittest
from datetime import timezone

from alertfuse.cluster import ClusterConfig, build_incidents
from alertfuse.models import Alert
from alertfuse.report import build_summary, render_text, to_json

BASE = 1_763_456_400.0  # 2026-11-18T09:00:00Z


def alert(minute=0, rule="Brute Force", severity="high", source="edr", **entities):
    return Alert(
        index=int(minute * 10),
        ts=BASE + minute * 60,
        rule=rule,
        severity=severity,
        source=source,
        entities={k: list(v) for k, v in entities.items()},
    )


class SummaryTests(unittest.TestCase):
    def test_reduction_ratio(self):
        alerts = [alert(i, host=["ws01"], user=["alice"]) for i in range(5)]
        incidents = build_incidents(alerts)
        summary = build_summary(incidents, 5, (), ClusterConfig())
        self.assertEqual(summary["incidents"], 1)
        self.assertEqual(summary["reduction_ratio"], 5.0)
        self.assertEqual(summary["noise_removed_pct"], 80.0)

    def test_empty_summary_is_safe(self):
        summary = build_summary([], 0, (), ClusterConfig())
        self.assertEqual(summary["incidents"], 0)
        self.assertEqual(summary["reduction_ratio"], 0.0)
        self.assertEqual(summary["noise_removed_pct"], 0.0)

    def test_counts_severity_buckets(self):
        alerts = [
            alert(0, severity="critical", host=["a"]),
            alert(1, severity="low", host=["b"]),
        ]
        summary = build_summary(build_incidents(alerts), 2, (), ClusterConfig())
        self.assertEqual(summary["by_severity"]["critical"], 1)
        self.assertEqual(summary["by_severity"]["low"], 1)

    def test_cross_tool_counted(self):
        alerts = [
            alert(0, rule="A", source="edr", host=["ws01"]),
            alert(1, rule="B", source="waf", host=["ws01"]),
        ]
        summary = build_summary(build_incidents(alerts), 2, (), ClusterConfig())
        self.assertEqual(summary["cross_tool_incidents"], 1)


class TextTests(unittest.TestCase):
    def test_header_reports_counts(self):
        alerts = [alert(i, host=["ws01"]) for i in range(3)]
        incidents = build_incidents(alerts)
        text = render_text(incidents, 3, (), ClusterConfig())
        self.assertIn("3 alerts -> 1 incident", text)

    def test_suppressed_section_present(self):
        alerts = [alert(0, rule="Noisy")]
        text = render_text(
            build_incidents(alerts), 1, [(alerts[0], "scanner")], ClusterConfig()
        )
        self.assertIn("suppressed (not triaged)", text)
        self.assertIn("scanner", text)

    def test_empty_state(self):
        text = render_text([], 0, (), ClusterConfig())
        self.assertIn("Nothing to triage", text)

    def test_entity_line_rendered(self):
        alerts = [alert(0, host=["ws01"], user=["alice"])]
        text = render_text(build_incidents(alerts), 1, (), ClusterConfig())
        self.assertIn("host   : ws01", text)
        self.assertIn("user   : alice", text)

    def test_many_entities_truncated(self):
        hosts = ["h{:02d}".format(i) for i in range(9)]
        alerts = [alert(0, rule="Port Scan", ip=["10.0.0.1"])]
        incidents = build_incidents(alerts)
        incidents[0].alerts[0].entities["host"] = hosts
        incidents[0]._anchor_cache = None
        text = render_text(incidents, 1, (), ClusterConfig())
        self.assertIn("(+3 more)", text)

    def test_output_ends_with_single_newline(self):
        alerts = [alert(0, host=["ws01"])]
        text = render_text(build_incidents(alerts), 1, (), ClusterConfig())
        self.assertTrue(text.endswith("\n"))
        self.assertFalse(text.endswith("\n\n"))


class JsonTests(unittest.TestCase):
    def test_serialisable(self):
        alerts = [alert(0, host=["ws01"], user=["alice"])]
        payload = to_json(build_incidents(alerts), 1, (), ClusterConfig())
        json.dumps(payload)
        self.assertEqual(payload["incidents"][0]["alert_count"], 1)

    def test_rank_is_one_based(self):
        alerts = [alert(0, host=["a"]), alert(1, host=["b"])]
        payload = to_json(build_incidents(alerts), 2, (), ClusterConfig())
        self.assertEqual([i["rank"] for i in payload["incidents"]], [1, 2])

    def test_timestamps_are_strings(self):
        alerts = [alert(0, host=["ws01"])]
        payload = to_json(build_incidents(alerts), 1, (), ClusterConfig(), timezone.utc)
        self.assertIsInstance(payload["incidents"][0]["first_seen"], str)

    def test_merge_reasons_included(self):
        alerts = [alert(0, host=["ws01"]), alert(1, host=["ws01"])]
        payload = to_json(build_incidents(alerts), 2, (), ClusterConfig())
        reasons = payload["incidents"][0]["merge_reasons"]
        self.assertTrue(any("host:ws01" in r for r in reasons))

    def test_suppressed_listed(self):
        alerts = [alert(0, rule="Noisy")]
        payload = to_json(
            [], 1, [(alerts[0], "scanner")], ClusterConfig()
        )
        self.assertEqual(payload["suppressed"][0]["suppression"], "scanner")


if __name__ == "__main__":
    unittest.main()
