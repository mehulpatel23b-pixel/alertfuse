"""Tests for the correlation engine."""

import unittest

from alertfuse.cluster import ClusterConfig, Incident, build_incidents, link_reason
from alertfuse.models import Alert

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


class ConfigTests(unittest.TestCase):
    def test_defaults(self):
        cfg = ClusterConfig()
        self.assertEqual(cfg.window_seconds, 900.0)
        self.assertEqual(cfg.min_shared, 1)

    def test_window_must_be_positive(self):
        with self.assertRaises(ValueError):
            ClusterConfig(window_seconds=0)

    def test_min_shared_must_be_positive(self):
        with self.assertRaises(ValueError):
            ClusterConfig(min_shared=0)


class DuplicateMergeTests(unittest.TestCase):
    def test_same_rule_same_host_merges(self):
        alerts = [
            alert(0, host=["ws01"], user=["alice"]),
            alert(1, host=["ws01"], user=["alice"]),
            alert(2, host=["ws01"], user=["alice"]),
        ]
        incidents = build_incidents(alerts)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(len(incidents[0].alerts), 3)

    def test_cross_tool_duplicates_merge(self):
        alerts = [
            alert(0, rule="SSH Brute Force", source="edr", host=["ws01"], user=["alice"]),
            alert(1, rule="ssh_brute_force", source="waf", host=["ws01"], user=["alice"]),
        ]
        incidents = build_incidents(alerts)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].sources, ["edr", "waf"])

    def test_reason_names_the_shared_entity(self):
        alerts = [alert(0, host=["ws01"]), alert(1, host=["ws01"])]
        incidents = build_incidents(alerts)
        reasons = " ".join(incidents[0].reasons)
        self.assertIn("host:ws01", reasons)

    def test_repeat_outside_window_stays_separate(self):
        alerts = [alert(0, host=["ws01"]), alert(60, host=["ws01"])]
        incidents = build_incidents(alerts, ClusterConfig(window_seconds=900))
        self.assertEqual(len(incidents), 2)

    def test_min_shared_controls_distinct_rule_merges(self):
        alerts = [
            alert(0, rule="Password Spray", host=["ws01"], user=["alice"]),
            alert(1, rule="Malware Detected", host=["ws02"], user=["alice"]),
        ]
        self.assertEqual(len(build_incidents(alerts, ClusterConfig(min_shared=2))), 2)
        self.assertEqual(len(build_incidents(alerts, ClusterConfig(min_shared=1))), 1)

    def test_same_rule_repeat_merges_on_single_anchor(self):
        alerts = [
            alert(0, rule="Password Spray", host=["ws01"], user=["alice"]),
            alert(1, rule="Password Spray", host=["ws02"], user=["alice"]),
        ]
        self.assertEqual(len(build_incidents(alerts, ClusterConfig(min_shared=2))), 1)


class ChainTests(unittest.TestCase):
    def test_distinct_rules_on_same_actor_merge(self):
        alerts = [
            alert(0, rule="Password Spray", user=["alice"], host=["ws01"]),
            alert(2, rule="Successful Logon After Failures", user=["alice"], host=["ws01"]),
            alert(4, rule="Sensitive File Access", user=["alice"], host=["ws01"]),
        ]
        incidents = build_incidents(alerts)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(len(incidents[0].rules), 3)

    def test_distinct_rules_different_actors_stay_separate(self):
        alerts = [
            alert(0, rule="Password Spray", user=["alice"], host=["ws01"]),
            alert(2, rule="Malware Detected", user=["bob"], host=["ws02"]),
        ]
        self.assertEqual(len(build_incidents(alerts)), 2)

    def test_shared_ip_links_otherwise_unrelated_hosts(self):
        alerts = [
            alert(0, rule="Port Scan", ip=["10.0.0.9"]),
            alert(1, rule="Web Exploit Attempt", ip=["10.0.0.9"]),
        ]
        incidents = build_incidents(alerts)
        self.assertEqual(len(incidents), 1)
        self.assertIn("ip:10.0.0.9", " ".join(incidents[0].reasons))

    def test_shared_hash_links_alerts(self):
        alerts = [
            alert(0, rule="AV Detection", hash=["deadbeefdeadbeef"]),
            alert(1, rule="EDR Quarantine", hash=["deadbeefdeadbeef"]),
        ]
        self.assertEqual(len(build_incidents(alerts)), 1)

    def test_weak_entity_alone_does_not_merge_distinct_rules(self):
        alerts = [
            alert(0, rule="Suspicious Parent", process=["cmd.exe"]),
            alert(1, rule="LOLBin Use", process=["cmd.exe"]),
        ]
        self.assertEqual(len(build_incidents(alerts)), 2)

    def test_weak_entity_merges_same_rule_repeat(self):
        alerts = [
            alert(0, rule="LOLBin Use", process=["cmd.exe"]),
            alert(1, rule="LOLBin Use", process=["cmd.exe"]),
        ]
        self.assertEqual(len(build_incidents(alerts)), 1)

    def test_long_campaign_still_collapses(self):
        # Each alert is 5 minutes after the previous one, so the gap from the
        # incident's latest alert stays inside the window.
        alerts = [alert(i * 5, rule="Beacon", host=["ws01"]) for i in range(12)]
        incidents = build_incidents(alerts, ClusterConfig(window_seconds=900))
        self.assertEqual(len(incidents), 1)
        self.assertEqual(len(incidents[0].alerts), 12)


class SeverityTests(unittest.TestCase):
    def test_worst_alert_wins(self):
        alerts = [
            alert(0, rule="A", severity="low", host=["ws01"]),
            alert(1, rule="B", severity="critical", host=["ws01"]),
        ]
        incidents = build_incidents(alerts)
        self.assertEqual(incidents[0].max_severity, "critical")

    def test_cross_tool_agreement_raises_one_step(self):
        alerts = [
            alert(0, rule="A", severity="medium", source="edr", host=["ws01"]),
            alert(1, rule="B", severity="medium", source="waf", host=["ws01"]),
        ]
        incidents = build_incidents(alerts)
        self.assertEqual(incidents[0].max_severity, "medium")
        self.assertEqual(incidents[0].severity, "high")

    def test_single_source_gets_no_bump(self):
        alerts = [
            alert(0, rule="A", severity="medium", source="edr", host=["ws01"]),
            alert(1, rule="B", severity="medium", source="edr", host=["ws01"]),
        ]
        incidents = build_incidents(alerts)
        self.assertEqual(incidents[0].severity, "medium")

    def test_bump_never_exceeds_critical(self):
        alerts = [
            alert(0, rule="A", severity="critical", source="edr", host=["ws01"]),
            alert(1, rule="B", severity="critical", source="waf", host=["ws01"]),
        ]
        incidents = build_incidents(alerts)
        self.assertEqual(incidents[0].severity, "critical")

    def test_bump_can_be_disabled(self):
        alerts = [
            alert(0, rule="A", severity="medium", source="edr", host=["ws01"]),
            alert(1, rule="B", severity="medium", source="waf", host=["ws01"]),
        ]
        incidents = build_incidents(alerts, ClusterConfig(bump_on_sources=False))
        self.assertEqual(incidents[0].severity, "medium")


class OrderingTests(unittest.TestCase):
    def test_incidents_sorted_worst_first(self):
        alerts = [
            alert(0, rule="Low thing", severity="low", host=["ws01"]),
            alert(1, rule="Critical thing", severity="critical", host=["db01"]),
        ]
        incidents = build_incidents(alerts)
        self.assertEqual(incidents[0].severity, "critical")

    def test_equal_severity_sorted_by_time(self):
        alerts = [
            alert(10, rule="Second", severity="high", host=["ws02"]),
            alert(0, rule="First", severity="high", host=["ws01"]),
        ]
        incidents = build_incidents(alerts)
        self.assertEqual(incidents[0].rules, ["First"])

    def test_empty_input(self):
        self.assertEqual(build_incidents([]), [])


class IncidentPropertyTests(unittest.TestCase):
    def test_duration_and_bounds(self):
        incidents = build_incidents([
            alert(0, host=["ws01"]),
            alert(10, host=["ws01"]),
        ])
        incident = incidents[0]
        self.assertEqual(incident.duration, 600.0)
        self.assertEqual(incident.first_ts, BASE)
        self.assertEqual(incident.last_ts, BASE + 600)

    def test_entity_summary_deduplicates(self):
        incidents = build_incidents([
            alert(0, host=["ws01"], user=["alice"]),
            alert(1, host=["ws01"], user=["alice"]),
        ])
        summary = incidents[0].entity_summary()
        self.assertEqual(summary["host"], ["ws01"])
        self.assertEqual(summary["user"], ["alice"])

    def test_link_reason_returns_none_outside_window(self):
        incident = Incident()
        incident.add(alert(0, host=["ws01"]), "first alert")
        self.assertIsNone(link_reason(incident, alert(60, host=["ws01"]), ClusterConfig()))

    def test_anchors_only_include_strong_kinds(self):
        incidents = build_incidents([
            alert(0, host=["ws01"], process=["cmd.exe"], domain=["evil.test"]),
        ])
        self.assertIn("host:ws01", incidents[0].anchors)
        self.assertNotIn("process:cmd.exe", incidents[0].anchors)
        self.assertIn("process:cmd.exe", incidents[0].weak_entities)


if __name__ == "__main__":
    unittest.main()
