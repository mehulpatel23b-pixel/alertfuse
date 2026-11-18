"""Tests for allowlist suppression rules."""

import unittest

from alertfuse.models import Alert
from alertfuse.suppress import (
    RuleError,
    SuppressionRule,
    apply_allowlist,
    load_allowlist,
    load_allowlist_text,
)

BASE = 1_763_456_400.0


def alert(rule="Test", source="edr", severity="high", **entities):
    return Alert(
        index=0,
        ts=BASE,
        rule=rule,
        severity=severity,
        source=source,
        entities={k: list(v) for k, v in entities.items()},
    )


class RuleValidationTests(unittest.TestCase):
    def test_empty_match_refused(self):
        with self.assertRaises(RuleError):
            SuppressionRule(match={}, reason="because")

    def test_missing_reason_refused(self):
        with self.assertRaises(RuleError):
            SuppressionRule(match={"rule": "X"}, reason="  ")

    def test_empty_condition_value_refused(self):
        with self.assertRaises(RuleError):
            SuppressionRule(match={"rule": " "}, reason="because")

    def test_generated_name_is_readable(self):
        rule = SuppressionRule(match={"rule": "X", "source": "edr"}, reason="r")
        self.assertEqual(rule.name, "rule=X+source=edr")

    def test_explicit_name_kept(self):
        rule = SuppressionRule(match={"rule": "X"}, reason="r", name="known-good")
        self.assertEqual(rule.name, "known-good")


class RuleMatchingTests(unittest.TestCase):
    def test_rule_match_is_fingerprint_insensitive(self):
        rule = SuppressionRule(match={"rule": "brute_force_ssh"}, reason="r")
        self.assertTrue(rule.matches(alert(rule="Brute Force SSH")))

    def test_source_match_case_insensitive(self):
        rule = SuppressionRule(match={"source": "EDR"}, reason="r")
        self.assertTrue(rule.matches(alert(source="edr")))

    def test_severity_match(self):
        rule = SuppressionRule(match={"severity": "INFO"}, reason="r")
        self.assertTrue(rule.matches(alert(severity="info")))

    def test_entity_match(self):
        rule = SuppressionRule(match={"host": "WS01"}, reason="r")
        self.assertTrue(rule.matches(alert(host=["ws01"])))

    def test_all_conditions_required(self):
        rule = SuppressionRule(match={"rule": "Test", "host": "ws99"}, reason="r")
        self.assertFalse(rule.matches(alert(rule="Test", host=["ws01"])))

    def test_unrelated_alert_not_matched(self):
        rule = SuppressionRule(match={"host": "ws01"}, reason="r")
        self.assertFalse(rule.matches(alert(host=["ws02"])))

    def test_missing_entity_not_matched(self):
        rule = SuppressionRule(match={"host": "ws01"}, reason="r")
        self.assertFalse(rule.matches(alert()))


class LoadingTests(unittest.TestCase):
    def test_list_payload(self):
        rules = load_allowlist([{"match": {"rule": "X"}, "reason": "r"}])
        self.assertEqual(len(rules), 1)

    def test_suppress_key(self):
        rules = load_allowlist({"suppress": [{"match": {"rule": "X"}, "reason": "r"}]})
        self.assertEqual(len(rules), 1)

    def test_rules_key(self):
        rules = load_allowlist({"rules": [{"match": {"rule": "X"}, "reason": "r"}]})
        self.assertEqual(len(rules), 1)

    def test_bad_payload_refused(self):
        with self.assertRaises(RuleError):
            load_allowlist("nope")

    def test_non_object_entry_refused(self):
        with self.assertRaises(RuleError):
            load_allowlist([["rule", "X"]])

    def test_text_round_trip(self):
        rules = load_allowlist_text('{"suppress": [{"match": {"rule": "X"}, "reason": "r"}]}')
        self.assertEqual(len(rules), 1)

    def test_empty_text_is_no_rules(self):
        self.assertEqual(load_allowlist_text("   "), [])

    def test_invalid_json_reports(self):
        with self.assertRaises(RuleError):
            load_allowlist_text("{not json")


class ApplyTests(unittest.TestCase):
    def test_suppressed_alerts_reported_not_dropped(self):
        alerts = [alert(rule="Noisy", host=["ws01"]), alert(rule="Real", host=["ws02"])]
        rules = [SuppressionRule(match={"rule": "Noisy"}, reason="known scanner", name="scanner")]
        kept, suppressed = apply_allowlist(alerts, rules)
        self.assertEqual([a.rule for a in kept], ["Real"])
        self.assertEqual(len(suppressed), 1)
        self.assertEqual(suppressed[0][1], "scanner")

    def test_first_matching_rule_wins(self):
        alerts = [alert(rule="X")]
        rules = [
            SuppressionRule(match={"rule": "X"}, reason="r", name="first"),
            SuppressionRule(match={"source": "edr"}, reason="r", name="second"),
        ]
        _, suppressed = apply_allowlist(alerts, rules)
        self.assertEqual(suppressed[0][1], "first")

    def test_no_rules_keeps_everything(self):
        alerts = [alert(), alert()]
        kept, suppressed = apply_allowlist(alerts, [])
        self.assertEqual(len(kept), 2)
        self.assertEqual(suppressed, [])


if __name__ == "__main__":
    unittest.main()
