"""Tests for severity normalisation and the alert model."""

import unittest

from alertfuse.models import (
    SEVERITY_ORDER,
    Alert,
    bump_severity,
    fingerprint,
    normalize_severity,
    severity_rank,
)


class SeverityTests(unittest.TestCase):
    def test_canonical_labels_round_trip(self):
        for label in SEVERITY_ORDER:
            self.assertEqual(normalize_severity(label)[0], label)

    def test_case_and_spacing_folded(self):
        self.assertEqual(normalize_severity("  CRITICAL ")[0], "critical")
        self.assertEqual(normalize_severity("High")[0], "high")

    def test_vendor_aliases(self):
        cases = {
            "sev5": "critical",
            "P1": "critical",
            "warning": "medium",
            "notice": "low",
            "informational": "info",
            "emergency": "critical",
        }
        for raw, expected in cases.items():
            self.assertEqual(normalize_severity(raw)[0], expected, raw)

    def test_numeric_cvss_scale(self):
        self.assertEqual(normalize_severity(9.8)[0], "critical")
        self.assertEqual(normalize_severity(7.5)[0], "high")
        self.assertEqual(normalize_severity(5.0)[0], "medium")
        self.assertEqual(normalize_severity(2.1)[0], "low")
        self.assertEqual(normalize_severity(0)[0], "info")

    def test_numeric_strings_use_same_scale(self):
        self.assertEqual(normalize_severity("9.1")[0], "critical")
        self.assertEqual(normalize_severity("4")[0], "medium")

    def test_unknown_values_never_inflate_urgency(self):
        self.assertEqual(normalize_severity("banana")[0], "low")
        self.assertEqual(normalize_severity(None)[0], "low")
        self.assertEqual(normalize_severity("")[0], "low")
        self.assertEqual(normalize_severity(True)[0], "low")

    def test_score_matches_label(self):
        label, score = normalize_severity("high")
        self.assertEqual(label, "high")
        self.assertEqual(score, 4)


class BumpTests(unittest.TestCase):
    def test_single_step(self):
        self.assertEqual(bump_severity("medium"), "high")
        self.assertEqual(bump_severity("low"), "medium")

    def test_capped_at_critical(self):
        self.assertEqual(bump_severity("critical"), "critical")
        self.assertEqual(bump_severity("high", 5), "critical")

    def test_unknown_label_treated_as_low(self):
        self.assertEqual(bump_severity("nonsense"), "medium")


class RankTests(unittest.TestCase):
    def test_critical_outranks_everything(self):
        for label in ("high", "medium", "low", "info"):
            self.assertGreater(severity_rank("critical"), severity_rank(label))

    def test_unknown_ranks_as_info(self):
        self.assertEqual(severity_rank("banana"), severity_rank("info"))


class FingerprintTests(unittest.TestCase):
    def test_punctuation_and_case_folded(self):
        self.assertEqual(
            fingerprint("Brute Force - SSH"), fingerprint("brute_force_ssh")
        )

    def test_distinct_detections_stay_distinct(self):
        self.assertNotEqual(fingerprint("Brute Force SSH"), fingerprint("Brute Force RDP"))

    def test_empty_is_safe(self):
        self.assertEqual(fingerprint(None), "")


class AlertModelTests(unittest.TestCase):
    def make(self, **kwargs):
        base = dict(index=0, ts=1_700_000_000.0, rule="Test Rule", severity="high", source="edr")
        base.update(kwargs)
        return Alert(**base)

    def test_entity_set_flattens_kinds(self):
        alert = self.make(entities={"host": ["ws01"], "user": ["alice"]})
        self.assertEqual(alert.entity_set(), frozenset({"host:ws01", "user:alice"}))

    def test_severity_score_uses_rank(self):
        self.assertEqual(self.make(severity="critical").severity_score, 5)

    def test_fingerprint_property(self):
        self.assertEqual(self.make(rule="Test Rule").fingerprint, "testrule")

    def test_no_entities_is_empty_set(self):
        self.assertEqual(self.make().entity_set(), frozenset())


if __name__ == "__main__":
    unittest.main()
