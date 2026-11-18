"""Core alert model and severity normalisation."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Tuple

# Ordered worst-first so sorting is stable and obvious.
SEVERITY_ORDER: Tuple[str, ...] = ("critical", "high", "medium", "low", "info")

SEVERITY_LABELS: Dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}

_ALIASES: Dict[str, str] = {
    "crit": "critical",
    "severe": "critical",
    "s5": "critical",
    "sev5": "critical",
    "p1": "critical",
    "urgent": "critical",
    "emergency": "critical",
    "major": "high",
    "error": "high",
    "severe_high": "high",
    "sev4": "high",
    "s4": "high",
    "p2": "high",
    "warning": "medium",
    "warn": "medium",
    "moderate": "medium",
    "sev3": "medium",
    "s3": "medium",
    "p3": "medium",
    "notice": "low",
    "minor": "low",
    "sev2": "low",
    "s2": "low",
    "p4": "low",
    "informational": "info",
    "information": "info",
    "debug": "info",
    "trace": "info",
    "sev1": "info",
    "s1": "info",
    "p5": "info",
}

_WHITESPACE = re.compile(r"[\s_\-]+")


def normalize_severity(value: Any) -> Tuple[str, int]:
    """Return ``(label, score)`` for a severity value from any export.

    Accepts canonical labels, common vendor aliases, and numeric severity on
    either a 0-10 or a 1-5 scale. Unknown values normalise to ``low`` so an
    unlabelled alert never manufactures urgency.
    """
    if value is None or isinstance(value, bool):
        return "low", SEVERITY_LABELS["low"]

    if isinstance(value, (int, float)):
        return _from_number(float(value))

    text = str(value).strip().lower()
    if not text:
        return "low", SEVERITY_LABELS["low"]

    key = _WHITESPACE.sub("", text)
    if key in SEVERITY_LABELS:
        return key, SEVERITY_LABELS[key]
    if key in _ALIASES:
        label = _ALIASES[key]
        return label, SEVERITY_LABELS[label]

    try:
        return _from_number(float(text))
    except ValueError:
        return "low", SEVERITY_LABELS["low"]


def _from_number(number: float) -> Tuple[str, int]:
    if number >= 9:
        label = "critical"
    elif number >= 7:
        label = "high"
    elif number >= 4:
        label = "medium"
    elif number >= 1:
        label = "low"
    else:
        label = "info"
    return label, SEVERITY_LABELS[label]


def bump_severity(label: str, steps: int = 1) -> str:
    """Raise a severity label by ``steps`` without going past critical."""
    if label not in SEVERITY_LABELS:
        label = "low"
    score = SEVERITY_LABELS[label] + max(0, steps)
    score = min(score, SEVERITY_LABELS["critical"])
    for name, value in SEVERITY_LABELS.items():
        if value == score:
            return name
    return "critical"


def severity_rank(label: str) -> int:
    """Rank where higher means worse; unknown labels rank as info."""
    return SEVERITY_LABELS.get(label, SEVERITY_LABELS["info"])


def fingerprint(rule: str) -> str:
    """Stable comparison key for a detection name across tools.

    Case, whitespace and punctuation are folded so "Brute Force - SSH" and
    "brute_force_ssh" count as the same detection.
    """
    text = _WHITESPACE.sub("", str(rule or "").lower())
    return re.sub(r"[^a-z0-9]", "", text)


@dataclass
class Alert:
    """One normalised alert row."""

    index: int
    ts: float
    rule: str
    severity: str
    source: str
    entities: Dict[str, List[str]] = field(default_factory=dict)
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def severity_score(self) -> int:
        return severity_rank(self.severity)

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.rule)

    def entity_set(self) -> FrozenSet[str]:
        """Flattened ``kind:value`` keys used for correlation."""
        return frozenset(
            "{}:{}".format(kind, value)
            for kind, values in self.entities.items()
            for value in values
        )
