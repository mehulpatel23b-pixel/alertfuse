"""Allowlist / suppression rules.

Suppression is the part of triage that quietly hides real attacks, so the
design is deliberately conservative:

* A rule must match **every** condition it declares.
* A rule with no conditions is refused, because it would suppress everything.
* Suppressed alerts are reported with their rule name, never dropped silently.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .models import Alert, fingerprint


class RuleError(ValueError):
    """Raised when a suppression rule is malformed."""


@dataclass
class SuppressionRule:
    """A single allowlist entry.

    ``match`` maps a field to a required value: ``rule``, ``source``,
    ``severity``, or any entity kind such as ``user``/``host``/``ip``.
    ``reason`` is required so every suppression is explainable later.
    """

    match: Dict[str, str] = field(default_factory=dict)
    reason: str = ""
    name: str = ""

    def __post_init__(self) -> None:
        if not self.match:
            raise RuleError("suppression rule needs at least one condition")
        if not str(self.reason).strip():
            raise RuleError("suppression rule needs a reason")
        cleaned = {}
        for key, value in self.match.items():
            text = str(value).strip()
            if not text:
                raise RuleError("empty condition value for {!r}".format(key))
            cleaned[str(key).strip().lower()] = text
        self.match = cleaned
        if not self.name:
            self.name = "+".join("{}={}".format(k, v) for k, v in sorted(cleaned.items()))

    def matches(self, alert: Alert) -> bool:
        for key, expected in self.match.items():
            if not self._field_matches(alert, key, expected):
                return False
        return True

    def _field_matches(self, alert: Alert, key: str, expected: str) -> bool:
        if key == "rule":
            return fingerprint(alert.rule) == fingerprint(expected)
        if key == "source":
            return alert.source.strip().lower() == expected.lower()
        if key == "severity":
            return alert.severity.lower() == expected.lower()
        wanted = expected.strip().lower()
        return any(v.lower() == wanted for v in alert.entities.get(key, []))


def load_allowlist(payload: Any) -> List[SuppressionRule]:
    """Build rules from a list, or a dict with a ``suppress``/``rules`` key."""
    entries: Iterable[Any]
    if isinstance(payload, dict):
        entries = payload.get("suppress") or payload.get("rules") or []
    elif isinstance(payload, list):
        entries = payload
    else:
        raise RuleError("allowlist must be a list or an object with 'suppress'")

    rules: List[SuppressionRule] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise RuleError("each rule must be an object")
        rules.append(
            SuppressionRule(
                match=entry.get("match") or {},
                reason=entry.get("reason", ""),
                name=entry.get("name", ""),
            )
        )
    return rules


def load_allowlist_text(text: str) -> List[SuppressionRule]:
    stripped = text.strip()
    if not stripped:
        return []
    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError as exc:
        raise RuleError("allowlist is not valid JSON: {}".format(exc)) from exc
    return load_allowlist(payload)


def apply_allowlist(
    alerts: Iterable[Alert], rules: Iterable[SuppressionRule]
) -> Tuple[List[Alert], List[Tuple[Alert, str]]]:
    """Split alerts into kept and suppressed, listing the rule for each drop."""
    rule_list = list(rules)
    kept: List[Alert] = []
    suppressed: List[Tuple[Alert, str]] = []

    for alert in alerts:
        hit: Optional[SuppressionRule] = None
        for rule in rule_list:
            if rule.matches(alert):
                hit = rule
                break
        if hit is None:
            kept.append(alert)
        else:
            suppressed.append((alert, hit.name))

    return kept, suppressed
