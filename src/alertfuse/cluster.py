"""Correlation engine: turn an alert stream into incidents.

Merge rule, in priority order:

1. **Fingerprint match** - the same detection firing again on the same anchor
   entity inside the window is one incident, even from a different tool.
2. **Shared anchor entities** - two different detections that share at least
   ``min_shared`` strong entities (user, host, ip, hash) and land inside the
   window are one incident, because they describe the same actor or asset.
3. **Nothing shared** - separate incidents.

Every merge records why, so an analyst can audit or reject it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

from .models import Alert, bump_severity, severity_rank

# Entity kinds that are strong enough to merge *different* detections.
ANCHOR_KINDS: Tuple[str, ...] = ("user", "host", "ip", "hash")

# Entities that repeat constantly in normal operations. They merge repeats of
# the same detection but never different detections on their own.
WEAK_KINDS: Tuple[str, ...] = ("process", "parent_process", "file", "domain")


@dataclass
class ClusterConfig:
    """Tunables for correlation. Defaults suit a 24h SOC backlog sweep."""

    window_seconds: float = 900.0
    min_shared: int = 1
    bump_on_sources: bool = True
    host_suffixes: Sequence[str] = ()

    def __post_init__(self) -> None:
        if self.window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if self.min_shared < 1:
            raise ValueError("min_shared must be at least 1")


@dataclass
class Incident:
    """A group of alerts an analyst can treat as one unit of work."""

    alerts: List[Alert] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    _anchor_cache: Optional[Set[str]] = None
    _weak_cache: Optional[Set[str]] = None

    def add(self, alert: Alert, reason: str) -> None:
        self.alerts.append(alert)
        if reason and reason not in self.reasons:
            self.reasons.append(reason)
        self._anchor_cache = None
        self._weak_cache = None

    @property
    def first_ts(self) -> float:
        return min(a.ts for a in self.alerts)

    @property
    def last_ts(self) -> float:
        return max(a.ts for a in self.alerts)

    @property
    def duration(self) -> float:
        return self.last_ts - self.first_ts

    @property
    def sources(self) -> List[str]:
        return sorted({a.source for a in self.alerts})

    @property
    def rules(self) -> List[str]:
        seen: List[str] = []
        for alert in self.alerts:
            if alert.rule not in seen:
                seen.append(alert.rule)
        return seen

    @property
    def fingerprints(self) -> Set[str]:
        return {a.fingerprint for a in self.alerts}

    @property
    def max_severity(self) -> str:
        best = "info"
        for alert in self.alerts:
            if severity_rank(alert.severity) > severity_rank(best):
                best = alert.severity
        return best

    @property
    def severity(self) -> str:
        """Worst single alert, raised one step when several tools agree.

        Cross-tool agreement is real signal: the same behaviour seen by an EDR
        and a network sensor is more urgent than either alone. The bump is
        capped at one step so correlation never invents a critical.
        """
        base = self.max_severity
        if self.config_flag and len(self.sources) >= 2:
            return bump_severity(base, 1)
        return base

    config_flag: bool = False

    @property
    def anchors(self) -> Set[str]:
        if self._anchor_cache is None:
            self._anchor_cache = {
                entity
                for alert in self.alerts
                for entity in alert.entity_set()
                if entity.split(":", 1)[0] in ANCHOR_KINDS
            }
        return self._anchor_cache

    @property
    def weak_entities(self) -> Set[str]:
        if self._weak_cache is None:
            self._weak_cache = {
                entity
                for alert in self.alerts
                for entity in alert.entity_set()
                if entity.split(":", 1)[0] in WEAK_KINDS
            }
        return self._weak_cache

    def entity_summary(self) -> Dict[str, List[str]]:
        grouped: Dict[str, List[str]] = {}
        for alert in self.alerts:
            for kind, values in alert.entities.items():
                bucket = grouped.setdefault(kind, [])
                for value in values:
                    if value not in bucket:
                        bucket.append(value)
        return grouped

    def sort_key(self) -> Tuple[int, float, int]:
        return (-severity_rank(self.severity), self.first_ts, -len(self.alerts))


def link_reason(incident: Incident, alert: Alert, config: ClusterConfig) -> Optional[str]:
    """Return a merge reason when ``alert`` belongs to ``incident``, else None."""
    if abs(alert.ts - incident.last_ts) > config.window_seconds:
        # Windows are measured from the incident's newest alert, so a long
        # campaign still collapses but a new day's activity does not.
        return None

    shared_anchor = alert.entity_set() & incident.anchors
    shared_weak = alert.entity_set() & incident.weak_entities

    same_rule = alert.fingerprint in incident.fingerprints
    if same_rule and (shared_anchor or shared_weak):
        shared = sorted(shared_anchor or shared_weak)[0]
        return "repeat of '{}' on {}".format(alert.rule, shared)

    if len(shared_anchor) >= config.min_shared:
        ordered = sorted(shared_anchor)[:3]
        return "shares {} with incident".format(", ".join(ordered))

    return None


def build_incidents(alerts: Sequence[Alert], config: Optional[ClusterConfig] = None) -> List[Incident]:
    """Group a time-sorted alert list into incidents, worst first."""
    cfg = config or ClusterConfig()
    incidents: List[Incident] = []

    for alert in sorted(alerts, key=lambda a: (a.ts, a.index)):
        target: Optional[Incident] = None
        reason: Optional[str] = None

        # Prefer the incident that already holds this alert's strongest anchor
        # so a busy host does not absorb unrelated activity.
        best_overlap = -1
        for incident in incidents:
            candidate = link_reason(incident, alert, cfg)
            if candidate is None:
                continue
            overlap = len(alert.entity_set() & incident.anchors)
            if overlap > best_overlap:
                best_overlap = overlap
                target = incident
                reason = candidate

        if target is None:
            fresh = Incident(config_flag=cfg.bump_on_sources)
            fresh.add(alert, "first alert")
            incidents.append(fresh)
            continue

        target.add(alert, reason or "related")

    incidents.sort(key=lambda i: i.sort_key())
    return incidents
