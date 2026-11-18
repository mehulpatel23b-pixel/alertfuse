"""Rendering: a human triage queue and a machine-readable summary."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .cluster import ClusterConfig, Incident
from .models import Alert, severity_rank

IST = timezone(timedelta(hours=5, minutes=30))


def _plural(count: int, noun: str) -> str:
    return "{} {}{}".format(count, noun, "" if count == 1 else "s")


def _stamp(epoch: float, tz: timezone = timezone.utc) -> str:
    return datetime.fromtimestamp(epoch, tz).strftime("%Y-%m-%d %H:%M:%S")


def build_summary(
    incidents: Sequence[Incident],
    total_alerts: int,
    suppressed: Sequence[Tuple[Alert, str]] = (),
    config: Optional[ClusterConfig] = None,
) -> Dict[str, Any]:
    """Compute the reduction numbers that justify the run."""
    grouped = sum(len(i.alerts) for i in incidents)
    return {
        "alerts_in": total_alerts,
        "alerts_suppressed": len(suppressed),
        "alerts_considered": grouped,
        "incidents": len(incidents),
        "reduction_ratio": round(grouped / len(incidents), 2) if incidents else 0.0,
        "noise_removed_pct": (
            round(100.0 * (grouped - len(incidents)) / grouped, 1) if grouped else 0.0
        ),
        "cross_tool_incidents": sum(1 for i in incidents if len(i.sources) > 1),
        "by_severity": _count_by_severity(incidents),
        "window_seconds": config.window_seconds if config else None,
        "suppression_rules_hit": sorted({name for _, name in suppressed}),
    }


def _count_by_severity(incidents: Sequence[Incident]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for incident in incidents:
        counts[incident.severity] = counts.get(incident.severity, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: -severity_rank(kv[0])))


def to_json(
    incidents: Sequence[Incident],
    total_alerts: int,
    suppressed: Sequence[Tuple[Alert, str]] = (),
    config: Optional[ClusterConfig] = None,
    tz: timezone = timezone.utc,
) -> Dict[str, Any]:
    """Structured output for pipelines and dashboards."""
    return {
        "summary": build_summary(incidents, total_alerts, suppressed, config),
        "incidents": [
            {
                "rank": position,
                "severity": incident.severity,
                "max_alert_severity": incident.max_severity,
                "alert_count": len(incident.alerts),
                "sources": incident.sources,
                "rules": incident.rules,
                "first_seen": _stamp(incident.first_ts, tz),
                "last_seen": _stamp(incident.last_ts, tz),
                "duration_seconds": round(incident.duration, 1),
                "entities": incident.entity_summary(),
                "merge_reasons": incident.reasons,
                "alerts": [
                    {
                        "rule": alert.rule,
                        "severity": alert.severity,
                        "source": alert.source,
                        "time": _stamp(alert.ts, tz),
                    }
                    for alert in incident.alerts
                ],
            }
            for position, incident in enumerate(incidents, start=1)
        ],
        "suppressed": [
            {"rule": alert.rule, "source": alert.source, "suppression": name}
            for alert, name in suppressed
        ],
    }


def render_text(
    incidents: Sequence[Incident],
    total_alerts: int,
    suppressed: Sequence[Tuple[Alert, str]] = (),
    config: Optional[ClusterConfig] = None,
    tz: timezone = timezone.utc,
    width: int = 96,
) -> str:
    """A terminal triage queue, worst incident first."""
    summary = build_summary(incidents, total_alerts, suppressed, config)
    lines: List[str] = []

    lines.append("alertfuse  {} -> {}".format(
        _plural(summary["alerts_in"], "alert"), _plural(summary["incidents"], "incident")))
    lines.append(
        "noise removed {:.1f}%   cross-tool incidents {}   suppressed {}".format(
            summary["noise_removed_pct"],
            summary["cross_tool_incidents"],
            summary["alerts_suppressed"],
        )
    )
    if summary["by_severity"]:
        lines.append(
            "by severity: "
            + "  ".join("{}={}".format(k, v) for k, v in summary["by_severity"].items())
        )
    lines.append("")

    if not incidents:
        lines.append("Nothing to triage.")
        if suppressed:
            lines.append("")
            lines.append("suppressed (not triaged):")
            for alert, name in suppressed:
                lines.append("    {:<26} {}  [{}]".format(alert.rule[:26], alert.source, name))
        return "\n".join(lines)

    for position, incident in enumerate(incidents, start=1):
        header = "#{} [{}] {}  {} -> {}".format(
            position,
            incident.severity.upper(),
            _plural(len(incident.alerts), "alert"),
            _stamp(incident.first_ts, tz),
            _stamp(incident.last_ts, tz),
        )
        lines.append(header)
        lines.append("-" * min(width, 96))
        lines.append("  tools  : {}".format(", ".join(incident.sources)))

        for kind, values in sorted(incident.entity_summary().items()):
            joined = ", ".join(values[:6])
            more = "" if len(values) <= 6 else " (+{} more)".format(len(values) - 6)
            lines.append("  {:<7}: {}{}".format(kind, joined, more))

        lines.append("  detections:")
        for alert in incident.alerts:
            lines.append(
                "    {}  {:<9} {:<14} {}".format(
                    _stamp(alert.ts, tz),
                    alert.severity,
                    alert.source[:14],
                    alert.rule,
                )
            )
        if incident.reasons:
            lines.append("  why merged: {}".format("; ".join(incident.reasons[:4])))
        lines.append("")

    if suppressed:
        lines.append("suppressed (not triaged):")
        for alert, name in suppressed:
            lines.append("    {:<26} {}  [{}]".format(alert.rule[:26], alert.source, name))
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"
