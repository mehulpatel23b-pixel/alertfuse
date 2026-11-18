"""Timestamp parsing and alert loading from mixed exports."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from .entities import DEFAULT_HOST_SUFFIXES, extract_entities
from .flatten import flatten
from .models import Alert, normalize_severity

_EPOCH_MS = 1e11  # anything larger than this is milliseconds, not seconds
_WINDOW = re.compile(
    r"^(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})"
    r"[T ](?P<hour>\d{2}):(?P<minute>\d{2})(?::(?P<second>\d{2}))?"
)

TIME_KEYS = (
    "timestamp",
    "@timestamp",
    "time",
    "ts",
    "event.created",
    "event.ingested",
    "date",
    "datetime",
    "created_at",
    "created",
    "event_time",
)

RULE_KEYS = (
    "rule.name",
    "rule.description",
    "rule",
    "detection",
    "signature",
    "title",
    "name",
    "alert",
    "event.action",
    "event.category",
    "description",
    "message",
)

SEVERITY_KEYS = (
    "severity",
    "rule.severity",
    "event.severity",
    "priority",
    "level",
    "risk",
    "risk_score",
    "confidence",
)

SOURCE_KEYS = ("source_tool", "tool", "vendor", "product", "observer.name", "sensor")


def parse_timestamp(value: Any) -> Optional[float]:
    """Return epoch seconds (UTC) for a timestamp in any common shape.

    Handles epoch seconds, epoch milliseconds, ISO-8601 with or without a
    ``Z``, offsets, and a trailing ``Z`` on naive strings. Unparseable values
    return ``None`` so the caller can decide, never a silent "now".
    """
    if value is None or isinstance(value, bool):
        return None

    if isinstance(value, (int, float)):
        return _from_epoch(float(value))

    text = str(value).strip()
    if not text:
        return None

    if re.fullmatch(r"\d+(\.\d+)?", text):
        try:
            return _from_epoch(float(text))
        except ValueError:
            return None

    candidate = text.replace("Z", "+00:00").replace("z", "+00:00")
    normalized = candidate.replace(" ", "T", 1) if " " in candidate and "T" not in candidate else candidate
    for attempt in (candidate, normalized):
        try:
            parsed = datetime.fromisoformat(attempt)
        except ValueError:
            continue
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()

    window = _WINDOW.match(text)
    if window:
        parts = {k: int(v) for k, v in window.groupdict().items() if v is not None}
        try:
            parsed = datetime(
                parts["year"],
                parts["month"],
                parts["day"],
                parts["hour"],
                parts["minute"],
                parts.get("second", 0),
                tzinfo=timezone.utc,
            )
        except ValueError:
            return None
        return parsed.timestamp()

    return None


def _from_epoch(number: float) -> Optional[float]:
    if number <= 0:
        return None
    if number > _EPOCH_MS:
        number /= 1000.0
    return number


def _first(flat: Dict[str, Any], keys: Iterable[str]) -> Any:
    for key in keys:
        if key in flat and flat[key] not in (None, ""):
            return flat[key]
    return None


def _as_list(payload: Any) -> List[Dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in ("alerts", "events", "data", "items", "results"):
            nested = payload.get(key)
            if isinstance(nested, list):
                return [item for item in nested if isinstance(item, dict)]
            if isinstance(nested, dict):
                inner = nested.get("alerts") or nested.get("events")
                if isinstance(inner, list):
                    return [item for item in inner if isinstance(item, dict)]
        return [payload]
    return []


def load_json_records(text: str) -> List[Dict[str, Any]]:
    """Parse JSON in array form or newline-delimited (NDJSON) form."""
    stripped = text.strip()
    if not stripped:
        return []
    try:
        return _as_list(json.loads(stripped))
    except json.JSONDecodeError:
        pass

    records: List[Dict[str, Any]] = []
    for line in stripped.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            records.append(parsed)
    return records


def load_alerts(
    records: Iterable[Dict[str, Any]],
    suffixes: Iterable[str] = DEFAULT_HOST_SUFFIXES,
    default_source: str = "unknown",
) -> List[Alert]:
    """Normalise raw records into :class:`Alert` objects, keeping input order."""
    alerts: List[Alert] = []
    for position, record in enumerate(records):
        flat = flatten(record)

        stamp = parse_timestamp(_first(flat, TIME_KEYS))
        if stamp is None:
            # Skipping beats inventing a time: an alert with a fabricated
            # timestamp silently corrupts every window decision downstream.
            continue

        rule_raw = _first(flat, RULE_KEYS)
        rule = str(rule_raw).strip() if rule_raw else "unclassified"

        severity, _ = normalize_severity(_first(flat, SEVERITY_KEYS))
        source_raw = _first(flat, SOURCE_KEYS)
        source = str(source_raw).strip() if source_raw else default_source

        alerts.append(
            Alert(
                index=position,
                ts=stamp,
                rule=rule,
                severity=severity,
                source=source,
                entities=extract_entities(flat, suffixes),
                raw=record,
            )
        )
    alerts.sort(key=lambda a: (a.ts, a.index))
    return alerts
