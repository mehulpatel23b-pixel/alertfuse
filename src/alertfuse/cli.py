"""Command line interface for alertfuse."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import timedelta, timezone
from typing import List, Optional, Sequence, Tuple

from . import __version__
from .cluster import ClusterConfig, build_incidents
from .ingest import load_alerts, load_json_records
from .models import Alert, severity_rank
from .report import render_text, to_json
from .suppress import RuleError, load_allowlist_text, apply_allowlist

EPILOG = """\
examples:
  alertfuse alerts.json
  alertfuse edr.json waf.ndjson --window 30m --fail-on critical
  alertfuse alerts.json --allowlist allow.json --json report.json
  cat alerts.ndjson | alertfuse -
"""

README = """alertfuse - fuse an alert stream into an incident queue.

Reads alerts exported from any number of tools (JSON array or NDJSON), groups
near-duplicates that share a user, host, IP or file hash inside a time window,
and prints one triage entry per incident with the reason each alert merged.

Exit codes: 0 clean, 1 review needed, 2 usage or input error.
"""


def parse_window(text: str) -> float:
    """Parse '90s', '15m', '2h', '1d' or a bare number of seconds."""
    raw = str(text).strip().lower()
    if not raw:
        raise argparse.ArgumentTypeError("empty window")
    unit = raw[-1]
    scale = {"s": 1, "m": 60, "h": 3600, "d": 86400}.get(unit)
    if scale is None:
        number = raw
        scale = 1
    else:
        number = raw[:-1]
    try:
        value = float(number) * scale
    except ValueError:
        raise argparse.ArgumentTypeError("invalid window: {!r}".format(text))
    if value <= 0:
        raise argparse.ArgumentTypeError("window must be positive")
    return value


def _read(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="alertfuse",
        description="Fuse duplicate alerts from many tools into one incident queue.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("inputs", nargs="*", help="alert files (JSON or NDJSON), or - for stdin")
    parser.add_argument(
        "-w", "--window", type=parse_window, default=900.0,
        help="correlation window, e.g. 15m (default 900s)",
    )
    parser.add_argument(
        "--min-shared", type=int, default=1,
        help="shared strong entities needed to merge different detections (default 1)",
    )
    parser.add_argument("--allowlist", help="JSON suppression rules")
    parser.add_argument("--json", dest="json_out", help="write structured report to this file")
    parser.add_argument(
        "--tz", choices=("utc", "ist"), default="utc", help="timezone for display (default utc)"
    )
    parser.add_argument(
        "--fail-on", choices=("none", "medium", "high", "critical"), default="none",
        help="exit 1 when an incident reaches this severity",
    )
    parser.add_argument("--limit", type=int, default=0, help="show only the top N incidents")
    parser.add_argument("--quiet", action="store_true", help="suppress the text queue")
    parser.add_argument("--version", action="version", version="alertfuse " + __version__)
    return parser


def _warn(message: str) -> None:
    print("alertfuse: " + message, file=sys.stderr)


def gather_records(paths: Sequence[str]) -> List[dict]:
    if not paths:
        _warn("no input given, reading stdin")
        paths = ["-"]

    records: List[dict] = []
    for path in paths:
        try:
            text = _read(path)
        except OSError as exc:
            raise SystemExit("alertfuse: cannot read {}: {}".format(path, exc))
        parsed = load_json_records(text)
        if not parsed:
            _warn("no alerts parsed from {}".format(path))
        records.extend(parsed)
    return records


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.limit < 0:
        parser.error("--limit cannot be negative")

    records = gather_records(args.inputs)
    if not records:
        _warn("nothing to do")
        return 0

    alerts: List[Alert] = load_alerts(records)
    skipped = len(records) - len(alerts)
    if skipped:
        _warn("skipped {} alert(s) with no usable timestamp".format(skipped))
    if not alerts:
        _warn("no alerts had a parseable timestamp")
        return 2

    suppressed: List[Tuple[Alert, str]] = []
    if args.allowlist:
        try:
            rules = load_allowlist_text(_read(args.allowlist))
        except (OSError, RuleError) as exc:
            _warn("allowlist problem: {}".format(exc))
            return 2
        alerts, suppressed = apply_allowlist(alerts, rules)

    config = ClusterConfig(
        window_seconds=args.window,
        min_shared=args.min_shared,
    )
    incidents = build_incidents(alerts, config)
    shown = incidents[: args.limit] if args.limit else incidents

    tz = timezone.utc if args.tz == "utc" else _ist()

    if not args.quiet:
        sys.stdout.write(render_text(shown, len(records), suppressed, config, tz))

    if args.json_out:
        payload = to_json(shown, len(records), suppressed, config, tz)
        try:
            with open(args.json_out, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2)
                handle.write("\n")
        except OSError as exc:
            _warn("cannot write {}: {}".format(args.json_out, exc))
            return 2
        if not args.quiet:
            print("json report written to {}".format(args.json_out))

    if args.fail_on != "none":
        threshold = severity_rank(args.fail_on)
        if any(severity_rank(i.severity) >= threshold for i in incidents):
            return 1
    return 0


def _ist():
    return timezone(timedelta(hours=5, minutes=30))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
