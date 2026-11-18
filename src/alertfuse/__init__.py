"""alertfuse - offline alert-stream fusion for SOC triage.

Collapses near-duplicate alerts from multiple tools into one incident each,
with an explainable reason for every merge, so an analyst reviews events
instead of alert rows.

Zero runtime dependencies. No network code. No credentials.
"""

from .models import Alert, SEVERITY_LABELS, SEVERITY_ORDER, normalize_severity
from .entities import extract_entities, normalize_host, normalize_ip
from .cluster import ClusterConfig, Incident, build_incidents, link_reason
from .suppress import SuppressionRule, load_allowlist, apply_allowlist
from .ingest import load_alerts, load_json_records, parse_timestamp
from .report import build_summary, render_text, to_json

__version__ = "0.1.0"

__all__ = [
    "Alert",
    "SEVERITY_LABELS",
    "SEVERITY_ORDER",
    "normalize_severity",
    "extract_entities",
    "normalize_host",
    "normalize_ip",
    "ClusterConfig",
    "Incident",
    "build_incidents",
    "link_reason",
    "SuppressionRule",
    "load_allowlist",
    "apply_allowlist",
    "load_alerts",
    "load_json_records",
    "parse_timestamp",
    "build_summary",
    "render_text",
    "to_json",
    "__version__",
]
