"""Flatten nested JSON into dotted paths.

An ECS document, a Wazuh alert and a hand-rolled webhook payload all describe
the same things at different depths. Flattening first means one entity
extractor can read all of them.
"""

from __future__ import annotations

from typing import Any, Dict


def flatten(obj: Any, prefix: str = "") -> Dict[str, Any]:
    """Flatten dicts and lists into ``{"a.b.0.c": value}``."""
    out: Dict[str, Any] = {}
    if isinstance(obj, dict):
        for key, value in obj.items():
            path = "{}.{}".format(prefix, key) if prefix else str(key)
            if isinstance(value, (dict, list)):
                out.update(flatten(value, path))
            else:
                out[path] = value
    elif isinstance(obj, list):
        for position, item in enumerate(obj):
            path = "{}.{}".format(prefix, position) if prefix else str(position)
            if isinstance(item, (dict, list)):
                out.update(flatten(item, path))
            else:
                out[path] = item
    elif prefix:
        out[prefix] = obj
    return out
