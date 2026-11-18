"""Entity extraction and canonicalisation.

Correlation quality lives or dies here: if one tool says ``WS01.corp.local``
and another says ``ws01``, they must produce the same entity or the merge
never happens.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

# Default internal DNS suffixes folded off a hostname so short and FQDN
# spellings of the same machine collide.
DEFAULT_HOST_SUFFIXES: Sequence[str] = (
    "local",
    "localdomain",
    "lan",
    "internal",
    "corp",
    "home",
    "domain",
    "intranet",
)

# Field aliases, lowercase. Longest match wins, so "file.hash.sha256" beats
# "hash" when both could apply.
ALIASES: Dict[str, str] = {
    # host
    "host.name": "host",
    "host.hostname": "host",
    "hostname": "host",
    "host": "host",
    "computer": "host",
    "computer_name": "host",
    "computername": "host",
    "agent.name": "host",
    "device.hostname": "host",
    "machine": "host",
    "endpoint": "host",
    "workstation": "host",
    # user
    "user.name": "user",
    "user": "user",
    "username": "user",
    "user_name": "user",
    "account": "user",
    "account.name": "user",
    "subject.username": "user",
    "src_user": "user",
    "target_user": "user",
    "identity": "user",
    # ip
    "source.ip": "ip",
    "source.address": "ip",
    "src_ip": "ip",
    "srcip": "ip",
    "src.ip": "ip",
    "srcaddr": "ip",
    "client.ip": "ip",
    "destination.ip": "ip",
    "dest_ip": "ip",
    "dst_ip": "ip",
    "dstip": "ip",
    "dst.ip": "ip",
    "dstaddr": "ip",
    "remote_ip": "ip",
    "remoteip": "ip",
    "local_ip": "ip",
    "ip": "ip",
    # hash
    "file.hash.sha256": "hash",
    "file.hash.md5": "hash",
    "file.hash.sha1": "hash",
    "sha256": "hash",
    "sha1": "hash",
    "md5": "hash",
    "hashes": "hash",
    "hash": "hash",
    "proc.hash": "hash",
    # domain
    "url.domain": "domain",
    "dns.question.name": "domain",
    "domain": "domain",
    "fqdn": "domain",
    "host.domain": "domain",
    "tls.client.server_name": "domain",
    # process / file
    "process.name": "process",
    "process": "process",
    "image": "process",
    "exe": "process",
    "filename": "process",
    "parent.process.name": "parent_process",
    "file.path": "file",
    "file.name": "file",
    "filepath": "file",
}

# Values that carry no correlating signal. Merging on these would fuse the
# whole estate into one incident.
NOISE_VALUES: Set[str] = {
    "",
    "-",
    "--",
    "?",
    "*",
    "n/a",
    "na",
    "n.a.",
    "none",
    "null",
    "nil",
    "unknown",
    "unspecified",
    "localhost",
    "0.0.0.0",
    "::",
    "::1",
    "127.0.0.1",
    "system",
    "systemd",
    "root",
}

_SPLIT = re.compile(r"[;,|]")
_PORT = re.compile(r"^(?P<host>.+?):(?P<port>\d{1,5})$")


def _is_noise(value: str) -> bool:
    return value.strip().lower() in NOISE_VALUES


def normalize_ip(value: str) -> Optional[str]:
    """Canonicalise an IP, dropping any port and bracketed IPv6 form."""
    text = str(value).strip()
    if not text:
        return None
    if text.startswith("[") and "]" in text:
        text = text[1:text.index("]")]
    else:
        match = _PORT.match(text)
        if match and match.group("host").count(":") <= 1:
            text = match.group("host")
    text = text.split("%", 1)[0]
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    if address.is_unspecified or address.is_loopback:
        return None
    return str(address)


def normalize_host(value: str, suffixes: Iterable[str] = DEFAULT_HOST_SUFFIXES) -> Optional[str]:
    """Lowercase a hostname and fold known internal DNS suffixes."""
    text = str(value).strip().lower().rstrip(".")
    if not text:
        return None
    match = _PORT.match(text)
    if match:
        text = match.group("host")
    if _is_noise(text):
        return None
    folded = set(str(s).lower().lstrip(".") for s in suffixes)
    if "." in text:
        # Strip the longest matching trailing suffix so ws01.corp.local and
        # ws01 both land on ws01, while a real external FQDN stays intact.
        changed = True
        while changed and "." in text:
            changed = False
            for suffix in sorted(folded, key=len, reverse=True):
                tail = "." + suffix
                if text.endswith(tail) and len(text) > len(tail):
                    text = text[: -len(tail)]
                    changed = True
                    break
    return text


def _normalize_generic(value: str) -> Optional[str]:
    text = str(value).strip().lower()
    if _is_noise(text):
        return None
    return text


def _match_kind(path: str) -> Optional[str]:
    """Map a flattened field path to an entity kind, longest alias first."""
    lowered = path.lower()
    if lowered in ALIASES:
        return ALIASES[lowered]
    best: Optional[tuple] = None
    for alias, kind in ALIASES.items():
        if lowered.endswith("." + alias) or lowered == alias:
            if best is None or len(alias) > best[0]:
                best = (len(alias), kind)
    return best[1] if best else None


def extract_entities(
    flat: Dict[str, Any],
    suffixes: Iterable[str] = DEFAULT_HOST_SUFFIXES,
) -> Dict[str, List[str]]:
    """Pull correlating entities out of a flattened alert document."""
    found: Dict[str, List[str]] = {}

    def add(kind: str, value: str) -> None:
        bucket = found.setdefault(kind, [])
        if value not in bucket:
            bucket.append(value)

    for path, raw in flat.items():
        kind = _match_kind(path)
        if kind is None or raw is None or isinstance(raw, (bool, dict, list)):
            continue
        text = str(raw)
        pieces = [text] if kind in {"process", "parent_process", "file"} else _SPLIT.split(text)
        for piece in pieces:
            if kind == "ip":
                value = normalize_ip(piece)
            elif kind == "host":
                value = normalize_host(piece, suffixes)
            elif kind == "domain":
                value = _normalize_generic(piece)
                if value:
                    value = value.rstrip(".")
                    if not value or "." not in value and value in NOISE_VALUES:
                        value = None
            elif kind == "hash":
                value = _normalize_generic(piece)
                if value:
                    value = value.split("=", 1)[-1].strip().lower()
                    if len(value) < 8:
                        value = None
            else:
                value = _normalize_generic(piece)
            if value:
                add(kind, value)

    return found
