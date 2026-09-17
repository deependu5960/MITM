"""Vendor lookup from OUI + randomized-MAC detection."""
from __future__ import annotations
from typing import Optional

from .oui_data import OUI_VENDORS

_cache: dict[str, str] = {}


def lookup(mac: Optional[str]) -> str:
    if not mac:
        return "Unknown"
    key = mac.upper().replace("-", ":")
    if key in _cache:
        return _cache[key]
    parts = key.split(":")
    if len(parts) < 3:
        _cache[key] = "Unknown"
        return "Unknown"
    prefix = ":".join(parts[:3])
    vendor = OUI_VENDORS.get(prefix, "Unknown")
    _cache[key] = vendor
    return vendor


def is_randomized(mac: Optional[str]) -> bool:
    """Locally-administered bit set = privacy MAC (phones by default)."""
    if not mac:
        return False
    try:
        first = int(mac.split(":")[0], 16)
        return bool(first & 0x02)
    except Exception:
        return False