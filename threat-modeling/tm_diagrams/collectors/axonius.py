"""Axonius collector (uses the official axonius-api-client SDK)."""
from __future__ import annotations

import logging

log = logging.getLogger(__name__)

DEVICE_FIELDS = [
    "adapters",
    "specific_data.data.hostname",
    "specific_data.data.name",
    "specific_data.data.network_interfaces.ips",
    "specific_data.data.network_interfaces.mac",
    "specific_data.data.os.type",
    "specific_data.data.os.distribution",
    "specific_data.data.device_model",
    "specific_data.data.last_seen",
    "labels",
]


def _first(v):
    if isinstance(v, list):
        return v[0] if v else None
    return v


def _flat(v) -> list:
    out = []
    for item in v if isinstance(v, list) else [v]:
        if isinstance(item, list):
            out.extend(_flat(item))
        elif item not in (None, ""):
            out.append(item)
    return out


def normalize(row: dict) -> dict:
    """Turn an Axonius device row into a small, stable dict."""
    g = row.get
    adapters = [a.replace("_adapter", "") for a in _flat(g("adapters", []))]
    return {
        "id": g("internal_axon_id"),
        "hostname": _first(g("specific_data.data.hostname")) or _first(g("specific_data.data.name")),
        "ips": sorted(set(_flat(g("specific_data.data.network_interfaces.ips", [])))),
        "macs": sorted({m.upper() for m in _flat(g("specific_data.data.network_interfaces.mac", []))}),
        "os": _first(g("specific_data.data.os.type")) or "",
        "os_detail": _first(g("specific_data.data.os.distribution")) or "",
        "model": _first(g("specific_data.data.device_model")) or "",
        "last_seen": _first(g("specific_data.data.last_seen")),
        "adapters": sorted(set(adapters)),
        "labels": _flat(g("labels", [])),
    }


def collect(cfg) -> dict:
    try:
        from axonius_api_client import Connect
    except ImportError as exc:
        raise RuntimeError("pip install axonius-api-client") from exc

    client = Connect(url=cfg.axonius_url, key=cfg.axonius_key, secret=cfg.axonius_secret,
                     certverify=cfg.axonius_verify_ssl, certwarn=False)
    client.start()
    if cfg.axonius_saved_query:
        log.info("Axonius: fetching devices from saved query %r", cfg.axonius_saved_query)
        rows = client.devices.get_by_saved_query(name=cfg.axonius_saved_query,
                                                 fields=DEVICE_FIELDS)
    else:
        log.info("Axonius: fetching all devices")
        rows = client.devices.get(fields=DEVICE_FIELDS)
    devices = [normalize(r) for r in rows]
    log.info("Axonius: %d devices", len(devices))
    return {"devices": devices}
