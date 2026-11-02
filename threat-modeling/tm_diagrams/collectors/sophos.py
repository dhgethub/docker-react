"""Sophos Central collector (raw REST; supports tenant, partner and organization credentials)."""
from __future__ import annotations

import logging
import time

import requests

log = logging.getLogger(__name__)

TOKEN_URL = "https://id.sophos.com/api/v2/oauth2/token"
WHOAMI_URL = "https://api.central.sophos.com/whoami/v1"
GLOBAL_URL = "https://api.central.sophos.com"


class SophosClient:
    def __init__(self, client_id: str, client_secret: str, timeout: int = 60):
        self.s = requests.Session()
        self.timeout = timeout
        r = self.s.post(TOKEN_URL, timeout=timeout, data={
            "grant_type": "client_credentials", "client_id": client_id,
            "client_secret": client_secret, "scope": "token"})
        r.raise_for_status()
        self.s.headers["Authorization"] = f"Bearer {r.json()['access_token']}"
        who = self._get(WHOAMI_URL)
        self.id_type = who["idType"]          # tenant | partner | organization
        self.id = who["id"]
        self.data_region = (who.get("apiHosts") or {}).get("dataRegion")

    def _get(self, url, headers=None, params=None):
        for attempt in range(5):
            r = self.s.get(url, headers=headers, params=params, timeout=self.timeout)
            if r.status_code == 429:
                time.sleep(int(r.headers.get("Retry-After", 2 ** attempt)))
                continue
            r.raise_for_status()
            return r.json()
        r.raise_for_status()

    def paged(self, url, headers, params=None, key_based=True):
        """Iterate items for Sophos 'pageFromKey' or 'page' style pagination."""
        params = dict(params or {})
        params.setdefault("pageSize", 500 if key_based else 100)
        page = 1
        while True:
            data = self._get(url, headers, params)
            yield from data.get("items", [])
            pages = data.get("pages") or {}
            if key_based and pages.get("nextKey"):
                params["pageFromKey"] = pages["nextKey"]
            elif not key_based and page < int(pages.get("total") or 1):
                page += 1
                params["page"] = page
            else:
                return

    def tenants(self) -> list[dict]:
        if self.id_type == "tenant":
            return [{"id": self.id, "name": "tenant", "apiHost": self.data_region}]
        hdr = {"X-Partner-ID" if self.id_type == "partner" else "X-Organization-ID": self.id}
        path = "partner" if self.id_type == "partner" else "organization"
        return list(self.paged(f"{GLOBAL_URL}/{path}/v1/tenants", hdr,
                               {"pageTotal": "true"}, key_based=False))


def _endpoint(e: dict, tenant: str) -> dict:
    health = e.get("health") or {}
    return {
        "id": e.get("id"),
        "tenant": tenant,
        "hostname": e.get("hostname"),
        "type": e.get("type"),   # computer | server | securityVm
        "os": (e.get("os") or {}).get("platform") or "",
        "os_name": (e.get("os") or {}).get("name") or "",
        "ips": e.get("ipv4Addresses") or [],
        "macs": [m.upper().replace("-", ":") for m in (e.get("macAddresses") or [])],
        "health": health.get("overall") or "unknown",
        "threats": (health.get("threats") or {}).get("status") or "unknown",
        "tamper_protection": e.get("tamperProtectionEnabled"),
        "last_seen": e.get("lastSeenAt"),
        "products": [p.get("code") for p in (e.get("assignedProducts") or [])],
        "isolated": ((e.get("isolation") or {}).get("status") == "isolated"),
    }


def collect(cfg) -> dict:
    sc = SophosClient(cfg.sophos_client_id, cfg.sophos_client_secret)
    log.info("Sophos: authenticated as %s", sc.id_type)
    out = {"endpoints": [], "firewalls": [], "alerts": []}
    for t in sc.tenants():
        host = t.get("apiHost") or sc.data_region
        name = t.get("name") or t["id"]
        hdr = {"X-Tenant-ID": t["id"]}
        try:
            out["endpoints"] += [_endpoint(e, name) for e in sc.paged(
                f"{host}/endpoint/v1/endpoints", hdr, {"view": "full"})]
        except requests.HTTPError as exc:
            log.warning("Sophos %s endpoints: %s", name, exc)
        try:
            for fw in sc.paged(f"{host}/firewall/v1/firewalls", hdr, key_based=False):
                out["firewalls"].append({
                    "id": fw.get("id"), "tenant": name,
                    "name": fw.get("name") or fw.get("hostname"),
                    "serial": fw.get("serialNumber"), "model": fw.get("model"),
                    "firmware": fw.get("firmwareVersion"),
                    "ips": [i for i in (fw.get("externalIpv4Addresses") or [])],
                    "connected": (fw.get("status") or {}).get("connected"),
                })
        except requests.HTTPError as exc:
            log.info("Sophos %s firewalls unavailable: %s", name, exc)
        try:
            for a in sc.paged(f"{host}/common/v1/alerts", hdr, key_based=True):
                out["alerts"].append({
                    "id": a.get("id"), "tenant": name, "severity": a.get("severity"),
                    "category": a.get("category"), "description": a.get("description"),
                    "hostname": ((a.get("managedAgent") or {}).get("name")),
                    "raised_at": a.get("raisedAt"),
                })
        except requests.HTTPError as exc:
            log.info("Sophos %s alerts unavailable: %s", name, exc)
    log.info("Sophos: %d endpoints, %d firewalls, %d alerts",
             len(out["endpoints"]), len(out["firewalls"]), len(out["alerts"]))
    return out
