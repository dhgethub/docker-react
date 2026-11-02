"""Cisco Meraki collector (uses the official meraki SDK)."""
from __future__ import annotations

import logging

log = logging.getLogger(__name__)


def _safe(fn, *args, default=None, **kwargs):
    try:
        return fn(*args, **kwargs)
    except Exception as exc:  # meraki.APIError for unsupported features (e.g. no MX)
        log.debug("Meraki %s%s skipped: %s", getattr(fn, "__name__", fn), args, exc)
        return default


def collect(cfg) -> dict:
    try:
        import meraki
    except ImportError as exc:
        raise RuntimeError("pip install meraki") from exc

    d = meraki.DashboardAPI(cfg.meraki_api_key, suppress_logging=True, print_console=False,
                            output_log=False, maximum_retries=5, wait_on_rate_limit=True)
    orgs = d.organizations.getOrganizations()
    if cfg.meraki_org_ids:
        orgs = [o for o in orgs if str(o["id"]) in cfg.meraki_org_ids]

    out = {"organizations": []}
    timespan = int(cfg.meraki_client_timespan_hours) * 3600
    for org in orgs:
        oid = org["id"]
        log.info("Meraki: org %s (%s)", org["name"], oid)
        o = {
            "id": oid, "name": org["name"],
            "devices": _safe(d.organizations.getOrganizationDevices, oid, total_pages="all", default=[]),
            "device_statuses": _safe(d.organizations.getOrganizationDevicesStatuses, oid,
                                     total_pages="all", default=[]),
            "vpn_statuses": _safe(d.appliance.getOrganizationApplianceVpnStatuses, oid,
                                  total_pages="all", default=[]),
            "networks": [],
        }
        for net in _safe(d.organizations.getOrganizationNetworks, oid, total_pages="all", default=[]):
            nid = net["id"]
            n = {"id": nid, "name": net["name"], "product_types": net.get("productTypes", [])}
            if "appliance" in n["product_types"]:
                a = d.appliance
                n["vlans"] = _safe(a.getNetworkApplianceVlans, nid, default=None)
                if n["vlans"] is None:   # VLANs disabled -> single LAN
                    single = _safe(a.getNetworkApplianceSingleLan, nid, default=None)
                    n["vlans"] = [{"id": 1, "name": "LAN", **single}] if single else []
                n["l3_rules"] = (_safe(a.getNetworkApplianceFirewallL3FirewallRules, nid,
                                       default={}) or {}).get("rules", [])
                n["inbound_rules"] = (_safe(a.getNetworkApplianceFirewallInboundFirewallRules, nid,
                                            default={}) or {}).get("rules", [])
                n["port_forwards"] = (_safe(a.getNetworkApplianceFirewallPortForwardingRules, nid,
                                            default={}) or {}).get("rules", [])
                n["one_to_one_nat"] = (_safe(a.getNetworkApplianceFirewallOneToOneNatRules, nid,
                                             default={}) or {}).get("rules", [])
                n["site_to_site_vpn"] = _safe(a.getNetworkApplianceVpnSiteToSiteVpn, nid, default={})
            n["clients"] = _safe(d.networks.getNetworkClients, nid, timespan=timespan,
                                 perPage=1000, total_pages="all", default=[])
            o["networks"].append(n)
        out["organizations"].append(o)
    return out
