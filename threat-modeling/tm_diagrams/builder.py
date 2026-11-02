"""Correlate raw Axonius / Sophos / Meraki data into a ThreatModel."""
from __future__ import annotations

import ipaddress
import re
from collections import defaultdict

from .model import Page, ThreatModel, Zone, Node

INTERNET_ZONE, INTERNET_NODE = "z_internet", "n_internet"
CLOUD_ZONE, MERAKI_CLOUD, SOPHOS_CLOUD = "z_cloud", "n_meraki_cloud", "n_sophos_central"
UNMAPPED_ZONE = "z_unmapped"
SOPHOS_FW_ZONE = "z_sophos_fw"


def _slug(s) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", str(s)).strip("_").lower()[:60] or "x"


def _short(host) -> str:
    return (host or "").split(".")[0].strip().lower()


def _net(cidr):
    try:
        return ipaddress.ip_network(str(cidr).strip(), strict=False)
    except ValueError:
        return None


def _ip(v):
    try:
        return ipaddress.ip_address(str(v).strip())
    except ValueError:
        return None


def categorize(a: dict) -> str:
    stype = (a.get("sophos") or {}).get("type") or ""
    os_ = f"{a.get('os', '')} {a.get('os_detail', '')}".lower()
    if stype == "server" or "server" in os_ or "linux" in os_ or "esx" in os_:
        return "Servers"
    if any(k in os_ for k in ("ios", "android", "ipados")):
        return "Mobile"
    if any(k in os_ for k in ("windows", "mac", "os x", "chrome")) or stype == "computer":
        return "Workstations"
    if any(k in os_ for k in ("cisco", "meraki", "fortinet", "juniper", "aruba")):
        return "Network devices"
    if any(k in os_ for k in ("printer",)) or "print" in (a.get("model") or "").lower():
        return "Printers"
    return "IoT / Other"


class AssetIndex:
    """Merge assets from all three sources by MAC, hostname and IP."""

    def __init__(self):
        self.assets: list[dict] = []
        self.by_mac, self.by_host, self.by_ip = {}, {}, {}

    def _find(self, macs, host, ips):
        for m in macs:
            if m in self.by_mac:
                return self.by_mac[m]
        if host and host in self.by_host:
            return self.by_host[host]
        for i in ips:
            if i in self.by_ip:
                return self.by_ip[i]
        return None

    def upsert(self, source: str, hostname, ips, macs, **attrs) -> dict:
        macs = [m.upper() for m in macs or [] if m]
        ips = [str(i) for i in ips or [] if _ip(i)]
        host = _short(hostname)
        a = self._find(macs, host, ips)
        if a is None:
            a = {"hostname": hostname or (ips[0] if ips else macs[0] if macs else "unknown"),
                 "ips": [], "macs": [], "sources": set(), "os": "", "os_detail": "", "model": ""}
            self.assets.append(a)
        a["sources"].add(source)
        for k, v in attrs.items():
            if v and not a.get(k):
                a[k] = v
        for m in macs:
            if m not in a["macs"]:
                a["macs"].append(m)
            self.by_mac[m] = a
        for i in ips:
            if i not in a["ips"]:
                a["ips"].append(i)
            self.by_ip.setdefault(i, a)
        if host:
            self.by_host.setdefault(host, a)
        return a


def build(raw: dict, cfg) -> ThreatModel:
    tm = ThreatModel()
    ax = raw.get("axonius") or {}
    so = raw.get("sophos") or {}
    mk = raw.get("meraki") or {}

    # ---- External / vendor-cloud zones -------------------------------------------------
    tm.add_zone(Zone(INTERNET_ZONE, "Internet (untrusted)", "internet", "untrusted"))
    tm.add_node(Node(INTERNET_NODE, "Internet users / attackers", "external", INTERNET_ZONE))
    if mk or so:
        tm.add_zone(Zone(CLOUD_ZONE, "Vendor cloud (management plane)", "cloud", "semi"))
    if mk:
        tm.add_node(Node(MERAKI_CLOUD, "Meraki Dashboard", "external", CLOUD_ZONE))
    if so:
        tm.add_node(Node(SOPHOS_CLOUD, "Sophos Central", "external", CLOUD_ZONE))

    # ---- Assets ------------------------------------------------------------------------
    idx = AssetIndex()
    for d in ax.get("devices", []):
        a = idx.upsert("axonius", d.get("hostname"), d.get("ips"), d.get("macs"),
                       os=d.get("os"), os_detail=d.get("os_detail"), model=d.get("model"))
        a.setdefault("adapters", set()).update(d.get("adapters") or [])
    for e in so.get("endpoints", []):
        a = idx.upsert("sophos", e.get("hostname"), e.get("ips"), e.get("macs"),
                       os=e.get("os"), os_detail=e.get("os_name"))
        a["sophos"] = e

    # ---- Meraki sites / VLANs ----------------------------------------------------------
    vlan_nets: list[tuple] = []                 # (ip_network, zone_id, site_zone_id)
    mx_by_network: dict[str, str] = {}
    site_of_network: dict[str, str] = {}
    vlan_zone_by_net_vlan: dict[tuple, str] = {}
    for org in mk.get("organizations", []):
        statuses = {s.get("serial"): s.get("status") for s in org.get("device_statuses", [])}
        devices_by_net = defaultdict(list)
        for dev in org.get("devices", []):
            dev["status"] = statuses.get(dev.get("serial"), dev.get("status"))
            devices_by_net[dev.get("networkId")].append(dev)
        for net in org.get("networks", []):
            nid = net["id"]
            sz = tm.add_zone(Zone(f"z_site_{_slug(nid)}", f"Site: {net['name']}", "site", "trusted",
                                  props={"org": org["name"], "network_id": nid}))
            site_of_network[nid] = sz.id
            devs = devices_by_net.get(nid, [])
            mxs = [d for d in devs if (d.get("model") or "").upper().startswith(("MX", "Z"))]
            others = [d for d in devs if d not in mxs]
            for d in mxs:
                n = tm.add_node(Node(f"n_mx_{_slug(d['serial'])}", f"{d.get('name') or d['model']}\n({d['model']})",
                                     "process", sz.id, props={"role": "firewall", "serial": d["serial"],
                                     "model": d["model"], "firmware": d.get("firmware"),
                                     "status": d.get("status"), "wan_ip": d.get("wan1Ip") or d.get("publicIp")}))
                mx_by_network.setdefault(nid, n.id)
            if others:
                kinds = defaultdict(int)
                for d in others:
                    kinds[(d.get("model") or "?")[:2]] += 1
                label = ", ".join(f"{k} x{v}" for k, v in sorted(kinds.items()))
                tm.add_node(Node(f"n_infra_{_slug(nid)}", f"Meraki switches / APs\n{label}", "device", sz.id,
                                 props={"devices": [d.get("serial") for d in others],
                                        "offline": [d.get("serial") for d in others if d.get("status") == "offline"]}))
            net["_site_zone"] = sz.id
            for v in net.get("vlans") or []:
                subnet = _net(v.get("subnet"))
                vz = tm.add_zone(Zone(f"z_vlan_{_slug(nid)}_{_slug(v.get('id'))}",
                                      f"VLAN {v.get('id')} {v.get('name', '')}\n{v.get('subnet', '')}",
                                      "vlan", "trusted", parent=sz.id,
                                      props={"vlan": v.get("id"), "subnet": v.get("subnet"),
                                             "appliance_ip": v.get("applianceIp")}))
                if subnet:
                    vlan_nets.append((subnet, vz.id, sz.id))
                vlan_zone_by_net_vlan[(nid, str(v.get("id")))] = vz.id
            for c in net.get("clients") or []:
                a = idx.upsert("meraki", c.get("description") or c.get("dhcpHostname"),
                               [c.get("ip")], [c.get("mac")], os=c.get("os"),
                               model=c.get("manufacturer"))
                a.setdefault("meraki_zone", vlan_zone_by_net_vlan.get((nid, str(c.get("vlan")))))

    def zone_for_ip(ip):
        ipa = _ip(ip)
        if not ipa:
            return None
        best = None
        for net, zid, _ in vlan_nets:
            if ipa.version == net.version and ipa in net and (best is None or net.prefixlen > best[0].prefixlen):
                best = (net, zid)
        return best[1] if best else None

    # ---- Sophos firewalls --------------------------------------------------------------
    for fw in so.get("firewalls", []):
        zid = next((z for z in map(zone_for_ip, fw.get("ips", [])) if z), None)
        if not zid:
            tm.add_zone(Zone(SOPHOS_FW_ZONE, "Sophos Firewall estate", "site", "trusted"))
            zid = SOPHOS_FW_ZONE
        n = tm.add_node(Node(f"n_sfw_{_slug(fw.get('serial') or fw.get('id'))}",
                             f"{fw.get('name')}\n(Sophos {fw.get('model') or 'Firewall'})",
                             "process", zid, props={"role": "firewall", **fw}))
        tm.add_flow(n.id, SOPHOS_CLOUD, "Central mgmt\nHTTPS 443", kind="mgmt")
        tm.add_flow(n.id, INTERNET_NODE, "WAN egress", kind="data")

    # ---- Place assets in zones ---------------------------------------------------------
    for a in idx.assets:
        a["category"] = categorize(a)
        a["sophos_managed"] = "sophos" in a["sources"] or any(
            "sophos" in x for x in a.get("adapters", ()))
        a["zone"] = a.get("meraki_zone") or next((z for z in map(zone_for_ip, a["ips"]) if z), None)
        if not a["zone"]:
            tm.add_zone(Zone(UNMAPPED_ZONE, "Remote / unmapped networks", "other", "semi"))
            a["zone"] = UNMAPPED_ZONE

    asset_node_by_ip: dict[str, str] = {}
    by_zone = defaultdict(list)
    for a in idx.assets:
        by_zone[a["zone"]].append(a)
    for zid, assets in by_zone.items():
        if len(assets) <= cfg.max_nodes_per_zone:
            for a in assets:
                nid = f"n_asset_{_slug(a['hostname'])}_{_slug(a['ips'][0] if a['ips'] else a['macs'][:1])}"
                n = tm.add_node(Node(nid, f"{a['hostname']}\n{', '.join(a['ips'][:2])}",
                                     "asset", zid, props=_asset_props(a)))
                a["node"] = n.id
                for ip in a["ips"]:
                    asset_node_by_ip[ip] = n.id
        else:
            groups = defaultdict(list)
            for a in assets:
                groups[a["category"]].append(a)
            for cat, members in sorted(groups.items()):
                unmanaged = sum(1 for m in members if not m["sophos_managed"])
                n = tm.add_node(Node(f"n_grp_{_slug(zid)}_{_slug(cat)}", f"{cat} ({len(members)})",
                                     "asset_group", zid, props={
                                         "category": cat, "count": len(members),
                                         "sophos_unmanaged": unmanaged,
                                         "members": [m["hostname"] for m in members][:500]}))
                for m in members:
                    m["node"] = n.id
                    for ip in m["ips"]:
                        asset_node_by_ip[ip] = n.id

    # ---- Flows -------------------------------------------------------------------------
    if SOPHOS_CLOUD in tm.nodes:
        for zid in sorted({a["zone"] for a in idx.assets if a["sophos_managed"]}):
            tm.add_flow(zid, SOPHOS_CLOUD, "Sophos agent telemetry / policy\nHTTPS 443", kind="mgmt")

    def resolve(spec: str, nid: str, src_zone_default: str):
        """Map a Meraki rule CIDR/'Any'/VLAN(x).* to an element id."""
        spec = (spec or "").strip()
        if spec.lower() == "any":
            return src_zone_default
        m = re.match(r"VLAN\((\d+)\)", spec, re.I)
        if m:
            return vlan_zone_by_net_vlan.get((nid, m.group(1)))
        net = _net(spec)
        if net is None:
            return None
        if net.num_addresses == 1 and str(net.network_address) in asset_node_by_ip:
            return asset_node_by_ip[str(net.network_address)]
        for vnet, zid, _ in vlan_nets:
            if net.version == vnet.version and net.subnet_of(vnet):
                return zid
        if not net.is_private:
            return INTERNET_NODE
        return None

    tm.l3_by_site = {}
    tm.sophos_alerts = so.get("alerts", [])
    for org in mk.get("organizations", []):
        for net in org.get("networks", []):
            nid = net["id"]
            sz = net.get("_site_zone")
            mx = mx_by_network.get(nid)
            for r in net.get("l3_rules") or []:
                r["_default"] = "default" in (r.get("comment") or "").lower()
            if net.get("l3_rules") is not None and mx:
                tm.l3_by_site[sz] = net["l3_rules"]
            infra = f"n_infra_{_slug(nid)}"
            if MERAKI_CLOUD in tm.nodes:
                for dev in (mx, infra):
                    if dev in tm.nodes:
                        tm.add_flow(dev, MERAKI_CLOUD, "Cloud mgmt tunnel\nTCP 443 / UDP 7351", kind="mgmt")
            if not mx:
                continue
            tm.add_flow(mx, INTERNET_NODE, "WAN egress (NAT)", kind="data", bidirectional=True)
            for z in tm.zones.values():
                if z.parent == sz and z.kind == "vlan":
                    tm.add_flow(z.id, mx, "Default gateway\n(inter-VLAN routing)", kind="routed",
                                bidirectional=True)
            for i, r in enumerate(net.get("l3_rules") or []):
                default = r["_default"]
                if r.get("policy") != "allow" or (default and not cfg.include_default_rules):
                    continue
                label = _rule_label(r)
                for s in str(r.get("srcCidr", "Any")).split(","):
                    for d in str(r.get("destCidr", "Any")).split(","):
                        se, de = resolve(s, nid, sz), resolve(d, nid, sz)
                        if se and de and se != de:
                            tm.add_flow(se, de, label, kind="data",
                                        props={"rule": r, "network": net["name"], "rule_index": i})
            for r in net.get("port_forwards") or []:
                dst = asset_node_by_ip.get(r.get("lanIp")) or (zone_for_ip(r.get("lanIp")) or mx)
                tm.add_flow(INTERNET_NODE, dst,
                            f"Port fwd {r.get('protocol', 'tcp').upper()} {r.get('publicPort')}"
                            f"\n-> {r.get('lanIp')}:{r.get('localPort')}",
                            kind="inbound", props={"rule": r, "network": net["name"], "type": "port_forward"})
            for r in net.get("one_to_one_nat") or []:
                dst = asset_node_by_ip.get(r.get("lanIp")) or (zone_for_ip(r.get("lanIp")) or mx)
                svcs = "; ".join(f"{x.get('protocol', '').upper()} {','.join(map(str, x.get('ports') or ['any']))}"
                                 for x in r.get("allowedInbound") or []) or "none"
                tm.add_flow(INTERNET_NODE, dst, f"1:1 NAT {r.get('publicIp')}\n{svcs}",
                            kind="inbound", props={"rule": r, "network": net["name"], "type": "one_to_one_nat"})
            vpn = net.get("site_to_site_vpn") or {}
            if vpn.get("mode") in ("spoke", "hub"):
                for hub in vpn.get("hubs") or []:
                    hub_mx = mx_by_network.get(hub.get("hubId"))
                    if hub_mx and hub_mx != mx:
                        tm.add_flow(mx, hub_mx, "AutoVPN (IPsec)", kind="vpn", bidirectional=True)

    _dedupe_flows(tm)

    # ---- Pages -------------------------------------------------------------------------
    top = {z.id for z in tm.zones.values() if z.parent is None}
    shared = {INTERNET_ZONE, CLOUD_ZONE} & set(tm.zones)
    overview_zones = set(top) | {z.id for z in tm.zones.values() if z.kind == "vlan"}
    overview_nodes = {n.id for n in tm.nodes.values()
                      if n.kind in ("external", "process", "device")}
    tm.pages.append(Page("Overview", overview_zones, overview_nodes))
    for z in sorted(tm.zones.values(), key=lambda z: z.name):
        if z.parent is None and z.id not in shared:
            zs = {z.id} | {c.id for c in tm.zones.values() if c.id != z.id and z.id in tm.zone_ancestors(c.id)}
            ns = {n.id for n in tm.nodes.values() if n.zone in zs}
            ns |= {n.id for n in tm.nodes.values() if n.zone in shared}
            tm.pages.append(Page(z.name.replace("Site: ", ""), zs | shared, ns))

    tm.stats = {
        "assets": len(idx.assets),
        "sophos_managed": sum(a["sophos_managed"] for a in idx.assets),
        "zones": len(tm.zones), "nodes": len(tm.nodes), "flows": len(tm.flows),
    }
    tm.assets = idx.assets  # used by threat rules
    return tm


def _asset_props(a):
    s = a.get("sophos") or {}
    return {"hostname": a["hostname"], "ips": a["ips"], "macs": a["macs"], "os": a.get("os"),
            "category": a["category"], "sources": sorted(a["sources"]),
            "sophos_managed": a["sophos_managed"], "sophos_health": s.get("health"),
            "tamper_protection": s.get("tamper_protection")}


def _rule_label(r) -> str:
    proto = (r.get("protocol") or "any").upper()
    port = r.get("destPort") or "Any"
    txt = f"{proto} {port}" if proto != "ANY" else "ANY"
    if r.get("comment") and "default" not in r["comment"].lower():
        txt += f"\n{r['comment'][:40]}"
    return txt


def _dedupe_flows(tm: ThreatModel):
    seen = {}
    out = []
    for f in tm.flows:
        if f.src not in tm.nodes and f.src not in tm.zones or f.dst not in tm.nodes and f.dst not in tm.zones:
            continue
        key = (f.src, f.dst, f.kind)
        if key in seen:
            prev = seen[key]
            if f.label not in prev.label:
                prev.label += "\n" + f.label
            prev.props.setdefault("merged", []).append(f.props)
            continue
        seen[key] = f
        out.append(f)
    for i, f in enumerate(out, 1):
        f.id = f"f{i}"
    tm.flows = out
