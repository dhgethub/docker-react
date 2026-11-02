"""STRIDE rule engine: turns the correlated model into concrete findings."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .builder import INTERNET_NODE
from .model import ThreatModel


def _ports(spec) -> set[int] | None:
    """Parse '443', '80,443', '1000-2000', 'any' -> set of ints (None = any)."""
    spec = str(spec or "any").strip().lower()
    if spec in ("any", ""):
        return None
    out = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            if a.isdigit() and b.isdigit() and int(b) - int(a) < 70000:
                out.update(range(int(a), int(b) + 1))
        elif part.isdigit():
            out.add(int(part))
    return out


def _rules(flow):
    for p in [flow.props, *flow.props.get("merged", [])]:
        if p.get("rule"):
            yield p


def _parse_time(v):
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except ValueError:
        return None


def analyze(tm: ThreatModel, cfg) -> ThreatModel:
    risky, clear = set(cfg.risky_ports), set(cfg.cleartext_ports)
    name = tm.label

    # 1. Internet-exposed services (port forwards, 1:1 NAT)
    for f in tm.flows:
        if f.kind != "inbound":
            continue
        for p in _rules(f):
            r = p["rule"]
            if p.get("type") == "port_forward":
                ports = _ports(r.get("publicPort"))
                allowed = r.get("allowedIps") or ["any"]
            else:
                ports = set()
                for x in r.get("allowedInbound") or []:
                    ps = _ports(",".join(map(str, x.get("ports") or ["any"])))
                    ports = None if ps is None or ports is None else ports | ps
                allowed = sum((x.get("allowedIps") or ["any"] for x in r.get("allowedInbound") or []), [])
            open_world = any(str(a).lower() in ("any", "0.0.0.0/0") for a in allowed)
            hit = (ports is None) or bool(ports & risky)
            sev = "critical" if hit and open_world else "high" if open_world else "medium"
            tm.add_finding(
                f"Internet-exposed service to {name(f.dst)} ({p['network']})", sev,
                ["Spoofing", "Tampering", "Elevation of privilege", "Denial of service"], [f.id, f.dst],
                f"{p['type'].replace('_', ' ')} rule '{r.get('name') or r.get('lanIp')}' exposes "
                f"ports {r.get('publicPort') or sorted(ports or [])[:10] or 'ANY'} from "
                f"{', '.join(map(str, allowed))}.",
                "Restrict allowedIps to known sources, place the service behind a VPN/ZTNA or "
                "reverse proxy with MFA, and confirm the host is Sophos-protected and patched.",
                "meraki")

    # 2. Over-permissive L3 rules between internal zones / to Internet
    for f in tm.flows:
        for p in _rules(f):
            r = p["rule"]
            if p.get("type") or r.get("policy") != "allow":
                continue
            ports = _ports(r.get("destPort"))
            src_any = str(r.get("srcCidr", "")).lower() == "any"
            dst_any = str(r.get("destCidr", "")).lower() == "any"
            if ports is None and (str(r.get("protocol", "any")).lower() == "any" or src_any or dst_any):
                tm.add_finding(
                    f"Permissive allow rule {name(f.src)} -> {name(f.dst)}", "medium",
                    ["Tampering", "Information disclosure", "Elevation of privilege"], [f.id],
                    f"MX L3 rule #{p['rule_index'] + 1} in {p['network']} allows "
                    f"{r.get('protocol')} {r.get('srcCidr')} -> {r.get('destCidr')}:{r.get('destPort')} "
                    f"({r.get('comment') or 'no comment'}). Enables lateral movement.",
                    "Replace with least-privilege rules (specific protocol/ports/hosts).", "meraki")
            elif ports and ports & clear:
                tm.add_finding(
                    f"Cleartext protocol allowed {name(f.src)} -> {name(f.dst)}", "low",
                    ["Information disclosure", "Tampering"], [f.id],
                    f"Rule allows cleartext ports {sorted(ports & clear)} ({p['network']}).",
                    "Prefer encrypted equivalents (HTTPS, SSH, LDAPS, SNMPv3, SFTP).", "meraki")
            elif ports and ports & risky and (src_any or dst_any):
                tm.add_finding(
                    f"Admin/high-risk ports broadly allowed {name(f.src)} -> {name(f.dst)}", "medium",
                    ["Elevation of privilege", "Spoofing"], [f.id],
                    f"Ports {sorted(ports & risky)} allowed with 'Any' source or destination.",
                    "Limit admin protocols to a management VLAN / jump hosts.", "meraki")

    # 3. Default allow between VLANs (only explicit if deny rules missing)
    for net_zone, rules in getattr(tm, "l3_by_site", {}).items():
        has_deny = any(r.get("policy") == "deny" for r in rules if not r.get("_default"))
        default = next((r for r in rules if r.get("_default")), None)
        vlans = [z for z in tm.zones.values() if z.parent == net_zone and z.kind == "vlan"]
        if default and default.get("policy") == "allow" and not has_deny and len(vlans) > 1:
            tm.add_finding(
                f"No inter-VLAN segmentation at {tm.zones[net_zone].name}", "high",
                ["Tampering", "Information disclosure", "Elevation of privilege"],
                [f.id for f in tm.flows if f.kind == "routed" and f.src in {v.id for v in vlans}],
                f"{len(vlans)} VLANs route freely: the only L3 policy is the default allow-any.",
                "Add deny rules between user, server, IoT and guest VLANs; allow only required flows.",
                "meraki")

    # 4. Endpoint protection coverage gaps (Axonius/Meraki assets without Sophos)
    for n in tm.nodes.values():
        if n.kind == "asset_group" and n.props["sophos_unmanaged"] and n.props["category"] in (
                "Workstations", "Servers"):
            cnt, tot = n.props["sophos_unmanaged"], n.props["count"]
            tm.add_finding(
                f"{cnt}/{tot} {n.props['category'].lower()} in {tm.label(n.zone)} "
                "lack Sophos", "high" if n.props["category"] == "Servers" or cnt / tot > 0.1 else "medium",
                ["Tampering", "Repudiation", "Elevation of privilege"], [n.id],
                "Assets seen by Axonius/Meraki with no matching Sophos Central endpoint.",
                "Deploy Sophos Intercept X / Server Protection or document a compensating control.",
                "axonius")
        elif n.kind == "asset" and not n.props["sophos_managed"] and n.props["category"] in (
                "Workstations", "Servers"):
            tm.add_finding(f"{n.props['hostname']} has no Sophos agent",
                           "high" if n.props["category"] == "Servers" else "medium",
                           ["Tampering", "Repudiation", "Elevation of privilege"], [n.id],
                           f"Seen by {', '.join(n.props['sources'])}; not in Sophos Central.",
                           "Install the Sophos agent or document a compensating control.", "axonius")

    # 5. Sophos endpoint health / tamper protection / stale
    stale_before = datetime.now(timezone.utc) - timedelta(days=cfg.stale_days)
    bad, no_tamper, stale = [], [], []
    for a in getattr(tm, "assets", []):
        s = a.get("sophos")
        if not s:
            continue
        if s.get("health") in ("bad", "suspicious") or s.get("threats") not in (None, "good", "unknown"):
            bad.append(a)
        if s.get("tamper_protection") is False:
            no_tamper.append(a)
        seen = _parse_time(s.get("last_seen"))
        if seen and seen < stale_before:
            stale.append(a)
    for items, title, sev, stride, rec in (
        (bad, "Sophos endpoints in bad/suspicious health", "high",
         ["Tampering", "Elevation of privilege"], "Investigate in Sophos Central; remediate or isolate."),
        (no_tamper, "Sophos tamper protection disabled", "high",
         ["Tampering", "Repudiation"], "Re-enable tamper protection via Central policy."),
        (stale, f"Sophos endpoints not seen in {cfg.stale_days}+ days", "low",
         ["Repudiation"], "Verify devices are decommissioned or reconnect them."),
    ):
        if items:
            tm.add_finding(f"{title} ({len(items)})", sev, stride, sorted({a["node"] for a in items}),
                           "Hosts: " + ", ".join(sorted(a["hostname"] for a in items)[:25]) +
                           (" ..." if len(items) > 25 else ""), rec, "sophos")

    # 6. Open high-severity Sophos alerts
    alerts = [a for a in getattr(tm, "sophos_alerts", []) if a.get("severity") == "high"]
    if alerts:
        hosts = {a.get("hostname") for a in alerts if a.get("hostname")}
        nodes = sorted({x["node"] for x in tm.assets if x["hostname"] in hosts})
        tm.add_finding(f"{len(alerts)} open high-severity Sophos alerts", "high",
                       ["Tampering", "Information disclosure"], nodes or [INTERNET_NODE],
                       "; ".join(f"{a.get('hostname')}: {a.get('description')}" for a in alerts[:10]),
                       "Triage in Sophos Central / XDR.", "sophos")

    # 7. Offline infrastructure
    for n in tm.nodes.values():
        if n.props.get("status") == "offline" or n.props.get("offline"):
            tm.add_finding(f"Offline network device(s) at {n.name.splitlines()[0]}", "low",
                           ["Denial of service"], [n.id],
                           "Device(s) offline in Meraki Dashboard: no telemetry or policy updates.",
                           "Restore connectivity or remove from inventory.", "meraki")
        if n.props.get("role") == "firewall" and n.props.get("connected") is False:
            tm.add_finding(f"Sophos firewall {n.name.splitlines()[0]} disconnected from Central", "medium",
                           ["Denial of service", "Repudiation"], [n.id],
                           "Firewall is not reporting to Sophos Central.", "Check Central connectivity.",
                           "sophos")

    # Generic boundary-crossing STRIDE prompts (informational) for flows without findings
    for f in tm.flows:
        if f.findings or f.kind == "routed":
            continue
        if f.src == INTERNET_NODE or f.dst == INTERNET_NODE:
            f.props["stride_prompt"] = "Crosses Internet boundary: consider S, T, I, D."
    return tm
