"""Normalized threat-model graph shared by all exporters."""
from __future__ import annotations

from dataclasses import dataclass, field

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Zone:
    """A trust boundary (Internet, vendor cloud, site, VLAN...). Zones nest via `parent`."""
    id: str
    name: str
    kind: str                  # internet | cloud | site | vlan | other
    trust: str = "trusted"     # untrusted | semi | trusted
    parent: str | None = None
    props: dict = field(default_factory=dict)


@dataclass
class Node:
    """A DFD element: external entity, process, data store or (grouped) asset."""
    id: str
    name: str
    kind: str                  # external | process | datastore | asset | asset_group | device
    zone: str
    props: dict = field(default_factory=dict)
    findings: list[str] = field(default_factory=list)


@dataclass
class Flow:
    """A data flow between two elements (node or zone ids)."""
    id: str
    src: str
    dst: str
    label: str
    kind: str = "data"         # data | mgmt | vpn | inbound | routed
    bidirectional: bool = False
    props: dict = field(default_factory=dict)
    findings: list[str] = field(default_factory=list)


@dataclass
class Finding:
    id: str
    title: str
    severity: str              # critical | high | medium | low | info
    stride: list[str]          # Spoofing, Tampering, Repudiation, Information disclosure, DoS, Elevation
    elements: list[str]
    detail: str
    recommendation: str
    source: str = ""


@dataclass
class Page:
    title: str
    zones: set[str]            # zones drawn on this page
    nodes: set[str]            # nodes drawn on this page


@dataclass
class ThreatModel:
    zones: dict[str, Zone] = field(default_factory=dict)
    nodes: dict[str, Node] = field(default_factory=dict)
    flows: list[Flow] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    pages: list[Page] = field(default_factory=list)
    stats: dict = field(default_factory=dict)

    def add_zone(self, z: Zone) -> Zone:
        return self.zones.setdefault(z.id, z)

    def add_node(self, n: Node) -> Node:
        return self.nodes.setdefault(n.id, n)

    def add_flow(self, src: str, dst: str, label: str, **kw) -> Flow:
        f = Flow(id=f"f{len(self.flows) + 1}", src=src, dst=dst, label=label, **kw)
        self.flows.append(f)
        return f

    def add_finding(self, title, severity, stride, elements, detail, recommendation, source=""):
        fid = f"T-{len(self.findings) + 1:03d}"
        f = Finding(fid, title, severity, stride, list(elements), detail, recommendation, source)
        self.findings.append(f)
        for el in elements:
            if el in self.nodes:
                self.nodes[el].findings.append(fid)
            else:
                for fl in self.flows:
                    if fl.id == el:
                        fl.findings.append(fid)
        return f

    def zone_ancestors(self, zid: str | None):
        while zid:
            yield zid
            zid = self.zones[zid].parent

    def label(self, el: str) -> str:
        """Single-line, site-qualified name for findings text."""
        if el in self.nodes:
            return self.nodes[el].name.replace("\n", " ")
        z = self.zones[el]
        name = z.name.splitlines()[0]
        if z.parent:
            name = f"{self.zones[z.parent].name.replace('Site: ', '')} / {name}"
        return name

    def worst_severity(self, finding_ids) -> str | None:
        sev = [f.severity for f in self.findings if f.id in finding_ids]
        return min(sev, key=SEVERITY_ORDER.get) if sev else None
