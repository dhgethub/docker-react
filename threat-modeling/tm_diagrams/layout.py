"""Simple deterministic nested-box layout shared by the draw.io and Lucid exporters."""
from __future__ import annotations

import math
from dataclasses import dataclass

from .model import Page, ThreatModel

NODE_W, NODE_H = 180, 70
GAP = 40
PAD = 30
HEADER = 40
MAX_ROW_W = {"page": 3000, "site": 1500, "default": 1100}
ZONE_ORDER = {"internet": 0, "cloud": 1, "site": 2, "other": 3, "vlan": 4}


@dataclass
class Box:
    x: float          # absolute
    y: float
    w: float
    h: float
    rx: float = 0     # relative to parent container
    ry: float = 0
    parent: str | None = None


def _shelf(items, max_w):
    """items: list of (id, w, h). Returns (positions{id:(x,y)}, total_w, total_h)."""
    pos, x, y, row_h, total_w = {}, 0, 0, 0, 0
    for iid, w, h in items:
        if x > 0 and x + w > max_w:
            x, y, row_h = 0, y + row_h + GAP, 0
        pos[iid] = (x, y)
        x += w + GAP
        row_h = max(row_h, h)
        total_w = max(total_w, x - GAP)
    return pos, total_w, y + row_h


def layout_page(tm: ThreatModel, page: Page) -> dict[str, Box]:
    zones = {z: tm.zones[z] for z in page.zones if z in tm.zones}
    nodes = [tm.nodes[n] for n in sorted(page.nodes) if n in tm.nodes and tm.nodes[n].zone in zones]
    kids_z = {z: [] for z in zones}
    kids_n = {z: [] for z in zones}
    roots = []
    for z in sorted(zones.values(), key=lambda z: (ZONE_ORDER.get(z.kind, 9), z.name)):
        if z.parent in zones:
            kids_z[z.parent].append(z.id)
        else:
            roots.append(z.id)
    for n in sorted(nodes, key=lambda n: (n.kind != "process", n.kind, n.name)):
        kids_n[n.zone].append(n.id)

    size, inner = {}, {}

    def measure(zid):
        for c in kids_z[zid]:
            measure(c)
        n = len(kids_n[zid])
        cols = min(4, max(1, math.ceil(math.sqrt(n)))) if n else 0
        rows = math.ceil(n / cols) if n else 0
        nw = cols * NODE_W + max(0, cols - 1) * GAP
        nh = rows * NODE_H + max(0, rows - 1) * GAP
        max_w = max(nw, MAX_ROW_W.get(zones[zid].kind, MAX_ROW_W["default"]))
        zpos, zw, zh = _shelf([(c, *size[c]) for c in kids_z[zid]], max_w)
        w = max(nw, zw, 260) + 2 * PAD
        h = HEADER + PAD + nh + (GAP if n and kids_z[zid] else 0) + zh + PAD
        inner[zid] = (cols, nh, zpos)
        size[zid] = (w, h)

    for r in roots:
        measure(r)

    boxes: dict[str, Box] = {}

    def place(zid, ax, ay, parent, rx, ry):
        w, h = size[zid]
        boxes[zid] = Box(ax, ay, w, h, rx, ry, parent)
        cols, nh, zpos = inner[zid]
        for i, nid in enumerate(kids_n[zid]):
            cx = PAD + (i % cols) * (NODE_W + GAP)
            cy = HEADER + PAD + (i // cols) * (NODE_H + GAP)
            boxes[nid] = Box(ax + cx, ay + cy, NODE_W, NODE_H, cx, cy, zid)
        off = HEADER + PAD + nh + (GAP if kids_n[zid] and kids_z[zid] else 0)
        for c, (x, y) in zpos.items():
            place(c, ax + PAD + x, ay + off + y, zid, PAD + x, off + y)

    # Row 1: Internet + vendor cloud; following rows: sites / other
    first = [r for r in roots if zones[r].kind in ("internet", "cloud")]
    rest = [r for r in roots if r not in first]
    y = 0
    for group in (first, rest):
        if not group:
            continue
        pos, _, gh = _shelf([(r, *size[r]) for r in group], MAX_ROW_W["page"])
        for r, (x, yy) in pos.items():
            place(r, x, y + yy, None, x, y + yy)
        y += gh + GAP * 2
    return boxes


def visible(tm: ThreatModel, page: Page, el: str) -> str | None:
    """Map a flow endpoint to the nearest element drawn on this page."""
    if el in page.nodes and el in tm.nodes:
        return el
    zid = tm.nodes[el].zone if el in tm.nodes else el
    for z in tm.zone_ancestors(zid if zid in tm.zones else None):
        if z in page.zones:
            return z
    return None


def page_flows(tm: ThreatModel, page: Page):
    """Flows re-targeted to visible elements and de-duplicated for one page."""
    merged = {}
    for f in tm.flows:
        s, d = visible(tm, page, f.src), visible(tm, page, f.dst)
        if not s or not d or s == d:
            continue
        key = (s, d, f.kind)
        if key in merged:
            m = merged[key]
            m["findings"] |= set(f.findings)
            if f.label not in m["labels"]:
                m["labels"].append(f.label)
            m["bidirectional"] = m["bidirectional"] or f.bidirectional
        else:
            merged[key] = {"id": f.id, "src": s, "dst": d, "kind": f.kind, "labels": [f.label],
                           "findings": set(f.findings), "bidirectional": f.bidirectional,
                           "stride_prompt": f.props.get("stride_prompt")}
    for m in merged.values():
        labels = m["labels"]
        m["label"] = "\n".join(labels[:4]) + (f"\n(+{len(labels) - 4} more)" if len(labels) > 4 else "")
    return list(merged.values())
