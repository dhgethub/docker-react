"""Export a ThreatModel to Lucid Standard Import (.lucid) and optionally upload it via the Lucid REST API.

Lucidchart can also import the .drawio file directly (Lucidchart > Import > draw.io), which
preserves the most styling. The native .lucid path is useful for automation (no manual import).
"""
from __future__ import annotations

import json
import logging
import zipfile
from pathlib import Path

from ..layout import layout_page, page_flows
from ..model import ThreatModel
from .styles import FLOW_COLOR, NODE_STYLE, SEV_COLOR, ZONE_STYLE

log = logging.getLogger(__name__)
LUCID_API = "https://api.lucid.co/documents"

# Standard Import shape types (Lucid standard library). Containers are drawn as dashed rectangles.
NODE_TYPE = {"external": "rectangle", "process": "circle", "device": "rectangle",
             "asset": "rectangle", "asset_group": "rectangle", "datastore": "rectangle"}


def _style(fill, stroke, width=1, dashed=False):
    return {"fill": {"type": "color", "color": fill},
            "stroke": {"color": stroke, "width": width, "style": "dashed" if dashed else "solid"}}


def _text(name, findings=()):
    t = name.replace("\n", " | ") if "\n" in name and len(name) > 60 else name
    if findings:
        t += "\n⚠ " + ", ".join(sorted(findings)[:4])
    return t


def build_document(tm: ThreatModel) -> dict:
    pages = []
    for pi, page in enumerate(tm.pages):
        boxes = layout_page(tm, page)
        shapes, lines = [], []
        for zid in sorted((z for z in boxes if z in tm.zones), key=lambda z: len(list(tm.zone_ancestors(z)))):
            z, b = tm.zones[zid], boxes[zid]
            fill, stroke = ZONE_STYLE.get(z.kind, ZONE_STYLE["other"])
            shapes.append({"id": f"p{pi}_{zid}", "type": "rectangle",
                           "boundingBox": {"x": b.x, "y": b.y, "w": b.w, "h": b.h},
                           "style": _style(fill, stroke, 2, dashed=True),
                           "text": z.name.replace("\n", "  |  "),
                           "customData": [{"key": "tm_type", "value": "trust_boundary"},
                                          {"key": "trust", "value": z.trust}]})
        for nid in (n for n in boxes if n in tm.nodes):
            n, b = tm.nodes[nid], boxes[nid]
            fill, stroke = NODE_STYLE.get(n.kind, NODE_STYLE["asset"])
            sev = tm.worst_severity(n.findings)
            shape = {"id": f"p{pi}_{nid}", "type": NODE_TYPE.get(n.kind, "rectangle"),
                     "boundingBox": {"x": b.x, "y": b.y, "w": b.w, "h": b.h},
                     "style": _style(fill, SEV_COLOR[sev] if sev else stroke, 3 if sev else 1),
                     "text": _text(n.name, n.findings),
                     "customData": [{"key": "tm_type", "value": n.kind}] + [
                         {"key": k, "value": ", ".join(map(str, v)) if isinstance(v, (list, set)) else str(v)}
                         for k, v in n.props.items()
                         if k not in ("members", "devices") and v not in (None, "", [])][:20]}
            shapes.append(shape)
        for f in page_flows(tm, page):
            sev = tm.worst_severity(f["findings"])
            color = SEV_COLOR[sev] if sev else FLOW_COLOR.get(f["kind"], "#333333")
            label = f["label"] + (f"\n⚠ {', '.join(sorted(f['findings'])[:4])}" if f["findings"] else "")
            lines.append({
                "id": f"p{pi}_{f['id']}", "lineType": "elbow",
                "stroke": {"color": color, "width": 3 if sev else 1,
                           "style": "dashed" if f["kind"] in ("mgmt", "vpn") else "solid"},
                "endpoint1": {"type": "shapeEndpoint", "style": "arrow" if f["bidirectional"] else "none",
                              "shapeId": f"p{pi}_{f['src']}", "position": {"x": 0.5, "y": 1}},
                "endpoint2": {"type": "shapeEndpoint", "style": "arrow",
                              "shapeId": f"p{pi}_{f['dst']}", "position": {"x": 0.5, "y": 0}},
                "text": [{"text": label, "position": 0.5, "side": "middle"}],
            })
        pages.append({"id": f"page{pi}", "title": page.title, "shapes": shapes, "lines": lines})

    # Findings page as a column of text boxes
    fshapes = [{"id": "findings_hdr", "type": "rectangle",
                "boundingBox": {"x": 0, "y": 0, "w": 1400, "h": 40},
                "style": _style("#EEEEEE", "#666666"), "text": "Threat findings (STRIDE)"}]
    for i, fd in enumerate(tm.findings):
        fshapes.append({"id": f"finding_{fd.id}", "type": "rectangle",
                        "boundingBox": {"x": 0, "y": 50 + i * 70, "w": 1400, "h": 60},
                        "style": _style("#FFFFFF", SEV_COLOR[fd.severity], 2),
                        "text": f"{fd.id} [{fd.severity.upper()}] {fd.title}\n"
                                f"STRIDE: {', '.join(fd.stride)} — {fd.recommendation}"})
    pages.append({"id": "page_findings", "title": "Findings", "shapes": fshapes, "lines": []})
    return {"version": 1, "pages": pages}


def export(tm: ThreatModel, path: Path) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("document.json", json.dumps(build_document(tm), indent=1))
    return path


def upload(path: Path, token: str, title: str) -> dict:
    """Create a Lucidchart document from a .lucid Standard Import file."""
    import requests

    with open(path, "rb") as fh:
        r = requests.post(LUCID_API, timeout=120,
                          headers={"Authorization": f"Bearer {token}", "Lucid-Api-Version": "1"},
                          data={"title": title, "product": "lucidchart"},
                          files={"file": (path.name, fh, "x-application/vnd.lucid.standardImport")})
    if r.status_code >= 400:
        raise RuntimeError(f"Lucid import failed ({r.status_code}): {r.text[:500]}")
    return r.json()
