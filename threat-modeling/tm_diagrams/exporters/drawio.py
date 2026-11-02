"""Export a ThreatModel to a multi-page .drawio file (also importable by Lucidchart)."""
from __future__ import annotations

import html
import xml.etree.ElementTree as ET
from pathlib import Path

from ..layout import layout_page, page_flows
from ..model import ThreatModel
from .styles import FLOW_COLOR, NODE_STYLE, SEV_COLOR, ZONE_STYLE

NODE_SHAPE = {
    "external": "rounded=0;",
    "process": "ellipse;",
    "device": "rounded=1;",
    "asset": "rounded=1;arcSize=10;",
    "asset_group": "shape=process;backgroundOutline=1;size=0.06;",
    "datastore": "shape=cylinder3;boundedLbl=1;size=10;",
}


def _label(text: str, findings: list[str]) -> str:
    out = "<br>".join(html.escape(line) for line in text.split("\n"))
    if findings:
        out += f"<br><font color=\"#B20000\"><b>&#9888; {html.escape(', '.join(sorted(findings)[:4]))}" \
               f"{' ...' if len(findings) > 4 else ''}</b></font>"
    return out


def _tooltip(props: dict) -> str:
    lines = []
    for k, v in props.items():
        if k in ("members", "devices", "merged", "rule") or v in (None, "", []):
            continue
        lines.append(f"{k}: {', '.join(map(str, v)) if isinstance(v, (list, set)) else v}")
    return "\n".join(lines)[:2000]


def _cell(root, cid, value, style, parent, vertex=True, tooltip="", **attrs):
    obj = ET.SubElement(root, "UserObject", {"id": cid, "label": value, **(
        {"tooltip": tooltip} if tooltip else {}), **{k: str(v) for k, v in attrs.items()}})
    cell = ET.SubElement(obj, "mxCell", {"style": style, "parent": parent,
                                         ("vertex" if vertex else "edge"): "1"})
    return cell


def build_xml(tm: ThreatModel) -> ET.Element:
    mxfile = ET.Element("mxfile", {"host": "tm-diagrams", "type": "device"})
    for pi, page in enumerate(tm.pages + [None]):
        diagram = ET.SubElement(mxfile, "diagram", {"id": f"page{pi}",
                                                    "name": page.title if page else "Findings"})
        model = ET.SubElement(diagram, "mxGraphModel", {
            "grid": "1", "gridSize": "10", "guides": "1", "tooltips": "1", "connect": "1",
            "arrows": "1", "fold": "1", "page": "0", "pageScale": "1", "math": "0", "shadow": "0"})
        root = ET.SubElement(model, "root")
        ET.SubElement(root, "mxCell", {"id": "0"})
        ET.SubElement(root, "mxCell", {"id": "1", "parent": "0"})
        if page is None:
            _findings_page(root, tm)
            continue
        boxes = layout_page(tm, page)
        p = f"p{pi}_"

        # Zones first (parents must precede children)
        for zid in sorted((z for z in boxes if z in tm.zones), key=lambda z: len(list(tm.zone_ancestors(z)))):
            z, b = tm.zones[zid], boxes[zid]
            fill, stroke = ZONE_STYLE.get(z.kind, ZONE_STYLE["other"])
            style = (f"swimlane;startSize=34;html=1;whiteSpace=wrap;rounded=1;arcSize=2;dashed=1;"
                     f"dashPattern=8 4;strokeWidth=2;fillColor={fill};swimlaneFillColor={fill};"
                     f"strokeColor={stroke};fontStyle=1;align=left;spacingLeft=10;container=1;collapsible=0;")
            c = _cell(root, p + zid, _label(z.name.replace("\n", "  |  "), []), style,
                      p + b.parent if b.parent else "1", tooltip=_tooltip(z.props),
                      tm_type="trust_boundary", tm_trust=z.trust)
            ET.SubElement(c, "mxGeometry", {"x": str(b.rx), "y": str(b.ry), "width": str(b.w),
                                            "height": str(b.h), "as": "geometry"})
        for nid in (n for n in boxes if n in tm.nodes):
            n, b = tm.nodes[nid], boxes[nid]
            fill, stroke = NODE_STYLE.get(n.kind, NODE_STYLE["asset"])
            sev = tm.worst_severity(n.findings)
            if sev:
                stroke = SEV_COLOR[sev]
            style = (f"{NODE_SHAPE.get(n.kind, '')}whiteSpace=wrap;html=1;fillColor={fill};"
                     f"strokeColor={stroke};strokeWidth={3 if sev else 1};fontSize=11;")
            c = _cell(root, p + nid, _label(n.name, n.findings), style, p + b.parent,
                      tooltip=_tooltip(n.props), tm_type=n.kind)
            ET.SubElement(c, "mxGeometry", {"x": str(b.rx), "y": str(b.ry), "width": str(b.w),
                                            "height": str(b.h), "as": "geometry"})
        for f in page_flows(tm, page):
            sev = tm.worst_severity(f["findings"])
            color = SEV_COLOR[sev] if sev else FLOW_COLOR.get(f["kind"], "#333333")
            dashed = "dashed=1;" if f["kind"] in ("mgmt", "vpn") else ""
            style = (f"edgeStyle=orthogonalEdgeStyle;rounded=1;html=1;endArrow=block;endFill=1;"
                     f"{'startArrow=block;startFill=1;' if f['bidirectional'] else ''}{dashed}"
                     f"strokeColor={color};strokeWidth={3 if sev else 1.5};fontSize=10;"
                     f"labelBackgroundColor=#FFFFFF;fontColor={color};")
            tip = f.get("stride_prompt") or ""
            c = _cell(root, p + f["id"], _label(f["label"], sorted(f["findings"])), style, "1",
                      vertex=False, tooltip=tip, tm_type=f"flow_{f['kind']}")
            c.set("source", p + f["src"])
            c.set("target", p + f["dst"])
            ET.SubElement(c, "mxGeometry", {"relative": "1", "as": "geometry"})
        _legend(root, p, boxes)
    return mxfile


def _legend(root, p, boxes):
    x = max((b.x + b.w for b in boxes.values()), default=0) + 60
    items = [("Trust boundary", "rounded=1;dashed=1;dashPattern=8 4;strokeWidth=2;strokeColor=#B85450;fillColor=none;"),
             ("External entity", "rounded=0;fillColor=#DAE8FC;strokeColor=#6C8EBF;"),
             ("Process / firewall", "ellipse;fillColor=#D5E8D4;strokeColor=#82B366;"),
             ("Asset / asset group", "rounded=1;fillColor=#FFFFFF;strokeColor=#666666;"),
             ("Critical / high finding", "rounded=1;fillColor=#FFFFFF;strokeColor=#E0301E;strokeWidth=3;"),
             ("Medium finding", "rounded=1;fillColor=#FFFFFF;strokeColor=#F28E1C;strokeWidth=3;")]
    c = _cell(root, p + "legend_title", "<b>Legend</b>", "text;html=1;align=left;", "1")
    ET.SubElement(c, "mxGeometry", {"x": str(x), "y": "0", "width": "200", "height": "30", "as": "geometry"})
    for i, (label, st) in enumerate(items):
        c = _cell(root, f"{p}legend{i}", label, st + "html=1;whiteSpace=wrap;fontSize=10;", "1")
        ET.SubElement(c, "mxGeometry", {"x": str(x), "y": str(40 + i * 50), "width": "160",
                                        "height": "40", "as": "geometry"})


def _findings_page(root, tm: ThreatModel):
    rows = "".join(
        f"<tr><td>{f.id}</td><td><font color=\"{SEV_COLOR[f.severity]}\"><b>{f.severity.upper()}</b></font></td>"
        f"<td>{html.escape(f.title)}</td><td>{html.escape(', '.join(f.stride))}</td>"
        f"<td>{html.escape(f.recommendation)}</td></tr>" for f in tm.findings)
    table = ("<table border=\"1\" cellpadding=\"4\" style=\"border-collapse:collapse;font-size:11px\">"
             "<tr><th>ID</th><th>Severity</th><th>Finding</th><th>STRIDE</th><th>Recommendation</th></tr>"
             f"{rows or '<tr><td colspan=5>No findings</td></tr>'}</table>")
    c = _cell(root, "findings_table", table, "text;html=1;whiteSpace=wrap;align=left;verticalAlign=top;", "1")
    ET.SubElement(c, "mxGeometry", {"x": "0", "y": "0", "width": "1400",
                                    "height": str(60 + 40 * len(tm.findings)), "as": "geometry"})


def export(tm: ThreatModel, path: Path) -> Path:
    tree = ET.ElementTree(build_xml(tm))
    ET.indent(tree)
    tree.write(path, encoding="utf-8", xml_declaration=False)
    return path
