"""Threat register outputs: Markdown, CSV and JSON."""
from __future__ import annotations

import csv
import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from ..model import SEVERITY_ORDER, ThreatModel


def export(tm: ThreatModel, out: Path) -> list[Path]:
    findings = sorted(tm.findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.id))
    md = out / "threat_register.md"
    counts = {s: sum(f.severity == s for f in findings) for s in SEVERITY_ORDER}
    lines = [f"# Threat register — generated {datetime.now():%Y-%m-%d %H:%M}", "",
             "| Metric | Value |", "|---|---|"]
    lines += [f"| {k.replace('_', ' ')} | {v} |" for k, v in tm.stats.items()]
    lines += [f"| {s} findings | {c} |" for s, c in counts.items() if c]
    lines += ["", "| ID | Severity | Finding | STRIDE | Detail | Recommendation |",
              "|---|---|---|---|---|---|"]
    esc = lambda s: str(s).replace("|", "\\|").replace("\n", " ")  # noqa: E731
    lines += [f"| {f.id} | {f.severity} | {esc(f.title)} | {', '.join(f.stride)} | {esc(f.detail)} | "
              f"{esc(f.recommendation)} |" for f in findings]
    md.write_text("\n".join(lines) + "\n")

    csv_path = out / "threat_register.csv"
    with open(csv_path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["id", "severity", "title", "stride", "elements", "detail", "recommendation", "source"])
        for f in findings:
            w.writerow([f.id, f.severity, f.title, "; ".join(f.stride), "; ".join(f.elements),
                        f.detail, f.recommendation, f.source])

    js = out / "model.json"
    js.write_text(json.dumps({
        "stats": tm.stats,
        "zones": [asdict(z) for z in tm.zones.values()],
        "nodes": [asdict(n) for n in tm.nodes.values()],
        "flows": [asdict(f) for f in tm.flows],
        "findings": [asdict(f) for f in findings],
    }, indent=2, default=str))
    return [md, csv_path, js]
