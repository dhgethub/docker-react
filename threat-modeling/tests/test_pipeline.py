"""Offline tests using the bundled demo data:  python -m pytest tests  (or python tests/test_pipeline.py)"""
import json
import sys
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tm_diagrams import builder, threats  # noqa: E402
from tm_diagrams.config import Config  # noqa: E402
from tm_diagrams.exporters import drawio, lucid, report  # noqa: E402

DEMO = Path(__file__).resolve().parents[1] / "tm_diagrams" / "sample_data" / "demo_raw.json"


def _model():
    cfg = Config()
    return threats.analyze(builder.build(json.loads(DEMO.read_text()), cfg), cfg)


def test_correlation_and_findings():
    tm = _model()
    assert tm.stats["assets"] == 76          # Axonius + Sophos + Meraki merged, no duplicates
    titles = [f.title for f in tm.findings]
    sev = {f.title: f.severity for f in tm.findings}
    rdp = next(t for t in titles if "Internet-exposed" in t and "SQL01" in t)
    assert sev[rdp] == "critical"
    assert any("No inter-VLAN segmentation" in t and "Branch-01" in t for t in titles)
    assert any("tamper protection" in t for t in titles)
    assert any("HQ-BKP01 has no Sophos" in t for t in titles)


def test_drawio_edges_reference_cells(tmp_path):
    tm = _model()
    path = drawio.export(tm, tmp_path / "tm.drawio")
    root = ET.parse(path).getroot()
    diagrams = root.findall("diagram")
    assert len(diagrams) == len(tm.pages) + 1
    for d in diagrams:
        ids = {e.get("id") for e in d.iter() if e.get("id")}
        for cell in d.iter("mxCell"):
            if cell.get("edge"):
                assert cell.get("source") in ids and cell.get("target") in ids
            if cell.get("parent"):
                assert cell.get("parent") in ids


def test_lucid_document(tmp_path):
    tm = _model()
    path = lucid.export(tm, tmp_path / "tm.lucid")
    doc = json.loads(zipfile.ZipFile(path).read("document.json"))
    assert doc["version"] == 1
    for page in doc["pages"]:
        ids = {s["id"] for s in page["shapes"]}
        assert len(ids) == len(page["shapes"])
        for line in page["lines"]:
            assert line["endpoint1"]["shapeId"] in ids and line["endpoint2"]["shapeId"] in ids


def test_report(tmp_path):
    files = report.export(_model(), tmp_path)
    assert all(f.exists() and f.stat().st_size for f in files)


if __name__ == "__main__":
    import tempfile
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            with tempfile.TemporaryDirectory() as d:
                fn(Path(d)) if fn.__code__.co_argcount else fn()
            print("ok", name)
