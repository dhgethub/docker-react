"""Command line entry point:  python -m tm_diagrams [options]"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime
from pathlib import Path

from . import builder, threats
from .config import load_config
from .exporters import drawio, lucid, report

log = logging.getLogger("tm_diagrams")
SOURCES = ("axonius", "sophos", "meraki")
DEMO = Path(__file__).parent / "sample_data" / "demo_raw.json"


def collect_all(cfg, only: list[str]) -> dict:
    raw = {}
    for name in only:
        if not getattr(cfg, f"has_{name}"):
            log.warning("%s: credentials not set, skipping", name)
            continue
        mod = __import__(f"tm_diagrams.collectors.{name}", fromlist=["collect"])
        try:
            raw[name] = mod.collect(cfg)
        except Exception as exc:  # keep going with the other sources
            log.error("%s collection failed: %s", name, exc, exc_info=log.isEnabledFor(logging.DEBUG))
    return raw


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="tm_diagrams",
                                 description="Pull Axonius/Sophos/Meraki data and build threat-model DFDs.")
    ap.add_argument("-c", "--config", help="config.yaml path (default ./config.yaml if present)")
    ap.add_argument("--env-file", help=".env path (default ./.env)")
    ap.add_argument("-o", "--output", help="output directory (overrides config)")
    ap.add_argument("--sources", default=",".join(SOURCES),
                    help="comma list of sources to pull (default: all)")
    ap.add_argument("--offline", metavar="RAW_JSON",
                    help="skip API calls and rebuild diagrams from a previously saved raw.json")
    ap.add_argument("--demo", action="store_true", help="use bundled sample data (no credentials needed)")
    ap.add_argument("--format", default="drawio,lucid,report",
                    help="comma list: drawio, lucid, report (default: all)")
    ap.add_argument("--lucid-upload", action="store_true",
                    help="upload the .lucid file to Lucidchart via REST API (needs LUCID_API_TOKEN)")
    ap.add_argument("--title", default="Threat Model", help="diagram/document title")
    ap.add_argument("--max-nodes-per-zone", type=int, help="collapse zones with more assets than this")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    cfg = load_config(args.config, args.env_file)
    if args.max_nodes_per_zone:
        cfg.max_nodes_per_zone = args.max_nodes_per_zone
    out = Path(args.output or cfg.output_dir) / datetime.now().strftime("%Y%m%d-%H%M%S")
    out.mkdir(parents=True, exist_ok=True)

    if args.demo:
        raw = json.loads(DEMO.read_text())
    elif args.offline:
        raw = json.loads(Path(args.offline).read_text())
    else:
        only = [s.strip() for s in args.sources.split(",") if s.strip() in SOURCES]
        raw = collect_all(cfg, only)
        if not raw:
            log.error("No data collected. Set credentials in .env (see .env.example) or use --demo.")
            return 2
    (out / "raw.json").write_text(json.dumps(raw, indent=1, default=str))

    tm = threats.analyze(builder.build(raw, cfg), cfg)
    log.info("Model: %s, %d findings", tm.stats, len(tm.findings))

    fmts = {f.strip() for f in args.format.split(",")}
    slug = args.title.lower().replace(" ", "_")
    if "drawio" in fmts:
        log.info("Wrote %s", drawio.export(tm, out / f"{slug}.drawio"))
    if "lucid" in fmts or args.lucid_upload:
        lpath = lucid.export(tm, out / f"{slug}.lucid")
        log.info("Wrote %s", lpath)
        if args.lucid_upload:
            if not cfg.lucid_api_token:
                log.error("LUCID_API_TOKEN not set; skipping upload")
            else:
                try:
                    doc = lucid.upload(lpath, cfg.lucid_api_token, args.title)
                    log.info("Lucidchart document created: %s", doc.get("editUrl") or doc)
                except Exception as exc:
                    log.error("%s  (you can still import %s manually, or the .drawio file)",
                              exc, lpath.name)
    if "report" in fmts:
        for p in report.export(tm, out):
            log.info("Wrote %s", p)
    print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
