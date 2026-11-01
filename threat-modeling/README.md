# Threat-model flow diagrams from Axonius, Sophos Central and Cisco Meraki

`tm_diagrams` pulls inventory, endpoint and network data from **Axonius**, **Sophos Central** and
**Cisco Meraki**. It correlates the three sources, runs a set of STRIDE rules over the combined data
and writes out:

| Output | What it is |
|---|---|
| `threat_model.drawio` | A multi-page data-flow diagram (DFD) with trust boundaries. It opens in diagrams.net / draw.io and **imports into Lucidchart** |
| `threat_model.lucid` | A Lucid **Standard Import** file. You can upload it with the API (`--lucid-upload`) or import it by hand |
| `threat_register.md` / `.csv` | The findings: severity, STRIDE category, detail and recommendation |
| `model.json`, `raw.json` | The normalized model and the raw API data. Rebuild later with `--offline raw.json` |

## What the diagram shows

* **Trust boundaries** (dashed red containers): the Internet, the vendor cloud (Meraki Dashboard and Sophos
  Central), each Meraki **site** with its **VLANs** nested inside, and a zone for remote or unmapped networks.
* **Elements**: MX/Sophos firewalls (processes), Meraki switches and APs, and assets. When a VLAN has more
  assets than `max_nodes_per_zone`, its assets are collapsed into category groups such as "Workstations (412)".
* **Data flows** come from the real configuration:
  * MX L3 firewall *allow* rules, mapped by CIDR or `VLAN(x).*` to VLANs and hosts
  * Port forwards and 1:1 NAT (inbound from the Internet)
  * AutoVPN hub/spoke tunnels, inter-VLAN routing and WAN egress
  * Management-plane flows to Meraki Dashboard and Sophos Central
* **Findings** are drawn on the diagram: elements and flows are outlined in the colour of their worst
  severity and labelled `⚠ T-00x`. Hover over an element in draw.io to see its IPs, OS, sources and
  Sophos health. The last page of the diagram is a findings table.

Pages: **Overview** (all sites, VLAN level), then **one detailed page per site**, then **Findings**.

### Built-in STRIDE rules

| Rule | Data used |
|---|---|
| Internet-exposed services (port forward or 1:1 NAT, rated critical if a risky port is open to `any`) | Meraki |
| Overly permissive or any-port allow rules, cleartext protocols, admin ports open broadly | Meraki |
| No inter-VLAN segmentation (only the default allow-any rule) | Meraki |
| Workstations or servers with no Sophos agent (coverage gap) | Axonius / Meraki vs Sophos |
| Sophos health bad or suspicious, tamper protection off, endpoint stale | Sophos |
| Open high-severity Sophos alerts | Sophos |
| Offline Meraki devices, Sophos firewall disconnected from Central | Meraki / Sophos |

Rules are in `tm_diagrams/threats.py`. Each rule is a short block of code, so you can add your own.

## Setup in WSL Ubuntu

```bash
sudo apt update && sudo apt install -y python3 python3-venv python3-pip
cd threat-modeling
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env           # add API credentials (chmod 600 .env)
cp config.example.yaml config.yaml   # optional tuning
```

### Credentials (read-only is enough)

| Source | Where to create it | `.env` keys |
|---|---|---|
| Axonius | User menu → *Account settings* → *API Key* (use a read-only service account) | `AXONIUS_URL`, `AXONIUS_API_KEY`, `AXONIUS_API_SECRET`, optionally `AXONIUS_SAVED_QUERY` |
| Sophos Central | *Global Settings* → *API Credentials Management* → role **Service Principal Read-Only**. Tenant, partner and enterprise credentials all work | `SOPHOS_CLIENT_ID`, `SOPHOS_CLIENT_SECRET` |
| Meraki | *Organization* → *Settings* → enable API access, then *My profile* → *API keys* (a read-only org admin is enough) | `MERAKI_API_KEY`, optionally `MERAKI_ORG_IDS` |
| Lucid (optional) | Lucid developer portal → OAuth2 app or API key with `lucidchart.document.content` / DocumentCreate scope | `LUCID_API_TOKEN` |

## Usage

```bash
# Try it now with the bundled sample data (no credentials needed)
python -m tm_diagrams --demo

# Pull live data from all three sources
python -m tm_diagrams

# Pull only some sources, give the output a title, and upload straight to Lucidchart
python -m tm_diagrams --sources meraki,sophos --title "Corp Threat Model" --lucid-upload

# Rebuild the diagrams from a previous pull (no API calls), with more detail per VLAN
python -m tm_diagrams --offline output/20261101-090000/raw.json --max-nodes-per-zone 25
```

Each run writes to `output/<timestamp>/`. Run `python -m tm_diagrams -h` to see all options.

To schedule it, for example weekly from WSL cron, add:

```cron
0 6 * * 1 cd ~/threat-modeling && .venv/bin/python -m tm_diagrams >> output/cron.log 2>&1
```

## Getting the diagram into Lucidchart

1. **Recommended: import the .drawio file.** In Lucidchart choose *File → Import → draw.io (.drawio/.xml)* and
   select `threat_model.drawio`. Each page becomes a Lucid page, and the containers, colours and labels are kept.
2. **Native API upload.** `--lucid-upload` sends `threat_model.lucid` to `POST https://api.lucid.co/documents`
   (Standard Import) and logs the URL of the new document. You can also upload the `.lucid` file by hand
   (*Import → Lucid Standard Import*).
3. You can open the .drawio file in the draw.io desktop app or VS Code (Draw.io Integration extension) and
   export it as `.vsdx`, which Lucid also imports.

## Project layout

```
tm_diagrams/
  collectors/   axonius.py (axonius-api-client SDK), sophos.py (REST + OAuth2), meraki.py (meraki SDK)
  builder.py    correlates assets (MAC → hostname → IP), builds zones, nodes and flows
  threats.py    STRIDE rule engine → findings
  layout.py     deterministic nested-container layout shared by both exporters
  exporters/    drawio.py, lucid.py, report.py
  sample_data/  demo_raw.json (fictional data for --demo and the tests)
tests/          python tests/test_pipeline.py  (or pytest)
```

## Notes and limitations

* Assets are placed in VLANs using the Meraki client VLAN first and the IP/subnet match second. Assets that
  match neither (remote laptops, cloud VMs) go in *Remote / unmapped networks*.
* MX L3 *deny* rules are not drawn as flows. They feed the segmentation check instead. The default
  allow-any rule is only drawn when `include_default_rules: true` is set, because it adds a lot of noise.
* Large estates take a while to pull: Meraki `getNetworkClients` runs once per network. The meraki SDK
  handles rate limits (429) by itself, and the Sophos client retries on 429.
* `raw.json` holds inventory data (hostnames, IPs, MACs). Treat the `output/` folder as sensitive. It is git-ignored.
