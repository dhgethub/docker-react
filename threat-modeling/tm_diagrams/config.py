"""Configuration: credentials from environment / .env, options from config.yaml."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    load_dotenv = None

DEFAULT_RISKY = [21, 22, 23, 25, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900,
                 5985, 5986, 6379, 9200, 27017]
DEFAULT_CLEARTEXT = [20, 21, 23, 25, 69, 80, 110, 143, 161, 389, 1883, 8080]


def _bool(v: str | None, default: bool = True) -> bool:
    if v is None or v == "":
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


@dataclass
class Config:
    output_dir: Path = Path("output")
    meraki_client_timespan_hours: int = 24
    max_nodes_per_zone: int = 8
    include_default_rules: bool = False
    risky_ports: list[int] = field(default_factory=lambda: list(DEFAULT_RISKY))
    cleartext_ports: list[int] = field(default_factory=lambda: list(DEFAULT_CLEARTEXT))
    stale_days: int = 14

    axonius_url: str = ""
    axonius_key: str = ""
    axonius_secret: str = ""
    axonius_saved_query: str = ""
    axonius_verify_ssl: bool = True

    sophos_client_id: str = ""
    sophos_client_secret: str = ""

    meraki_api_key: str = ""
    meraki_org_ids: list[str] = field(default_factory=list)

    lucid_api_token: str = ""

    @property
    def has_axonius(self) -> bool:
        return bool(self.axonius_url and self.axonius_key and self.axonius_secret)

    @property
    def has_sophos(self) -> bool:
        return bool(self.sophos_client_id and self.sophos_client_secret)

    @property
    def has_meraki(self) -> bool:
        return bool(self.meraki_api_key)


def load_config(config_path: str | None = None, env_file: str | None = None) -> Config:
    if load_dotenv:
        load_dotenv(env_file or ".env", override=False)

    cfg = Config()
    path = Path(config_path) if config_path else Path("config.yaml")
    if path.exists():
        if yaml is None:
            raise RuntimeError("PyYAML is required to read config.yaml (pip install PyYAML)")
        data = yaml.safe_load(path.read_text()) or {}
        for key, value in data.items():
            if hasattr(cfg, key):
                setattr(cfg, key, Path(value) if key == "output_dir" else value)
    elif config_path:
        raise FileNotFoundError(config_path)

    e = os.environ.get
    cfg.axonius_url = (e("AXONIUS_URL") or "").rstrip("/")
    cfg.axonius_key = e("AXONIUS_API_KEY", "")
    cfg.axonius_secret = e("AXONIUS_API_SECRET", "")
    cfg.axonius_saved_query = e("AXONIUS_SAVED_QUERY", "")
    cfg.axonius_verify_ssl = _bool(e("AXONIUS_VERIFY_SSL"), True)
    cfg.sophos_client_id = e("SOPHOS_CLIENT_ID", "")
    cfg.sophos_client_secret = e("SOPHOS_CLIENT_SECRET", "")
    cfg.meraki_api_key = e("MERAKI_API_KEY", "")
    cfg.meraki_org_ids = [o.strip() for o in (e("MERAKI_ORG_IDS") or "").split(",") if o.strip()]
    cfg.lucid_api_token = e("LUCID_API_TOKEN", "")
    return cfg
