"""Colours shared by exporters (DFD conventions: dashed red trust boundaries)."""
SEV_COLOR = {"critical": "#B20000", "high": "#E0301E", "medium": "#F28E1C", "low": "#C9A800", "info": "#6C8EBF"}

ZONE_STYLE = {   # kind: (fill, stroke)
    "internet": ("#FDECEA", "#B85450"),
    "cloud": ("#FFF4E5", "#D79B00"),
    "site": ("#F3F7FB", "#B85450"),
    "vlan": ("#FFFFFF", "#B85450"),
    "other": ("#F5F5F5", "#B85450"),
}
NODE_STYLE = {   # kind: (fill, stroke)
    "external": ("#DAE8FC", "#6C8EBF"),
    "process": ("#D5E8D4", "#82B366"),
    "device": ("#E1D5E7", "#9673A6"),
    "asset": ("#FFFFFF", "#666666"),
    "asset_group": ("#F8F8F8", "#666666"),
    "datastore": ("#FFF2CC", "#D6B656"),
}
FLOW_COLOR = {"data": "#333333", "mgmt": "#7F7F7F", "vpn": "#2E75B6", "inbound": "#B20000", "routed": "#999999"}
