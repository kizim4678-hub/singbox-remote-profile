#!/usr/bin/env python3
import argparse
import base64
import hashlib
import json
import re
import urllib.parse
import urllib.request
from typing import Dict, List, Tuple

DEFAULT_SOURCES: List[Tuple[str, str, int]] = [
    ("zieng2", "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt", 20),
    ("igareck_checked", "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/WHITE-CIDR-RU-checked.txt", 20),
    ("avencores_26", "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/githubmirror/26.txt", 12),
]
RESERVE_SOURCES: List[Tuple[str, str, int]] = [
    ("igareck_all", "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/WHITE-CIDR-RU-all.txt", 12),
]


def fetch_text(url: str, timeout: int = 30) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        charset = resp.headers.get_content_charset() or "utf-8"
        return resp.read().decode(charset, errors="replace")


def maybe_decode_base64(payload: str) -> str:
    s = payload.strip()
    if "://" in s or "\n" in s or "\r" in s:
        return payload
    if not re.fullmatch(r"[A-Za-z0-9+/=]+", s):
        return payload
    try:
        decoded = base64.b64decode(s + "===", validate=False).decode("utf-8", errors="replace")
        if "://" in decoded:
            return decoded
    except Exception:
        pass
    return payload


def normalize_lines(text: str) -> List[str]:
    text = maybe_decode_base64(text)
    out: List[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        out.append(line)
    return out


def safe_tag(name: str, link: str) -> str:
    name = re.sub(r"[^0-9A-Za-z._ -]+", "_", name or "node").strip() or "node"
    suffix = hashlib.sha1(link.encode()).hexdigest()[:8]
    return f"{name[:36]}_{suffix}"


def parse_host_port(hostport: str) -> Tuple[str, int]:
    if hostport.startswith("["):
        host, _, tail = hostport.partition("]")
        host = host + "]"
        if not tail.startswith(":"):
            raise ValueError("missing port")
        return host, int(tail[1:])
    host, port = urllib.parse.splitport(hostport)
    if not host or not port:
        raise ValueError("missing host/port")
    return host, int(port)


def build_vless_outbound(link: str) -> Dict:
    u = urllib.parse.urlsplit(link)
    if u.scheme != "vless" or "@" not in u.netloc:
        raise ValueError("not a VLESS link")
    userinfo, hostport = u.netloc.rsplit("@", 1)
    host, port = parse_host_port(hostport)
    params = dict(urllib.parse.parse_qsl(u.query, keep_blank_values=True))
    name = urllib.parse.unquote(u.fragment or host)

    outbound: Dict = {
        "type": "vless",
        "tag": safe_tag(name, link),
        "server": host.strip("[]"),
        "server_port": port,
        "uuid": userinfo,
    }

    flow = params.get("flow")
    if flow:
        outbound["flow"] = flow

    packet_encoding = params.get("packetEncoding") or params.get("packet_encoding")
    if packet_encoding in {"xudp", "packetaddr"}:
        outbound["packet_encoding"] = packet_encoding

    security = (params.get("security") or "").lower()
    if security in {"tls", "reality"}:
        tls: Dict = {"enabled": True}
        server_name = params.get("sni") or params.get("serverName") or params.get("host")
        if server_name:
            tls["server_name"] = server_name
        alpn = params.get("alpn")
        if alpn:
            tls["alpn"] = [x.strip() for x in alpn.split(",") if x.strip()]
        fp = params.get("fp") or params.get("fingerprint")
        if fp:
            tls["utls"] = {"enabled": True, "fingerprint": fp}
        if str(params.get("allowInsecure", "false")).lower() in {"1", "true", "yes", "on"}:
            tls["insecure"] = True
        if security == "reality":
            tls["reality"] = {"enabled": True}
            public_key = params.get("pbk") or params.get("publicKey")
            short_id = params.get("sid") or params.get("shortId")
            if public_key:
                tls["reality"]["public_key"] = public_key
            if short_id:
                tls["reality"]["short_id"] = short_id
        outbound["tls"] = tls

    network = (params.get("type") or params.get("transport") or "tcp").lower()
    if network == "ws":
        transport: Dict = {"type": "ws"}
        if params.get("path"):
            transport["path"] = params["path"]
        if params.get("host"):
            transport["headers"] = {"Host": params["host"]}
        outbound["transport"] = transport
    elif network == "grpc":
        transport = {"type": "grpc"}
        if params.get("serviceName"):
            transport["service_name"] = params["serviceName"]
        outbound["transport"] = transport
    elif network == "httpupgrade":
        transport = {"type": "httpupgrade"}
        if params.get("host"):
            transport["host"] = params["host"]
        if params.get("path"):
            transport["path"] = params["path"]
        outbound["transport"] = transport
    elif network == "http":
        transport = {"type": "http"}
        if params.get("host"):
            transport["host"] = [h.strip() for h in params["host"].split(",") if h.strip()]
        if params.get("path"):
            transport["path"] = params["path"]
        outbound["transport"] = transport

    return outbound


def collect_outbounds(include_reserve: bool) -> List[Dict]:
    sources = list(DEFAULT_SOURCES)
    if include_reserve:
        sources.extend(RESERVE_SOURCES)

    outbounds: List[Dict] = []
    seen_links = set()
    for source_name, url, limit in sources:
        added = 0
        text = fetch_text(url)
        for line in normalize_lines(text):
            if not line.startswith("vless://") or line in seen_links:
                continue
            try:
                outbound = build_vless_outbound(line)
            except Exception:
                continue
            outbound["tag"] = f"{source_name}_{outbound['tag']}"
            outbounds.append(outbound)
            seen_links.add(line)
            added += 1
            if added >= limit:
                break
    return outbounds


def build_config(outbounds: List[Dict], interval: str, tolerance: int, test_url: str) -> Dict:
    tags = [x["tag"] for x in outbounds]
    return {
        "log": {"level": "info"},
        "dns": {
            "servers": [
                {"tag": "local", "type": "local"},
                {
                    "tag": "dns-remote",
                    "type": "https",
                    "server": "1.1.1.1",
                    "server_port": 443,
                    "path": "/dns-query",
                },
            ],
            "rules": [
                {"clash_mode": "Direct", "server": "local"},
                {"clash_mode": "Global", "server": "dns-remote"},
            ],
            "final": "dns-remote",
        },
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "auto_route": True,
                "stack": "system",
                "sniff": True,
            }
        ],
        "outbounds": outbounds
        + [
            {
                "type": "urltest",
                "tag": "auto",
                "outbounds": tags,
                "url": test_url,
                "interval": interval,
                "tolerance": tolerance,
                "idle_timeout": "30m",
                "interrupt_exist_connections": True,
            },
            {
                "type": "selector",
                "tag": "select",
                "outbounds": ["auto"] + tags,
                "default": "auto",
                "interrupt_exist_connections": True,
            },
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"},
            {"type": "dns", "tag": "dns-out"},
        ],
        "route": {
            "auto_detect_interface": True,
            "override_android_vpn": True,
            "final": "select",
            "rules": [
                {"protocol": "dns", "outbound": "dns-out"},
                {
                    "domain": [
                        "connectivitycheck.gstatic.com",
                        "connectivitycheck.android.com",
                    ],
                    "outbound": "direct",
                },
            ],
        },
        "experimental": {"cache_file": {"enabled": True}},
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate sing-box Android remote profile")
    ap.add_argument("--output", default="dist/sing-box-android-whitelist.json")
    ap.add_argument("--interval", default="5m")
    ap.add_argument("--tolerance", type=int, default=120)
    ap.add_argument("--test-url", default="https://cp.cloudflare.com")
    ap.add_argument("--include-reserve", action="store_true")
    args = ap.parse_args()

    outbounds = collect_outbounds(include_reserve=args.include_reserve)
    config = build_config(outbounds, args.interval, args.tolerance, args.test_url)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)
        f.write("\n")

    meta = {
        "generated_from": [x[1] for x in (DEFAULT_SOURCES + (RESERVE_SOURCES if args.include_reserve else []))],
        "outbound_count": len(outbounds),
        "urltest_interval": args.interval,
        "urltest_tolerance_ms": args.tolerance,
        "test_url": args.test_url,
    }
    with open("dist/metadata.json", "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)
        f.write("\n")

    print(f"Wrote {args.output} with {len(outbounds)} outbounds")


if __name__ == "__main__":
    main()
