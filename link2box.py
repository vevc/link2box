import argparse
import base64
import json
import sys
import urllib.parse
from typing import Any, Dict


def fix_base64_padding(s: str) -> str:
    """Automatically fix Base64 padding."""
    return s + "=" * (-len(s) % 4)


def build_transport(
    net_type: str,
    raw_path: str = "/",
    host: str = "",
    service_name: str = "",
) -> Dict[str, Any]:
    """Build transport configuration, stripping query parameters like ?ed=xxxx from path."""
    if net_type == "grpc":
        return {
            "type": "grpc",
            "service_name": service_name or raw_path.lstrip("/"),
        }

    # Strip query parameters (like ?ed=2560) to avoid 404, keeping standard WebSocket handshake
    clean_path = (raw_path or "/").split("?", 1)[0] or "/"
    transport: Dict[str, Any] = {
        "type": net_type,
        "path": clean_path,
    }
    if host:
        transport["headers"] = {"Host": host}

    return transport


def is_insecure(params: Dict[str, Any]) -> bool:
    """Check if certificate validation should be skipped."""
    if params.get("verify_cert") is False:
        return True

    # Explicit insecure flags
    flags = (
        "insecure",
        "allowInsecure",
        "allow_insecure",
        "skip-cert-verify",
        "skip_cert_verify",
    )
    if any(str(params.get(k, "")).lower() in ("1", "true") for k in flags):
        return True

    # Certificate pinning parameters (e.g., hy2 pinSHA256, vless/trojan pcs)
    pin_keys = (
        "pinSHA256",
        "pinsha256",
        "pcs",
        "pinned-certchain-sha256",
        "pinned_certchain_sha256",
    )
    return any(bool(params.get(k)) for k in pin_keys)


def parse_vless(url_str: str) -> Dict[str, Any]:
    """Parse VLESS share link into sing-box outbound configuration."""
    url = urllib.parse.urlsplit(url_str)
    query = dict(urllib.parse.parse_qsl(url.query))

    outbound: Dict[str, Any] = {
        "type": "vless",
        "server": url.hostname,
        "server_port": url.port or 443,
        "uuid": url.username,
    }

    if flow := query.get("flow"):
        outbound["flow"] = flow

    # Transport layer
    net_type = query.get("type", "tcp")
    if net_type != "tcp":
        outbound["transport"] = build_transport(
            net_type=net_type,
            raw_path=query.get("path") or "/",
            host=query.get("host") or url.hostname or "",
            service_name=query.get("serviceName") or "",
        )

    # TLS / Reality
    security = query.get("security", "none")
    if security in ("tls", "reality"):
        tls_config: Dict[str, Any] = {
            "enabled": True,
            "server_name": query.get("sni")
            or query.get("host")
            or url.hostname,
            "insecure": is_insecure(query),
            "utls": {
                "enabled": True,
                "fingerprint": query.get("fp", "chrome"),
            },
        }
        if security == "reality":
            tls_config["reality"] = {
                "enabled": True,
                "public_key": query.get("pbk", ""),
                "short_id": query.get("sid", ""),
            }
        outbound["tls"] = tls_config

    return outbound


def parse_vmess(url_str: str) -> Dict[str, Any]:
    """Parse VMess share link into sing-box outbound configuration."""
    b64_content = url_str.removeprefix("vmess://")
    raw_json = base64.b64decode(fix_base64_padding(b64_content)).decode("utf-8")
    data = json.loads(raw_json)

    outbound: Dict[str, Any] = {
        "type": "vmess",
        "server": data.get("add"),
        "server_port": int(data.get("port", 443)),
        "uuid": data.get("id"),
        "security": data.get("scy") or "auto",
    }

    net = data.get("net", "tcp")
    if net != "tcp":
        outbound["transport"] = build_transport(
            net_type=net,
            raw_path=data.get("path") or "/",
            host=data.get("host") or data.get("add") or "",
            service_name=data.get("path") or "",
        )

    if data.get("tls") == "tls":
        outbound["tls"] = {
            "enabled": True,
            "server_name": data.get("sni")
            or data.get("host")
            or data.get("add"),
            "insecure": is_insecure(data),
            "utls": {
                "enabled": True,
                "fingerprint": data.get("fp", "chrome"),
            },
        }
    return outbound


def parse_trojan(url_str: str) -> Dict[str, Any]:
    """Parse Trojan share link into sing-box outbound configuration."""
    url = urllib.parse.urlsplit(url_str)
    query = dict(urllib.parse.parse_qsl(url.query))

    password = urllib.parse.unquote(url.username or url.password or "")

    outbound: Dict[str, Any] = {
        "type": "trojan",
        "server": url.hostname,
        "server_port": url.port or 443,
        "password": password,
    }

    # Transport layer
    net_type = query.get("type", "tcp")
    if net_type != "tcp":
        outbound["transport"] = build_transport(
            net_type=net_type,
            raw_path=query.get("path") or "/",
            host=query.get("host") or url.hostname or "",
            service_name=query.get("serviceName") or "",
        )

    # TLS / Reality
    tls_config: Dict[str, Any] = {
        "enabled": True,
        "server_name": query.get("sni")
        or query.get("host")
        or url.hostname,
        "insecure": is_insecure(query),
        "utls": {
            "enabled": True,
            "fingerprint": query.get("fp", "chrome"),
        },
    }

    if query.get("security") == "reality" or query.get("pbk"):
        tls_config["reality"] = {
            "enabled": True,
            "public_key": query.get("pbk", ""),
            "short_id": query.get("sid", ""),
        }

    if alpn := query.get("alpn"):
        tls_config["alpn"] = alpn.split(",")

    outbound["tls"] = tls_config

    return outbound


def parse_anytls(url_str: str) -> Dict[str, Any]:
    """Parse AnyTLS share link into sing-box outbound configuration."""
    url = urllib.parse.urlsplit(url_str)
    query = dict(urllib.parse.parse_qsl(url.query))

    password = urllib.parse.unquote(url.username or url.password or "")

    outbound: Dict[str, Any] = {
        "type": "anytls",
        "server": url.hostname,
        "server_port": url.port or 443,
        "password": password,
        "tls": {
            "enabled": True,
            "server_name": query.get("sni") or url.hostname,
            "insecure": is_insecure(query),
            "utls": {
                "enabled": True,
                "fingerprint": query.get("fp", "chrome"),
            },
        },
    }
    return outbound


def parse_hysteria2(url_str: str) -> Dict[str, Any]:
    """Parse Hysteria 2 share link into sing-box outbound configuration."""
    url = urllib.parse.urlsplit(url_str)
    query = dict(urllib.parse.parse_qsl(url.query))

    outbound: Dict[str, Any] = {
        "type": "hysteria2",
        "server": url.hostname,
        "server_port": url.port or 443,
        "password": url.username,
        "tls": {
            "enabled": True,
            "server_name": query.get("sni") or url.hostname,
            "insecure": is_insecure(query),
        },
    }
    if obfs := query.get("obfs"):
        outbound["obfs"] = {"type": "salamander", "password": obfs}
    return outbound


def parse_tuic(url_str: str) -> Dict[str, Any]:
    """Parse TUIC share link into sing-box outbound configuration."""
    url = urllib.parse.urlsplit(url_str)
    query = dict(urllib.parse.parse_qsl(url.query))

    user_info = urllib.parse.unquote(url.username or "")
    if ":" in user_info:
        uuid_val, password_val = user_info.split(":", 1)
    else:
        uuid_val = user_info
        password_val = urllib.parse.unquote(url.password or "")

    outbound: Dict[str, Any] = {
        "type": "tuic",
        "server": url.hostname,
        "server_port": url.port or 443,
        "uuid": uuid_val,
        "congestion_control": query.get("congestion_control", "bbr"),
    }
    if password_val:
        outbound["password"] = password_val

    tls_config: Dict[str, Any] = {
        "enabled": True,
        "server_name": query.get("sni") or url.hostname,
        "insecure": is_insecure(query),
    }
    if alpn := query.get("alpn"):
        tls_config["alpn"] = alpn.split(",")
    outbound["tls"] = tls_config

    return outbound


def parse_shadowsocks(url_str: str) -> Dict[str, Any]:
    """Parse Shadowsocks share link into sing-box outbound configuration."""
    content = url_str.removeprefix("ss://").split("#", 1)[0]

    if "?" in content:
        content, query_str = content.split("?", 1)
        query = dict(urllib.parse.parse_qsl(query_str))
    else:
        query = {}

    if "@" in content:
        user_info, host_port = content.split("@", 1)
        try:
            decoded = base64.b64decode(fix_base64_padding(user_info)).decode("utf-8")
        except Exception:
            decoded = urllib.parse.unquote(user_info)
        method, password = decoded.split(":", 1)
        server, port_str = host_port.rsplit(":", 1)
    else:
        decoded = base64.b64decode(fix_base64_padding(content)).decode("utf-8")
        user_info, host_port = decoded.rsplit("@", 1)
        method, password = user_info.split(":", 1)
        server, port_str = host_port.rsplit(":", 1)

    outbound: Dict[str, Any] = {
        "type": "shadowsocks",
        "server": server.strip("[]"),
        "server_port": int(port_str),
        "method": method,
        "password": password,
    }

    if plugin := query.get("plugin"):
        decoded_plugin = urllib.parse.unquote(plugin)
        plugin_name, _, plugin_opts = decoded_plugin.partition(";")
        outbound["plugin"] = plugin_name
        if plugin_opts:
            outbound["plugin_opts"] = plugin_opts

    return outbound


def parse_socks(url_str: str) -> Dict[str, Any]:
    """Parse SOCKS5 share link into sing-box outbound configuration."""
    url = urllib.parse.urlsplit(url_str)

    username = urllib.parse.unquote(url.username or "")
    password = urllib.parse.unquote(url.password or "")

    if username and not password:
        try:
            decoded = base64.b64decode(fix_base64_padding(username)).decode("utf-8")
            if ":" in decoded:
                username, password = decoded.split(":", 1)
        except Exception:
            pass

    outbound: Dict[str, Any] = {
        "type": "socks",
        "server": url.hostname,
        "server_port": url.port or 1080,
    }
    if username:
        outbound["username"] = username
    if password:
        outbound["password"] = password

    return outbound


def generate_sing_box_config(node_link: str) -> str:
    """Generate sing-box configuration from a proxy node link."""
    scheme = node_link.split("://", 1)[0].lower()

    parsers = {
        "vless": parse_vless,
        "vmess": parse_vmess,
        "trojan": parse_trojan,
        "anytls": parse_anytls,
        "hysteria2": parse_hysteria2,
        "hy2": parse_hysteria2,
        "tuic": parse_tuic,
        "shadowsocks": parse_shadowsocks,
        "ss": parse_shadowsocks,
        "socks": parse_socks,
        "socks5": parse_socks,
    }

    if scheme not in parsers:
        raise ValueError(f"Unsupported protocol: {scheme}")

    outbound = parsers[scheme](node_link)

    config = {
        "log": {"level": "info"},
        "inbounds": [
            {
                "type": "mixed",
                "listen": "127.0.0.1",
                "listen_port": 2080,
            },
        ],
        "outbounds": [
            outbound,
        ],
    }

    return json.dumps(config, indent=2, ensure_ascii=False)


def main() -> None:
    """CLI entry point for link2box."""
    parser = argparse.ArgumentParser(
        description="Parse proxy node link and generate sing-box configuration"
    )
    # Add positional or optional arguments
    parser.add_argument(
        "link",
        nargs="?",  # Optional positional argument
        help="Node link, e.g., 'vless://...', 'vmess://...', 'ss://...'",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="sing-box-config.json",
        help="Output configuration file path (default: sing-box-config.json)",
    )
    parser.add_argument(
        "-p", "--print", action="store_true", help="Print directly to stdout without writing to file"
    )
    args = parser.parse_args()
    # If no link is provided via command line, try reading from stdin (pipe)
    link = args.link
    if not link:
        if not sys.stdin.isatty():
            link = sys.stdin.read().strip()
        else:
            parser.error("Please provide a node link, or use -h for help")
    try:
        config_json = generate_sing_box_config(link)
        if args.print:
            print(config_json)
        else:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(config_json)
            print(f"[SUCCESS] Configuration file generated at: {args.output}")
    except Exception as e:
        print(f"[ERROR] Failed to generate configuration: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
