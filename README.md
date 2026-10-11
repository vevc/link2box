# link2box

A lightweight CLI tool to parse proxy node links and convert them into clean, minimal [sing-box](https://github.com/SagerNet/sing-box) configuration files.

## Features

- **Supported Protocols**:
  - `vless` (TCP, WebSocket, gRPC, TLS, Reality)
  - `vmess` (TCP, WebSocket, gRPC, TLS)
  - `trojan` (TCP, WebSocket, gRPC, TLS, Reality)
  - `hysteria2` / `hy2` (QUIC, Salamander obfs)
  - `tuic` (QUIC, BBR congestion control, ALPN)
  - `anytls` (TLS, uTLS)
  - `shadowsocks` / `ss` (SIP002, Legacy, SIP003 plugins like `v2ray-plugin`)
  - `socks5` / `socks`
- **Minimal & Focused**:
  - Unified `mixed` inbound on `127.0.0.1:2080` (handles both HTTP and SOCKS5).
  - Automatic WebSocket path cleanup (strips Xray `?ed=2560` parameters to prevent 404 errors).

## Usage

```bash
# Print configuration directly to stdout
python link2box.py -p "vless://..."

# Save configuration to a file (default: sing-box-config.json)
python link2box.py -o config.json "trojan://..."

# Pipe from standard input
echo "vmess://..." | python link2box.py -p
```
