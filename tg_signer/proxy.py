"""Proxy subscription parsing and xray-core management."""

import base64
import json
import logging
import os
import shutil
import signal
import subprocess
import threading
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib import parse, request

logger = logging.getLogger("tg-signer.proxy")

LOCAL_SOCKS_PORT = 10808
LOCAL_SOCKS_ADDR = f"socks5://127.0.0.1:{LOCAL_SOCKS_PORT}"

# Global xray process reference
_xray_proc: Optional[subprocess.Popen] = None
_xray_lock = threading.Lock()


def fetch_subscription(url: str, timeout: int = 15) -> str:
    """Fetch and decode a base64 subscription URL."""
    req = request.Request(url, headers={"User-Agent": "ClashForAndroid/2.5"})
    with request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()

    text = raw.decode("utf-8", errors="ignore").strip()
    logger.info("Subscription raw length: %d chars", len(text))

    # If it already looks like protocol URIs, return as-is
    if any(text.startswith(p) for p in ("ss://", "vless://", "vmess://", "trojan://")):
        return text

    # Try base64 decode (remove whitespace/newlines from base64 block)
    try:
        clean = text.replace("\r", "").replace("\n", "").replace(" ", "")
        # Fix padding
        padding = 4 - len(clean) % 4
        if padding != 4:
            clean += "=" * padding
        decoded = base64.b64decode(clean).decode("utf-8", errors="ignore")
        logger.info("Decoded subscription: %d chars, first 100: %s", len(decoded), decoded[:100])
        return decoded
    except Exception as e:
        logger.warning("Base64 decode failed: %s, returning raw text", e)
        return text


def parse_subscription(raw: str) -> List[Dict]:
    """Parse subscription content into a list of proxy nodes."""
    nodes = []
    for line in raw.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        node = _parse_uri(line)
        if node:
            nodes.append(node)
        else:
            logger.debug("Skipped unrecognized line: %s", line[:80])
    logger.info("Parsed %d nodes from subscription", len(nodes))
    return nodes


def _parse_uri(uri: str) -> Optional[Dict]:
    """Parse a single proxy URI into a dict."""
    if uri.startswith("ss://"):
        return _parse_ss(uri)
    if uri.startswith("vless://"):
        return _parse_vless(uri)
    if uri.startswith("vmess://"):
        return _parse_vmess(uri)
    if uri.startswith("trojan://"):
        return _parse_trojan(uri)
    return None


def _parse_ss(uri: str) -> Optional[Dict]:
    """Parse ss:// URI."""
    try:
        # Format: ss://base64(method:password)@host:port#name
        rest = uri[5:]
        name = ""
        if "#" in rest:
            rest, name = rest.rsplit("#", 1)
            name = parse.unquote(name)

        # Some use base64(method:password@host:port)
        if "@" in rest:
            userinfo_b64, server_part = rest.rsplit("@", 1)
            host, port = server_part.rsplit(":", 1)
            # Decode userinfo
            try:
                userinfo = base64.b64decode(userinfo_b64 + "==").decode()
            except Exception:
                userinfo = userinfo_b64
            method, password = userinfo.split(":", 1)
        else:
            decoded = base64.b64decode(rest + "==").decode()
            method_pass, server = decoded.rsplit("@", 1)
            method, password = method_pass.split(":", 1)
            host, port = server.rsplit(":", 1)

        return {
            "protocol": "shadowsocks",
            "name": name,
            "host": host,
            "port": int(port),
            "method": method,
            "password": password,
        }
    except Exception as e:
        logger.debug("Failed to parse ss:// URI: %s", e)
        return None


def _parse_vless(uri: str) -> Optional[Dict]:
    """Parse vless:// URI."""
    try:
        parsed = parse.urlparse(uri)
        name = parse.unquote(parsed.fragment) if parsed.fragment else ""
        params = dict(parse.parse_qsl(parsed.query))
        return {
            "protocol": "vless",
            "name": name,
            "uuid": parsed.username,
            "host": parsed.hostname,
            "port": parsed.port,
            "security": params.get("security", "none"),
            "type": params.get("type", "tcp"),
            "flow": params.get("flow", ""),
            "sni": params.get("sni", ""),
            "pbk": params.get("pbk", ""),
            "sid": params.get("sid", ""),
            "fp": params.get("fp", ""),
            "path": params.get("path", ""),
            "serviceName": params.get("serviceName", ""),
            "_raw_params": params,
        }
    except Exception as e:
        logger.debug("Failed to parse vless:// URI: %s", e)
        return None


def _parse_vmess(uri: str) -> Optional[Dict]:
    """Parse vmess:// URI."""
    try:
        raw = base64.b64decode(uri[8:] + "==").decode()
        data = json.loads(raw)
        return {
            "protocol": "vmess",
            "name": data.get("ps", ""),
            "host": data.get("add", ""),
            "port": int(data.get("port", 0)),
            "uuid": data.get("id", ""),
            "alter_id": int(data.get("aid", 0)),
            "security": data.get("scy", "auto"),
            "net": data.get("net", "tcp"),
            "type": data.get("type", "none"),
            "tls": data.get("tls", ""),
            "sni": data.get("sni", ""),
            "path": data.get("path", ""),
            "host_header": data.get("host", ""),
        }
    except Exception as e:
        logger.debug("Failed to parse vmess:// URI: %s", e)
        return None


def _parse_trojan(uri: str) -> Optional[Dict]:
    """Parse trojan:// URI."""
    try:
        parsed = parse.urlparse(uri)
        name = parse.unquote(parsed.fragment) if parsed.fragment else ""
        params = dict(parse.parse_qsl(parsed.query))
        return {
            "protocol": "trojan",
            "name": name,
            "password": parsed.username,
            "host": parsed.hostname,
            "port": parsed.port,
            "sni": params.get("sni", parsed.hostname),
            "type": params.get("type", "tcp"),
        }
    except Exception as e:
        logger.debug("Failed to parse trojan:// URI: %s", e)
        return None


def node_to_xray_outbound(node: Dict) -> Dict:
    """Convert a parsed proxy node to an xray outbound config."""
    proto = node["protocol"]

    if proto == "shadowsocks":
        return {
            "tag": "proxy",
            "protocol": "shadowsocks",
            "settings": {
                "servers": [
                    {
                        "address": node["host"],
                        "port": node["port"],
                        "method": node["method"],
                        "password": node["password"],
                    }
                ]
            },
        }

    if proto == "vless":
        outbound = {
            "tag": "proxy",
            "protocol": "vless",
            "settings": {
                "vnext": [
                    {
                        "address": node["host"],
                        "port": node["port"],
                        "users": [
                            {
                                "id": node["uuid"],
                                "encryption": "none",
                                "flow": node.get("flow", ""),
                            }
                        ],
                    }
                ]
            },
        }
        # Stream settings
        stream = {"network": node.get("type", "tcp")}

        security = node.get("security", "none")
        if security == "reality":
            stream["security"] = "reality"
            stream["realitySettings"] = {
                "serverName": node.get("sni", ""),
                "fingerprint": node.get("fp", "chrome"),
                "publicKey": node.get("pbk", ""),
                "shortId": node.get("sid", ""),
                "spiderX": node.get("path", ""),
            }
        elif security == "tls":
            stream["security"] = "tls"
            stream["tlsSettings"] = {
                "serverName": node.get("sni", ""),
                "fingerprint": node.get("fp", "chrome"),
            }

        net = node.get("type", "tcp")
        if net == "ws":
            stream["wsSettings"] = {
                "path": node.get("path", "/"),
                "headers": {"Host": node.get("sni", "")},
            }
        elif net == "grpc":
            stream["grpcSettings"] = {
                "serviceName": node.get("serviceName", ""),
            }

        outbound["streamSettings"] = stream
        return outbound

    if proto == "vmess":
        outbound = {
            "tag": "proxy",
            "protocol": "vmess",
            "settings": {
                "vnext": [
                    {
                        "address": node["host"],
                        "port": node["port"],
                        "users": [
                            {
                                "id": node["uuid"],
                                "alterId": node.get("alter_id", 0),
                                "security": node.get("security", "auto"),
                            }
                        ],
                    }
                ]
            },
        }
        stream = {"network": node.get("net", "tcp")}
        if node.get("tls") == "tls":
            stream["security"] = "tls"
            stream["tlsSettings"] = {"serverName": node.get("sni", "")}

        net = node.get("net", "tcp")
        if net == "ws":
            stream["wsSettings"] = {
                "path": node.get("path", "/"),
                "headers": {"Host": node.get("host_header", "")},
            }
        outbound["streamSettings"] = stream
        return outbound

    if proto == "trojan":
        outbound = {
            "tag": "proxy",
            "protocol": "trojan",
            "settings": {
                "servers": [
                    {
                        "address": node["host"],
                        "port": node["port"],
                        "password": node["password"],
                    }
                ]
            },
            "streamSettings": {
                "network": node.get("type", "tcp"),
                "security": "tls",
                "tlsSettings": {"serverName": node.get("sni", node["host"])},
            },
        }
        return outbound

    raise ValueError(f"Unsupported protocol: {proto}")


def generate_xray_config(node: Dict, socks_port: int = LOCAL_SOCKS_PORT) -> Dict:
    """Generate a full xray config JSON for the selected node."""
    outbound = node_to_xray_outbound(node)
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "socks-in",
                "port": socks_port,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {"udp": True},
            }
        ],
        "outbounds": [
            outbound,
            {"tag": "direct", "protocol": "freedom"},
        ],
    }


def find_xray_binary() -> Optional[str]:
    """Find the xray binary."""
    # Check common locations
    for name in ["xray", "xray-core"]:
        path = shutil.which(name)
        if path:
            return path
    # Check /usr/local/bin explicitly
    for p in ["/usr/local/bin/xray", "/usr/bin/xray"]:
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


def start_xray(node: Dict) -> Tuple[bool, str]:
    """Start xray with the given node config. Returns (success, message)."""
    global _xray_proc

    xray_bin = find_xray_binary()
    if not xray_bin:
        return False, "未找到 xray 可执行文件，请确保已安装 xray-core"

    with _xray_lock:
        stop_xray()

        config = generate_xray_config(node)
        config_path = Path("/tmp/xray_config.json")
        config_path.write_text(json.dumps(config, indent=2))

        try:
            _xray_proc = subprocess.Popen(
                [xray_bin, "run", "-c", str(config_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            # Wait a moment to see if it starts
            import time

            time.sleep(1)
            if _xray_proc.poll() is not None:
                stderr = _xray_proc.stderr.read().decode(errors="ignore")
                return False, f"xray 启动失败: {stderr[:200]}"

            # Set TG_PROXY env var
            os.environ["TG_PROXY"] = LOCAL_SOCKS_ADDR
            logger.info(
                "xray started (pid=%d), proxy at %s",
                _xray_proc.pid,
                LOCAL_SOCKS_ADDR,
            )
            return True, f"代理已启动: {LOCAL_SOCKS_ADDR} (PID: {_xray_proc.pid})"

        except Exception as e:
            return False, f"启动 xray 失败: {e}"


def stop_xray() -> str:
    """Stop the running xray process."""
    global _xray_proc

    with _xray_lock:
        if _xray_proc and _xray_proc.poll() is None:
            try:
                _xray_proc.terminate()
                _xray_proc.wait(timeout=5)
            except Exception:
                _xray_proc.kill()
            _xray_proc = None
            os.environ.pop("TG_PROXY", None)
            return "代理已停止"
        _xray_proc = None
        return "无运行中的代理"


def is_xray_running() -> bool:
    """Check if xray is currently running."""
    return _xray_proc is not None and _xray_proc.poll() is None
