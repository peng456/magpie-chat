#!/usr/bin/env python3
"""magpie 聊天页：一个静态页 + 同源反代。

magpie 网关（默认 127.0.0.1:3425）不返回 CORS 头，所以浏览器里跨域直接调
/v1/chat/completions 会被拦。这里把页面和 /v1/* 放在同一个源下：页面照常带
Authorization: Bearer <网关 key>，服务端只做转发（不改也不保存 token）。

用法：
    python3 serve.py                 # http://127.0.0.1:8088
    python3 serve.py --port 9000     # 换端口
    python3 serve.py --lan           # 允许局域网访问（0.0.0.0）
    MAGPIE_GATEWAY=http://127.0.0.1:3425 python3 serve.py
"""

import argparse
import http.server
import ipaddress
import json
import os
import posixpath
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.dirname(os.path.abspath(__file__))
GATEWAY = os.environ.get("MAGPIE_GATEWAY", "http://127.0.0.1:3425").rstrip("/")
PROXY_PREFIX = "/v1/"
TOKEN_FILE = os.environ.get("MAGPIE_TOKEN_FILE", os.path.join(ROOT, ".token"))
LOCAL_ONLY = {"127.0.0.1", "::1", "::ffff:127.0.0.1"}
HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host", "content-length",
}
FORWARD_HEADERS = (
    "authorization", "x-api-key", "content-type", "accept",
    "anthropic-version", "anthropic-beta", "openai-beta", "user-agent",
)


def load_key():
    """服务端代持的网关 key：环境变量优先，其次 .token 文件。"""
    key = (os.environ.get("MAGPIE_TOKEN") or "").strip()
    if key:
        return key
    try:
        with open(TOKEN_FILE, "r", encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError:
        return ""


SERVER_KEY = load_key()
CORS_ORIGINS = []          # --cors 传入；空 = 不开跨域（同源页面用不到）


def cors_for(request_origin):
    """返回该放行的 Origin；没配或不在名单里返回 None。"""
    if not request_origin or not CORS_ORIGINS:
        return None
    if "*" in CORS_ORIGINS:
        return "*"
    for origin in CORS_ORIGINS:
        if request_origin.rstrip("/") == origin.rstrip("/"):
            return request_origin
    return None

DEFAULT_GATEWAY = GATEWAY
EXTRA_HOSTS = {
    h.strip().lower()
    for h in (os.environ.get("MAGPIE_GATEWAY_ALLOW") or "").split(",")
    if h.strip()
}
GATEWAY_HEADER = "X-Magpie-Gateway"
PRIVATE_PREFIXES = (
    "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "100.64.", "100.65.", "100.66", "127.", "169.254.",
)


def host_allowed(hostname):
    """只放行本机、私有网段、*.local 和显式白名单，避免变成开放代理。"""
    host = (hostname or "").strip().lower().strip("[]")
    if not host:
        return False
    if host in {"localhost", "::1"} or host.endswith(".local") or host in EXTRA_HOSTS:
        return True
    if any(host.startswith(prefix) for prefix in PRIVATE_PREFIXES):
        return True
    try:  # 域名解析到私有地址也放行（比如路由器给的主机名）
        import ipaddress
        for info in socket.getaddrinfo(host, None):
            addr = ipaddress.ip_address(info[4][0])
            if addr.is_loopback or addr.is_private:
                return True
    except Exception:
        pass
    return False


def pick_gateway(requested):
    """返回 (目标网关, 错误说明)。空 = 用服务端默认的那个。"""
    raw = (requested or "").strip()
    if not raw:
        return DEFAULT_GATEWAY, None
    from urllib.parse import urlsplit
    try:
        parts = urlsplit(raw if "://" in raw else "http://" + raw)
    except ValueError:
        return None, "地址不合法"
    if parts.scheme not in ("http", "https"):
        return None, "只支持 http/https"
    if not parts.hostname:
        return None, "地址里没有主机名"
    if not host_allowed(parts.hostname):
        return None, f"不允许连到 {parts.hostname}：只放行本机、局域网地址和 *.local"
    port = f":{parts.port}" if parts.port else ""
    path = parts.path.rstrip("/")
    return f"{parts.scheme}://{parts.hostname}{port}{path}", None


GATEWAY_PORT = 3425
SCAN_CACHE_SECONDS = 15
_scan_cache = {"at": 0.0, "payload": None}


def local_networks():
    """从 ifconfig 里拿非回环的 IPv4 网段；网段太大就只扫本机所在的 /24。"""
    found = []
    try:
        out = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=4).stdout
    except (OSError, subprocess.SubprocessError):
        return found
    for match in re.finditer(r"inet (\d+\.\d+\.\d+\.\d+) netmask (0x[0-9a-fA-F]+)", out):
        ip_raw, mask_raw = match.group(1), match.group(2)
        if ip_raw.startswith("127."):
            continue
        prefix = bin(int(mask_raw, 16)).count("1")
        network = ipaddress.ip_network(f"{ip_raw}/{prefix}", strict=False)
        if network.num_addresses > 512:
            network = ipaddress.ip_network(ip_raw + "/24", strict=False)
        found.append((ip_raw, network))
    return found


def probe_gateway(ip, token, port=GATEWAY_PORT):
    """先不带 key 探，只有对方自报 magpie 才拿 token 再试一次。"""
    def hit(with_token):
        headers = {"Accept": "application/json", "User-Agent": "magpie-chat/scan"}
        if with_token and token:
            headers["Authorization"] = "Bearer " + token
        req = urllib.request.Request(f"http://{ip}:{port}/", headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=0.5) as resp:
                return resp.status, resp.read(4096).decode("utf-8", "replace")
        except urllib.error.HTTPError as err:
            return err.code, err.read(4096).decode("utf-8", "replace")
        except Exception:
            return None, ""

    status, body = hit(False)
    if status is None or "magpie" not in body.lower():
        return None                      # 不是 magpie（或者根本没有服务）
    info = {"url": f"http://{ip}:{port}", "ip": ip, "authorized": status == 200,
            "version": "", "models": None, "needKey": status == 401}
    try:
        payload = json.loads(body)
        info["version"] = payload.get("version", "")
        info["models"] = payload.get("models")
    except ValueError:
        pass
    if status == 401 and token:
        status2, body2 = hit(True)
        if status2 == 200:
            try:
                payload = json.loads(body2)
                info.update(authorized=True, needKey=False, version=payload.get("version", ""),
                            models=payload.get("models"))
            except ValueError:
                info.update(authorized=True, needKey=False)
    return info


def discover(token):
    now = time.time()
    if _scan_cache["payload"] and now - _scan_cache["at"] < SCAN_CACHE_SECONDS:
        return _scan_cache["payload"]

    hosts, subnets, mine = [], [], set()
    for ip_raw, network in local_networks():
        subnets.append(str(network))
        mine.add(ip_raw)
        for addr in network.hosts():
            if str(addr) not in mine:
                hosts.append(str(addr))
    # 本机的默认网关也算一个候选
    default_host = urllib.parse.urlsplit(DEFAULT_GATEWAY).hostname or "127.0.0.1"
    if default_host in {"127.0.0.1", "localhost", "::1"}:
        hosts.insert(0, "127.0.0.1")
    elif default_host not in hosts:
        hosts.insert(0, default_host)

    found = []
    with ThreadPoolExecutor(max_workers=96) as pool:
        for info in pool.map(lambda ip: probe_gateway(ip, token), hosts):
            if info:
                found.append(info)
    found.sort(key=lambda item: (not item["authorized"], item["ip"]))

    payload = {"scanned": subnets, "hosts": len(hosts), "port": GATEWAY_PORT,
               "found": found, "at": time.strftime("%H:%M:%S")}
    _scan_cache.update(at=now, payload=payload)
    return payload


class Handler(http.server.BaseHTTPRequestHandler):
    # HTTP/1.0 + 不写 Content-Length：响应结束靠断连接，SSE 才能边收边显示。
    protocol_version = "HTTP/1.0"
    server_version = "magpie-chat/1.0"

    def log_message(self, fmt, *args):  # 安静一点，只留错误
        pass

    def _cors_headers(self):
        """给响应补上 CORS 头；只有配了 --cors 且 Origin 匹配时才加。"""
        allowed = cors_for(self.headers.get("Origin"))
        if not allowed:
            return
        self.send_header("Access-Control-Allow-Origin", allowed)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header(
            "Access-Control-Allow-Headers",
            "authorization, content-type, accept, x-api-key, x-magpie-gateway, anthropic-version",
        )
        self.send_header("Access-Control-Max-Age", "600")
        self.send_header("Vary", "Origin")

    # ---------- 代理 ----------

    def _proxy(self, method):
        target, why = pick_gateway(self.headers.get(GATEWAY_HEADER))
        if why:
            self._send_json(400, {"error": {"message": f"网关地址不可用：{why}"}})
            return

        length = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(length) if length else None

        headers = {}
        for name in FORWARD_HEADERS:
            value = self.headers.get(name)
            if value:
                headers[name.title()] = value

        # 只有默认网关才注入服务端那把 key；自定义地址必须自带 token，
        # 免得把 key 送到别人机器手里。
        if (SERVER_KEY and target == DEFAULT_GATEWAY
                and not (headers.get("Authorization") or headers.get("X-Api-Key"))):
            headers["Authorization"] = "Bearer " + SERVER_KEY

        url = target + self.path
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            resp = urllib.request.urlopen(req, timeout=600)
        except urllib.error.HTTPError as err:
            resp = err
        except Exception as err:  # 网关没起来之类
            self._send_json(502, {"error": {"message": f"上游 magpie 网关连不上：{err}"}})
            return

        self.send_response(resp.status)
        self.send_header("content-type", resp.headers.get("content-type", "application/json"))
        self.send_header("cache-control", "no-store")
        self.send_header("x-accel-buffering", "no")
        self._cors_headers()
        self.end_headers()
        try:
            while True:
                chunk = resp.read(8192)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass  # 浏览器关了页面/点了停止
        finally:
            resp.close()

    def _send_json(self, status, payload):
        import json
        data = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("cache-control", "no-store")
        self.send_header("content-length", str(len(data)))
        self._cors_headers()
        self.end_headers()
        self.wfile.write(data)

    # ---------- 静态页 ----------

    def _serve_static(self):
        path = urllib.request.url2pathname(self.path.split("?", 1)[0].split("#", 1)[0])
        if path in ("/", ""):
            path = "/index.html"
        clean = posixpath.normpath(path).lstrip("/")
        target = os.path.realpath(os.path.join(ROOT, clean))
        if not target.startswith(os.path.realpath(ROOT) + os.sep) or not os.path.isfile(target):
            self._send_json(404, {"error": {"message": "not found"}})
            return
        ctype = {
            ".html": "text/html; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".js": "text/javascript; charset=utf-8",
            ".svg": "image/svg+xml",
            ".png": "image/png",
            ".json": "application/json",
        }.get(os.path.splitext(target)[1].lower(), "application/octet-stream")
        with open(target, "rb") as handle:
            data = handle.read()
        self.send_response(200)
        self.send_header("content-type", ctype)
        self.send_header("cache-control", "no-cache")
        self.send_header("content-length", str(len(data)))
        self._cors_headers()
        self.end_headers()
        self.wfile.write(data)

    # ---------- 路由 ----------

    def do_GET(self):
        if self.path.startswith(PROXY_PREFIX):
            self._proxy("GET")
        elif self.path.split("?", 1)[0] == "/api/discover":
            token = ""
            auth = self.headers.get("Authorization") or ""
            if auth.lower().startswith("bearer "):
                token = auth[7:].strip()
            token = token or SERVER_KEY
            self._send_json(200, discover(token))
        elif self.path.split("?", 1)[0] == "/config.json":
            local = (self.client_address[0] or "").split("%")[0] in LOCAL_ONLY
            payload = {
                "gateway": DEFAULT_GATEWAY,
                "injected": bool(SERVER_KEY),
                # 只有本机才把 key 交给页面；局域网设备拿不到
                "token": SERVER_KEY if (local and SERVER_KEY) else "",
                "local": local,
            }
            self._send_json(200, payload)
        else:
            self._serve_static()

    def do_POST(self):
        if self.path.startswith(PROXY_PREFIX):
            self._proxy("POST")
        else:
            self._send_json(405, {"error": {"message": "只代理 /v1/*"}})

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("cache-control", "no-store")
        self._cors_headers()
        self.end_headers()


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def lan_addresses():
    ips = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.add(info[4][0])
    except OSError:
        pass
    try:  # 默认路由出口地址，最像"手机能连的那个"
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect(("8.8.8.8", 80))
        ips.add(probe.getsockname()[0])
        probe.close()
    except OSError:
        pass
    return sorted(ip for ip in ips if not ip.startswith("127."))


def main():
    parser = argparse.ArgumentParser(description="magpie chat 页面服务")
    parser.add_argument("--port", type=int, default=8088)
    parser.add_argument("--lan", action="store_true", help="监听 0.0.0.0，局域网可访问")
    parser.add_argument(
        "--cors", action="append", default=[], metavar="ORIGIN",
        help="允许跨域调用的页面来源，可重复或用逗号分隔（如 --cors https://peng456.github.io）",
    )
    args = parser.parse_args()

    for item in args.cors:
        CORS_ORIGINS.extend([piece.strip() for piece in item.split(",") if piece.strip()])
    host = "0.0.0.0" if args.lan else "127.0.0.1"
    try:
        httpd = Server((host, args.port), Handler)
    except OSError as err:
        print(f"端口 {args.port} 起不来：{err}", file=sys.stderr)
        sys.exit(1)

    shown = "127.0.0.1" if host == "0.0.0.0" else host
    print(f"magpie chat  →  http://{shown}:{args.port}", flush=True)
    if host == "0.0.0.0":
        for ip in lan_addresses():
            print(f"                http://{ip}:{args.port}", flush=True)
    print(f"上游网关     →  {GATEWAY}", flush=True)
    print(f"服务端代持 key →  {'yes（浏览器里不会出现）' if SERVER_KEY else 'no（.token 为空）'}", flush=True)
    if CORS_ORIGINS:
        print(f"允许跨域来源   →  {', '.join(CORS_ORIGINS)}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
