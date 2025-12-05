#!/usr/bin/env python3
"""
Full Single-Port WebSocket TCP Proxy with DoH + HTTP
-----------------------------------------------------
Features equivalent to original JS version:
- Single port for HTTP ("/" => Hello World!, "/stats") and WebSocket /ech
- WS subprotocol TOKEN authentication
- CONNECT:host:port|payload format
- TCP full duplex proxy
- DoH resolving with cache + fallback CF_FALLBACK_IPS list
- No concurrent websocket receive crash

DNS/DoH 修復內容：
1) CF_FALLBACK_IPS 會過濾空字串，避免 env 空值導致 attempt="" 連線/解析崩潰
2) Cache 使用 expire_at（含 DoH TTL），避免 timestamp 不準與過期邏輯錯
3) DoH 回傳的 IP 會過濾 private/loopback/reserved 等非 public IP
4) 重用全域 aiohttp session，避免每次 resolve 建新 session
"""

import os
import asyncio
import json
import time
import logging
import ipaddress
import socket
from typing import Optional

import aiohttp
from websockets.server import WebSocketServerProtocol, serve


# ========= CONFIG =========
PORT = int(os.environ.get("PORT", "2832"))
TOKEN = os.environ.get("TOKEN", "")

# 修：過濾空字串/空白，避免 env 空時變成 [""] 造成 attempt=""
CF_FALLBACK_IPS = [
    ip.strip()
    for ip in os.environ.get("CF_FALLBACK_IPS", "").split(",")
    if ip.strip()
]

DOH_SERVERS = [
    "https://cloudflare-dns.com/dns-query",
    "https://1.1.1.1/dns-query",
    "https://dns.google/dns-query"
]

# cache: host -> {"ip": str, "expire_at": float}
DNS_CACHE_DEFAULT_TTL_MS = 300000  # fallback TTL
dns_cache = {}
dns_cache_lock = asyncio.Lock()

DOH_TIMEOUT_SEC = 5
TCP_CONNECT_TIMEOUT = 10

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s: %(message)s")
log = logging.getLogger("ws-tcp")

# 全域 aiohttp session（在 main() 初始化）
http_session: aiohttp.ClientSession | None = None


# ========= DNS via DoH =========
def _is_public_ip(ip: str) -> bool:
    """過濾掉私網/loopback/保留/多播等不該拿來連線的 IP。"""
    try:
        addr = ipaddress.ip_address(ip)
        return not (
            addr.is_private
            or addr.is_loopback
            or addr.is_multicast
            or addr.is_reserved
            or addr.is_link_local
            or addr.is_unspecified
        )
    except ValueError:
        return False


async def resolve_doh(host: str) -> str:
    """Resolve host to IPv4 using DoH with TTL cache + system fallback."""
    # 1) host 本身就是 IP -> 直接回
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass

    # 2) 檢查 cache
    now = time.time()
    async with dns_cache_lock:
        entry = dns_cache.get(host)
        if entry and now < entry["expire_at"]:
            log.info(f"[DoH Cache] {host} -> {entry['ip']}")
            return entry["ip"]
        elif entry:
            dns_cache.pop(host, None)

    # 3) DoH 查詢
    headers = {"accept": "application/dns-json"}
    session = http_session
    if session is None or session.closed:
        session = aiohttp.ClientSession()

    last_err = None
    for doh in DOH_SERVERS:
        url = f"{doh}?name={host}&type=A"
        try:
            async with session.get(url, headers=headers, timeout=DOH_TIMEOUT_SEC) as resp:
                if resp.status != 200:
                    last_err = RuntimeError(f"DoH status {resp.status}")
                    continue

                data = await resp.json()
                answers = data.get("Answer") or []

                chosen_ip = None
                chosen_ttl = None
                for ans in answers:
                    if ans.get("type") == 1:  # A record
                        ip = ans.get("data")
                        if ip and _is_public_ip(ip):
                            chosen_ip = ip
                            chosen_ttl = ans.get("TTL")
                            break

                if chosen_ip:
                    ttl_ms = (
                        int(chosen_ttl) * 1000
                        if isinstance(chosen_ttl, (int, float)) and chosen_ttl > 0
                        else DNS_CACHE_DEFAULT_TTL_MS
                    )
                    expire_at = time.time() + ttl_ms / 1000.0

                    async with dns_cache_lock:
                        dns_cache[host] = {"ip": chosen_ip, "expire_at": expire_at}

                    log.info(f"[DoH] {host} -> {chosen_ip} (ttl={ttl_ms}ms)")
                    return chosen_ip

        except Exception as e:
            last_err = e
            log.error(f"[DoH failed {doh}] {e}")

    # 4) 系統 DNS fallback（同樣挑 public IPv4）
    try:
        infos = await asyncio.get_event_loop().getaddrinfo(
            host, None, family=socket.AF_INET, type=socket.SOCK_STREAM
        )
        for info in infos:
            ip = info[4][0]
            if _is_public_ip(ip):
                expire_at = time.time() + DNS_CACHE_DEFAULT_TTL_MS / 1000.0
                async with dns_cache_lock:
                    dns_cache[host] = {"ip": ip, "expire_at": expire_at}
                log.info(f"[System DNS] {host} -> {ip}")
                return ip

        raise RuntimeError("no public A record")

    except Exception as e:
        raise RuntimeError(f"DNS failed: {host} ({last_err or e})")


# ========= WS TCP bridge =========
async def handle_tcp(websocket: WebSocketServerProtocol, target: str, first_payload: Optional[str]):
    host, port = target.rsplit(":", 1)
    port = int(port)

    # 先嘗試解析 host；失敗才用 fallback IP
    attempts = [host] + CF_FALLBACK_IPS
    reader = writer = None

    for attempt in attempts:
        try:
            ip = attempt
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                ip = await resolve_doh(attempt)

            log.info(f"[TCP] connect {ip}:{port}")
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=TCP_CONNECT_TIMEOUT
            )

            if first_payload:
                writer.write(first_payload.encode())
                await writer.drain()

            await websocket.send("CONNECTED")

            async def tcp_to_ws():
                try:
                    while True:
                        data = await reader.read(4096)
                        if not data:
                            break
                        await websocket.send(data)
                except Exception:
                    pass
                finally:
                    try:
                        await websocket.close()
                    except Exception:
                        pass

            asyncio.create_task(tcp_to_ws())
            return reader, writer

        except Exception as e:
            log.error(f"[TCP Error] {attempt}: {e}")

    raise RuntimeError("connect failed")


# ========= WebSocket Handler =========
async def ws_handler(websocket: WebSocketServerProtocol):
    if websocket.subprotocol != TOKEN:
        log.info("Reject: invalid token")
        await websocket.close(code=1008, reason="Bad token")
        return

    log.info("WS connected")

    remote_reader = remote_writer = None

    async for message in websocket:
        try:
            if isinstance(message, str):
                if message.startswith("CONNECT:"):
                    rest = message[8:]
                    if "|" in rest:
                        target, payload = rest.split("|", 1)
                    else:
                        target, payload = rest, None

                    remote_reader, remote_writer = await handle_tcp(websocket, target, payload)

                elif message == "CLOSE":
                    break

                elif remote_writer:
                    remote_writer.write(message.encode())
                    await remote_writer.drain()

            else:
                if remote_writer:
                    remote_writer.write(message)
                    await remote_writer.drain()

        except Exception as e:
            try:
                await websocket.send("ERROR: " + str(e))
            except Exception:
                pass
            break

    try:
        if remote_writer:
            remote_writer.close()
            await remote_writer.wait_closed()
    except Exception:
        pass

    log.info("WS closed")


# ========= HTTP Handler in same port =========
async def process_request(path, headers):
    if path == "/":
        return (200, [], b"Hello World!")
    if path == "/stats":
        async with dns_cache_lock:
            body = json.dumps({
                "cacheSize": len(dns_cache),
                "dohServers": DOH_SERVERS,
                "cacheKeys": list(dns_cache.keys())
            }).encode()
        return (200, [("Content-Type", "application/json")], body)
    return None


# ========= Main =========
async def main():
    global http_session
    http_session = aiohttp.ClientSession()

    log.info(f"Listening on :{PORT}  (HTTP + WS single port)")
    log.info(f"Token: {TOKEN}")

    try:
        async with serve(
            ws_handler,
            "0.0.0.0",
            PORT,
            process_request=process_request,
            subprotocols=[TOKEN],
            max_size=None
        ):
            await asyncio.Future()
    finally:
        if http_session and not http_session.closed:
            await http_session.close()


if __name__ == "__main__":
    asyncio.run(main())
