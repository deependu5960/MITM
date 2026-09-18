"""TCP interceptor proxy. Redirected victim TCP terminates here.

Reads the destination host from:
  - TLS ClientHello SNI (port 443)
  - HTTP Host header  (port 80)

Applies the rule engine, then either:
  - ALLOW -> open a socket to the real server, relay bytes
  - DENY  -> close the connection immediately
  - PAUSE -> hold the connection open until the user decides

Never decrypts TLS. Only reads the plaintext SNI / HTTP headers on the wire.
"""
from __future__ import annotations
import logging
import queue
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .stream import STREAM

log = logging.getLogger("mitm.proxy")


# =====================================================================
# Intercept session
# =====================================================================
@dataclass
class Intercept:
    id: int
    client_ip: str
    client_port: int
    hostname: Optional[str]
    dst_port: int
    proto: str                          # "HTTP" | "HTTPS"
    first_seen: float
    bytes: int = 0
    status: str = "pending"             # pending | forwarded | dropped | error
    resolved_at: Optional[float] = None
    sni_raw: Optional[str] = None
    http_method: Optional[str] = None
    http_path: Optional[str] = None
    http_headers: Optional[dict] = None
    reason: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "client_ip": self.client_ip,
            "client_port": self.client_port,
            "hostname": self.hostname,
            "dst_port": self.dst_port,
            "proto": self.proto,
            "first_seen": self.first_seen,
            "bytes": self.bytes,
            "status": self.status,
            "resolved_at": self.resolved_at,
            "sni_raw": self.sni_raw,
            "http_method": self.http_method,
            "http_path": self.http_path,
            "http_headers": self.http_headers,
            "reason": self.reason,
        }


# =====================================================================
# Parsers
# =====================================================================
def _read_tls_sni(buf: bytes) -> Optional[str]:
    """Extract SNI from a TLS ClientHello. Returns None if not present."""
    try:
        if len(buf) < 6 or buf[0] != 0x16 or buf[5] != 0x01:
            return None
        p = 5 + 4 + 2 + 32
        if p >= len(buf):
            return None
        sid_len = buf[p]; p += 1 + sid_len
        if p + 2 > len(buf):
            return None
        cs_len = int.from_bytes(buf[p:p+2], "big"); p += 2 + cs_len
        if p + 1 > len(buf):
            return None
        comp_len = buf[p]; p += 1 + comp_len
        if p + 2 > len(buf):
            return None
        ext_len = int.from_bytes(buf[p:p+2], "big"); p += 2
        end = min(p + ext_len, len(buf))
        while p + 4 <= end:
            etype = int.from_bytes(buf[p:p+2], "big")
            elen = int.from_bytes(buf[p+2:p+4], "big")
            p += 4
            if etype == 0x00 and p + elen <= len(buf) and elen >= 5:
                name_len = int.from_bytes(buf[p+3:p+5], "big")
                name = buf[p+5:p+5+name_len].decode("ascii", errors="ignore")
                if name:
                    return name.lower()
            p += elen
    except Exception:
        pass
    return None


def _read_http_headers(buf: bytes) -> Optional[dict]:
    """Parse the first HTTP request line + headers."""
    try:
        text = buf[:8192].decode("latin-1", errors="ignore")
        if "\r\n\r\n" not in text and "\n\n" not in text:
            return None
        lines = text.replace("\r\n", "\n").split("\n")
        if not lines:
            return None
        first = lines[0].split()
        if len(first) < 3:
            return None
        method, path, _ = first[0], first[1], first[2]
        headers = {}
        for line in lines[1:]:
            if not line:
                break
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        return {
            "method": method,
            "path": path,
            "headers": headers,
            "host": headers.get("host"),
        }
    except Exception:
        return None


# =====================================================================
# Proxy
# =====================================================================
class InterceptProxy:
    def __init__(self, listen_port: int, engine, on_new: callable = None):
        self.listen_port = listen_port
        self.engine = engine
        self.on_new = on_new
        self._stop = threading.Event()
        self._server: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._conn_lock = threading.Lock()
        self._next_id = 1
        self._intercepts: Dict[int, Intercept] = {}
        self._decisions: Dict[int, str] = {}   # id -> "forward" | "drop"

    # ------------------------------------------------------------------
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        try:
            if self._server:
                self._server.close()
        except Exception:
            pass
        # Release any paused connections
        with self._conn_lock:
            for iid in list(self._decisions.keys()):
                self._decisions[iid] = "drop"
            for iid, itc in self._intercepts.items():
                if itc.status == "pending":
                    itc.status = "dropped"
                    itc.reason = "session stopped"

    def _serve(self) -> None:
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", self.listen_port))
            srv.listen(128)
            self._server = srv
            log.info("Intercept proxy listening on port %d", self.listen_port)
        except Exception as e:
            log.error("Proxy bind failed: %s", e)
            return

        while not self._stop.is_set():
            try:
                srv.settimeout(0.5)
                client, addr = srv.accept()
            except socket.timeout:
                continue
            except Exception:
                break
            threading.Thread(
                target=self._handle,
                args=(client, addr),
                daemon=True,
            ).start()

    # ------------------------------------------------------------------
    def _handle(self, client: socket.socket, addr) -> None:
        itc: Optional[Intercept] = None
        upstream: Optional[socket.socket] = None
        try:
            # Read the original destination port via SO_ORIGINAL_DST (Linux NAT)
            orig_dst = self._original_dst(client)
            dst_port = orig_dst[1] if orig_dst else 443

            # Peek at the first bytes to identify hostname
            client.settimeout(4.0)
            try:
                head = client.recv(4096, socket.MSG_PEEK)
            except Exception:
                head = b""

            hostname = None
            proto = "HTTPS" if dst_port == 443 else "HTTP"
            sni_raw = None
            http_method = http_path = None
            http_headers = None

            if dst_port == 443:
                sni_raw = _read_tls_sni(head) if head else None
                hostname = sni_raw
            elif dst_port == 80:
                parsed = _read_http_headers(head) if head else None
                if parsed:
                    http_method = parsed.get("method")
                    http_path = parsed.get("path")
                    http_headers = parsed.get("headers")
                    hostname = parsed.get("host")

            with self._conn_lock:
                iid = self._next_id
                self._next_id += 1
                itc = Intercept(
                    id=iid,
                    client_ip=addr[0],
                    client_port=addr[1],
                    hostname=hostname,
                    dst_port=dst_port,
                    proto=proto,
                    first_seen=time.time(),
                    sni_raw=sni_raw,
                    http_method=http_method,
                    http_path=http_path,
                    http_headers=http_headers,
                )
                self._intercepts[iid] = itc

            # Publish to GUI
            STREAM.publish_intercept(itc.to_dict())

            # Decide
            action = self.engine.decide(hostname)
            if action == "pause":
                # Wait for user decision (with a generous timeout)
                deadline = time.time() + 300
                while time.time() < deadline and not self._stop.is_set():
                    with self._conn_lock:
                        decision = self._decisions.get(iid)
                    if decision:
                        break
                    time.sleep(0.1)
                with self._conn_lock:
                    decision = self._decisions.pop(iid, "drop")
                action = "allow" if decision == "forward" else "deny"

            if action == "deny":
                itc.status = "dropped"
                itc.resolved_at = time.time()
                itc.reason = "rule" if self.engine.decide(hostname) == "deny" else "user"
                STREAM.publish_intercept(itc.to_dict())
                try:
                    client.close()
                except Exception:
                    pass
                return

            # ALLOW — connect upstream
            upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            upstream.settimeout(6.0)
            upstream.connect((self._original_dst_ip(client) or hostname or "", dst_port))

            itc.status = "forwarded"
            itc.resolved_at = time.time()
            STREAM.publish_intercept(itc.to_dict())

            # Relay bytes both directions
            self._pipe(client, upstream, itc)
            self._pipe(upstream, client, itc)

        except Exception as e:
            log.debug("intercept handle error: %s", e)
            if itc:
                itc.status = "error"
                itc.reason = str(e)
                itc.resolved_at = time.time()
                STREAM.publish_intercept(itc.to_dict())
        finally:
            for s in (client, upstream):
                try:
                    if s:
                        s.close()
                except Exception:
                    pass
            if itc:
                STREAM.publish_intercept(itc.to_dict())

    def _pipe(self, a: socket.socket, b: socket.socket, itc: Intercept) -> None:
        try:
            while not self._stop.is_set():
                a.settimeout(1.0)
                try:
                    data = a.recv(65536)
                except socket.timeout:
                    continue
                except Exception:
                    break
                if not data:
                    break
                itc.bytes += len(data)
                try:
                    b.sendall(data)
                except Exception:
                    break
        except Exception:
            pass

    # ------------------------------------------------------------------
    def _original_dst(self, s: socket.socket) -> Optional[tuple]:
        """Read original destination IP:port via SO_ORIGINAL_DST (Linux NAT)."""
        try:
            SO_ORIGINAL_DST = 80
            dst = s.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
            port = struct.unpack(">H", dst[2:4])[0]
            ip = ".".join(str(b) for b in dst[4:8])
            return (ip, port)
        except Exception:
            return None

    def _original_dst_ip(self, s: socket.socket) -> Optional[str]:
        d = self._original_dst(s)
        return d[0] if d else None

    # ------------------------------------------------------------------
    def decide(self, intercept_id: int, action: str) -> bool:
        """Called by the API. action = 'forward' | 'drop'."""
        if action not in ("forward", "drop"):
            return False
        with self._conn_lock:
            if intercept_id not in self._intercepts:
                return False
            self._decisions[intercept_id] = action
        return True

    def forward_all_pending(self) -> int:
        with self._conn_lock:
            n = 0
            for iid, itc in self._intercepts.items():
                if itc.status == "pending":
                    self._decisions[iid] = "forward"
                    n += 1
            return n

    def drop_all_pending(self) -> int:
        with self._conn_lock:
            n = 0
            for iid, itc in self._intercepts.items():
                if itc.status == "pending":
                    self._decisions[iid] = "drop"
                    n += 1
            return n

    def snapshot(self, limit: int = 500) -> list:
        with self._conn_lock:
            items = sorted(self._intercepts.values(), key=lambda x: x.id, reverse=True)
            return [i.to_dict() for i in items[:limit]]

    def clear_history(self) -> None:
        with self._conn_lock:
            # Keep only pending
            self._intercepts = {k: v for k, v in self._intercepts.items()
                                 if v.status == "pending"}