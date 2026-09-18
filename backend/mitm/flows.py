"""Flow tracker — turns raw packets into per-destination session records."""
from __future__ import annotations
import logging
import socket
import threading
import time
from typing import Dict, Optional, Tuple

from .models import Flow

log = logging.getLogger("mitm.flows")

MAX_FLOWS = 200
RDNS_TIMEOUT = 0.6

CATEGORY_KEYWORDS = [
    ("search", ["google.", "bing.", "duckduckgo.", "yandex.", "baidu."]),
    ("streaming", ["youtube.", "youtu.be", "googlevideo.", "ytimg.",
                    "netflix.", "nflxvideo.", "twitch.", "vimeo.",
                    "hotstar.", "primevideo.", "disneyplus.", "hulu."]),
    ("social", ["facebook.", "fbcdn.", "instagram.", "cdninstagram.",
                 "twitter.", "x.com", "tiktok.", "snapchat.", "reddit.",
                 "linkedin.", "pinterest."]),
    ("development", ["github.", "githubusercontent.", "gitlab.",
                      "bitbucket.", "stackoverflow.", "npmjs.", "pypi.",
                      "docker.", "npm.", "crates.io"]),
    ("shopping", ["amazon.", "media-amazon.", "ebay.", "flipkart.",
                   "alibaba.", "aliexpress.", "etsy.", "walmart."]),
    ("email", ["gmail.", "outlook.", "yahoo.", "protonmail.", "mail."]),
    ("messaging", ["whatsapp.", "whatsapp.net", "telegram.", "signal.",
                    "messenger.", "discord.", "slack."]),
    ("music", ["spotify.", "scdn.co", "soundcloud.", "music.apple.",
                "deezer.", "pandora."]),
    ("cloud", ["dropbox.", "drive.google.", "onedrive.", "icloud.",
                "mega.nz", "box.com"]),
    ("cdn", ["cloudflare.", "akamai.", "fastly.", "cloudfront.",
              "fbcdn.", "ggpht.", "googleusercontent.", "gstatic.",
              "googleapis."]),
    ("ads", ["doubleclick.", "adservice.", "adsystem.", "googlesyndication.",
              "googleadservices.", "googletagmanager."]),
    ("google", ["google.", "gstatic.", "1e100.net"]),
]

ORG_RANGES = [
    ("Google",     ["142.250.", "172.217.", "216.58.", "74.125.",
                     "64.233.", "108.177.", "173.194.", "209.85."]),
    ("Facebook",   ["157.240.", "31.13.", "179.60.", "129.134."]),
    ("Cloudflare", ["104.16.", "104.17.", "104.18.", "104.19.",
                     "172.64.", "172.65.", "162.159."]),
    ("Amazon",     ["52.", "54.", "13.32.", "13.33.", "13.224."]),
    ("Akamai",     ["23.32.", "23.33.", "104.80.", "104.96."]),
    ("Microsoft",  ["13.107.", "40.126.", "52.96.", "20."]),
    ("Apple",      ["17.", "23.61."]),
    ("Fastly",     ["151.101."]),
]


def _categorize(hostname: Optional[str]) -> str:
    if not hostname:
        return "unknown"
    h = hostname.lower()
    for cat, needles in CATEGORY_KEYWORDS:
        for n in needles:
            if n in h:
                return cat
    return "unknown"


def _org_for_ip(ip: str) -> Optional[str]:
    for org, prefixes in ORG_RANGES:
        for p in prefixes:
            if ip.startswith(p):
                return org
    return None


class FlowTracker:
    def __init__(self, victim_ip: str):
        self.victim_ip = victim_ip
        self._lock = threading.Lock()
        self._flows: Dict[str, Flow] = {}
        self._dns_cache: Dict[str, str] = {}
        self._sni_cache: Dict[str, str] = {}
        self._http_cache: Dict[str, str] = {}
        self._rdns_cache: Dict[str, Optional[str]] = {}
        self._rdns_pending: set = set()

    # ------------------------------------------------------------------
    def observe(self, pkt) -> Optional[Flow]:
        try:
            src_ip, dst_ip, sport, dport, proto = self._endpoints(pkt)
        except Exception:
            return None
        if not src_ip or not dst_ip:
            return None
        if self.victim_ip not in (src_ip, dst_ip):
            return None

        if proto == "DNS":
            self._learn_dns(pkt, src_ip, dst_ip)
            return None
        if proto not in ("TCP", "UDP", "QUIC"):
            return None

        if proto == "TCP":
            self._maybe_learn_sni(pkt, dst_ip, dport)
            self._maybe_learn_http_host(pkt, dst_ip, dport)

        if src_ip == self.victim_ip:
            direction = "outbound"
            remote_ip, remote_port = dst_ip, dport
        else:
            direction = "inbound"
            remote_ip, remote_port = src_ip, sport

        key = f"{remote_ip}:{remote_port}:{proto}"
        now = time.time()
        try:
            pkt_len = len(pkt)
        except Exception:
            pkt_len = 0

        with self._lock:
            f = self._flows.get(key)
            if f is None:
                hostname = self._name_for(remote_ip)
                f = Flow(
                    key=key, dst_ip=remote_ip, dst_port=remote_port,
                    protocol=proto, hostname=hostname,
                    category=_categorize(hostname),
                    first_seen=now, last_seen=now,
                    packets=0, bytes=0, direction=direction,
                )
                self._flows[key] = f
                self._trim()
            f.packets += 1
            f.bytes += pkt_len
            f.last_seen = now
            if f.hostname is None:
                n = self._name_for(remote_ip)
                if n:
                    f.hostname = n
                    f.category = _categorize(n)
            return Flow(**f.to_dict())

    def snapshot(self) -> list:
        with self._lock:
            flows = list(self._flows.values())
            for f in flows:
                if f.hostname is None:
                    n = self._name_for(f.dst_ip)
                    if n:
                        f.hostname = n
                        f.category = _categorize(n)
        flows.sort(key=lambda f: f.last_seen, reverse=True)
        return [f.to_dict() for f in flows]

    # ------------------------------------------------------------------
    def _name_for(self, ip: str) -> Optional[str]:
        n = (self._sni_cache.get(ip)
             or self._http_cache.get(ip)
             or self._dns_cache.get(ip))
        if n:
            return n
        if ip in self._rdns_cache:
            return self._rdns_cache[ip]
        org = _org_for_ip(ip)
        if org:
            self._schedule_rdns(ip)
            return f"{org} (unresolved)"
        self._schedule_rdns(ip)
        return None

    def _schedule_rdns(self, ip: str) -> None:
        if ip in self._rdns_cache or ip in self._rdns_pending:
            return
        self._rdns_pending.add(ip)
        t = threading.Thread(target=self._do_rdns, args=(ip,), daemon=True)
        t.start()

    def _do_rdns(self, ip: str) -> None:
        old = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(RDNS_TIMEOUT)
            name, _, _ = socket.gethostbyaddr(ip)
            if name:
                self._rdns_cache[ip] = name.rstrip(".")
            else:
                self._rdns_cache[ip] = None
        except Exception:
            self._rdns_cache[ip] = None
        finally:
            socket.setdefaulttimeout(old)
            self._rdns_pending.discard(ip)

    def _trim(self) -> None:
        if len(self._flows) <= MAX_FLOWS:
            return
        items = sorted(self._flows.items(), key=lambda kv: kv[1].last_seen)
        for k, _ in items[: len(self._flows) - MAX_FLOWS]:
            self._flows.pop(k, None)

    # ------------------------------------------------------------------
    def _endpoints(self, pkt) -> Tuple[Optional[str], Optional[str],
                                        Optional[int], Optional[int], str]:
        from scapy.layers.inet import IP, TCP, UDP  # type: ignore
        from scapy.layers.dns import DNS  # type: ignore

        src_ip = dst_ip = None
        sport = dport = None
        proto = "OTHER"

        if pkt.haslayer(IP):
            ip = pkt[IP]
            src_ip = ip.src
            dst_ip = ip.dst

        if pkt.haslayer(DNS):
            proto = "DNS"
        elif pkt.haslayer(TCP):
            proto = "TCP"
            l = pkt[TCP]
            sport = int(l.sport)
            dport = int(l.dport)
        elif pkt.haslayer(UDP):
            proto = "UDP"
            l = pkt[UDP]
            sport = int(l.sport)
            dport = int(l.dport)

        return src_ip, dst_ip, sport, dport, proto

    def _learn_dns(self, pkt, src_ip: str, dst_ip: str) -> None:
        try:
            from scapy.layers.dns import DNS  # type: ignore
        except Exception:
            return
        try:
            if not pkt.haslayer(DNS):
                return
            dns = pkt[DNS]
            if dns.qr != 1:
                return
            rr = dns.an
            count = 0
            while rr is not None and count < 30:
                count += 1
                try:
                    rtype = getattr(rr, "type", None)
                    if rtype == 1 and getattr(rr, "rdata", None):
                        ip = str(rr.rdata)
                        nm = rr.rrname
                        if isinstance(nm, bytes):
                            nm = nm.decode(errors="ignore")
                        nm = str(nm).rstrip(".")
                        if nm and ip:
                            self._dns_cache[ip] = nm
                except Exception:
                    pass
                if not hasattr(rr, "payload"):
                    break
                rr = rr.payload
        except Exception:
            pass

    def _maybe_learn_sni(self, pkt, ip: str, port: Optional[int]) -> None:
        if port not in (443, 8443):
            return
        try:
            from scapy.layers.inet import TCP  # type: ignore
            if not pkt.haslayer(TCP):
                return
            payload = bytes(pkt[TCP].payload)
            if len(payload) < 6:
                return
            if payload[0] != 0x16 or payload[5] != 0x01:
                return
            p = 5 + 4 + 2 + 32
            if p >= len(payload):
                return
            sid_len = payload[p]; p += 1 + sid_len
            if p + 2 > len(payload):
                return
            cs_len = int.from_bytes(payload[p:p+2], "big"); p += 2 + cs_len
            if p + 1 > len(payload):
                return
            comp_len = payload[p]; p += 1 + comp_len
            if p + 2 > len(payload):
                return
            ext_len = int.from_bytes(payload[p:p+2], "big"); p += 2
            end = min(p + ext_len, len(payload))
            while p + 4 <= end:
                etype = int.from_bytes(payload[p:p+2], "big")
                elen = int.from_bytes(payload[p+2:p+4], "big")
                p += 4
                if etype == 0x00 and p + elen <= len(payload) and elen >= 5:
                    name_len = int.from_bytes(payload[p+3:p+5], "big")
                    name = payload[p+5:p+5+name_len].decode("ascii", errors="ignore")
                    if name:
                        self._sni_cache[ip] = name.lower()
                        return
                p += elen
        except Exception:
            pass

    def _maybe_learn_http_host(self, pkt, ip: str, port: Optional[int]) -> None:
        if port != 80:
            return
        try:
            from scapy.layers.inet import TCP  # type: ignore
            if not pkt.haslayer(TCP):
                return
            payload = bytes(pkt[TCP].payload)
            if not payload:
                return
            if payload[:4] not in (b"GET ", b"POST", b"HEAD", b"PUT ",
                                     b"DELE", b"OPTI", b"PATC"):
                return
            text = payload[:4096].decode("latin-1", errors="ignore")
            for line in text.split("\r\n"):
                if line.lower().startswith("host:"):
                    host = line.split(":", 1)[1].strip()
                    if host:
                        self._http_cache[ip] = host.lower()
                        return
        except Exception:
            pass