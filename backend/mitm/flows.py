"""Flow tracker — turns raw packets into per-destination session records.

Extracts:
  - DNS answers       -> ip -> hostname map
  - TLS SNI           -> hostname for the following TCP session
  - HTTP Host header  -> hostname for plain HTTP
  - Category keyword  -> friendly grouping for the Traffic tab

Does NOT decrypt anything and never reads payload beyond the handshake
fields that are already plaintext on the wire (SNI, HTTP Host).
"""
from __future__ import annotations
import logging
import threading
import time
from typing import Dict, Optional, Tuple

from .models import Flow

log = logging.getLogger("mitm.flows")

MAX_FLOWS = 200

CATEGORY_KEYWORDS = [
    ("search", ["google.", "bing.", "duckduckgo.", "yandex.", "baidu."]),
    ("streaming", ["youtube.", "youtu.be", "netflix.", "twitch.", "vimeo.",
                    "hotstar.", "primevideo.", "disneyplus.", "hulu."]),
    ("social", ["facebook.", "instagram.", "twitter.", "x.com", "tiktok.",
                 "snapchat.", "reddit.", "linkedin.", "pinterest."]),
    ("development", ["github.", "gitlab.", "bitbucket.", "stackoverflow.",
                      "npmjs.", "pypi.", "docker.", "npm.", "crates.io"]),
    ("shopping", ["amazon.", "ebay.", "flipkart.", "alibaba.", "aliexpress.",
                   "etsy.", "walmart.", "target."]),
    ("email", ["gmail.", "outlook.", "yahoo.", "protonmail.", "mail."]),
    ("messaging", ["whatsapp.", "telegram.", "signal.", "messenger.",
                    "discord.", "slack."]),
    ("music", ["spotify.", "soundcloud.", "music.apple.", "deezer.",
                "pandora."]),
    ("cloud", ["dropbox.", "drive.google.", "onedrive.", "icloud.",
                "mega.nz", "box.com"]),
    ("cdn", ["cloudflare.", "akamai.", "fastly.", "cloudfront.",
              "fbcdn.", "ggpht.", "googleusercontent."]),
    ("ads", ["doubleclick.", "adservice.", "adsystem.", "googlesyndication."]),
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


class FlowTracker:
    def __init__(self, victim_ip: str):
        self.victim_ip = victim_ip
        self._lock = threading.Lock()
        self._flows: Dict[str, Flow] = {}
        self._dns_cache: Dict[str, str] = {}       # ip -> hostname
        self._sni_cache: Dict[str, str] = {}       # ip -> hostname
        self._http_cache: Dict[str, str] = {}      # ip -> hostname

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def observe(self, pkt) -> Optional[Flow]:
        """
        Extract metadata from a scapy packet. Returns the updated Flow if
        the packet belongs to a tracked session, else None.
        """
        try:
            src_ip, dst_ip, sport, dport, proto = self._endpoints(pkt)
        except Exception:
            return None
        if not src_ip or not dst_ip:
            return None

        # Ignore packets not involving the victim
        if self.victim_ip not in (src_ip, dst_ip):
            return None

        # Ignore ARP / ICMP-only traffic — those are noise for this tab
        if proto not in ("TCP", "UDP", "DNS", "QUIC"):
            # Still parse DNS to update the cache
            if proto == "DNS":
                self._learn_dns(pkt, src_ip, dst_ip)
            return None

        # Parse protocol-specific metadata
        if proto == "DNS":
            self._learn_dns(pkt, src_ip, dst_ip)
            return None

        # SNI / HTTP Host extraction on first packet of each flow
        if proto == "TCP":
            self._maybe_learn_sni(pkt, dst_ip, dport)
            self._maybe_learn_http_host(pkt, dst_ip, dport)

        # Build / update flow
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
                hostname = (
                    self._sni_cache.get(remote_ip)
                    or self._http_cache.get(remote_ip)
                    or self._dns_cache.get(remote_ip)
                )
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
                f.hostname = (
                    self._sni_cache.get(remote_ip)
                    or self._http_cache.get(remote_ip)
                    or self._dns_cache.get(remote_ip)
                )
                if f.hostname:
                    f.category = _categorize(f.hostname)
            return Flow(**f.to_dict())

    def snapshot(self) -> list:
        with self._lock:
            flows = list(self._flows.values())
        # Sort by most recent activity
        flows.sort(key=lambda f: f.last_seen, reverse=True)
        return [f.to_dict() for f in flows]

    def flow_packets_key(self) -> Dict[str, str]:
        """Map of flow_key -> flow_key (helper for the GUI to filter packets)."""
        with self._lock:
            return {k: k for k in self._flows.keys()}

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _trim(self) -> None:
        if len(self._flows) <= MAX_FLOWS:
            return
        # Drop the oldest, least recently seen
        items = sorted(self._flows.items(), key=lambda kv: kv[1].last_seen)
        for k, _ in items[: len(self._flows) - MAX_FLOWS]:
            self._flows.pop(k, None)

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
            from scapy.layers.dns import DNS, DNSRR  # type: ignore
        except Exception:
            return
        try:
            if not pkt.haslayer(DNS):
                return
            dns = pkt[DNS]
            # Only answer records
            if dns.qr != 1:
                return
            # Extract answers
            answers = []
            rr = dns.an
            while rr is not None:
                try:
                    if rr.type == 1 and rr.rdata:  # A record
                        answers.append((str(rr.rdata), rr.rrname))
                except Exception:
                    pass
                rr = rr.payload if hasattr(rr, "payload") else None
                if rr is not None and not hasattr(rr, "type"):
                    break
            for ip, name in answers:
                hostname = name.decode(errors="ignore").rstrip(".") if isinstance(name, bytes) else str(name).rstrip(".")
                if hostname and ip:
                    self._dns_cache[ip] = hostname
        except Exception:
            pass

    def _maybe_learn_sni(self, pkt, ip: str, port: Optional[int]) -> None:
        """Parse TLS ClientHello SNI. Plaintext per RFC 6066."""
        if port not in (443, 8443):
            return
        try:
            from scapy.layers.inet import TCP  # type: ignore
            if not pkt.haslayer(TCP):
                return
            payload = bytes(pkt[TCP].payload)
            if len(payload) < 5:
                return
            # TLS record header: type(1) version(2) length(2)
            if payload[0] != 0x16:  # handshake
                return
            if payload[5] != 0x01:  # ClientHello
                return
            # Walk the ClientHello to the extensions
            # 4 (hs header) + 2 (version) + 32 (random) + sessid + ciphers + comps
            p = 5 + 4
            p += 2 + 32
            if p >= len(payload): return
            sid_len = payload[p]; p += 1 + sid_len
            if p + 2 > len(payload): return
            cs_len = int.from_bytes(payload[p:p+2], "big"); p += 2 + cs_len
            if p + 1 > len(payload): return
            comp_len = payload[p]; p += 1 + comp_len
            if p + 2 > len(payload): return
            ext_len = int.from_bytes(payload[p:p+2], "big"); p += 2
            end = p + ext_len
            while p + 4 <= end and p + 4 <= len(payload):
                etype = int.from_bytes(payload[p:p+2], "big")
                elen = int.from_bytes(payload[p+2:p+4], "big")
                p += 4
                if etype == 0x00 and p + elen <= len(payload):  # server_name
                    # list length (2) + type (1) + name length (2) + name
                    if elen >= 5:
                        name_len = int.from_bytes(payload[p+3:p+5], "big")
                        name = payload[p+5:p+5+name_len].decode("ascii", errors="ignore")
                        if name:
                            self._sni_cache[ip] = name.lower()
                            return
                p += elen
        except Exception:
            pass

    def _maybe_learn_http_host(self, pkt, ip: str, port: Optional[int]) -> None:
        """Read the Host header from plain HTTP requests. Port 80 only."""
        if port != 80:
            return
        try:
            from scapy.layers.inet import TCP  # type: ignore
            if not pkt.haslayer(TCP):
                return
            payload = bytes(pkt[TCP].payload)
            if not payload:
                return
            # Only try if it looks like an HTTP request line
            if not payload[:4] in (b"GET ", b"POST", b"HEAD", b"PUT ", b"DELE",
                                     b"OPTI", b"PATC"):
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