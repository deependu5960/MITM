"""Packet capture worker — sniffs, normalizes, and queues records.

Uses scapy's AsyncSniffer so we don't lose packets between iterations.
No BPF filter by default (we capture everything on the lab interface and
let normalize() classify). Metadata only — no payload inspection.
"""
from __future__ import annotations
import logging
import queue
import threading
import time
from typing import Optional

from .models import PacketRecord

log = logging.getLogger("mitm.capture")


def _proto_name(pkt) -> str:
    try:
        from scapy.layers.l2 import ARP  # type: ignore
        from scapy.layers.inet import IP, TCP, UDP, ICMP  # type: ignore
        from scapy.layers.dns import DNS  # type: ignore
    except Exception:
        return "OTHER"

    if pkt.haslayer(ARP):
        return "ARP"
    if pkt.haslayer(DNS):
        return "DNS"
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    if pkt.haslayer(IP):
        return "IP"
    return "OTHER"


def _ports(pkt):
    try:
        from scapy.layers.inet import TCP, UDP  # type: ignore
        if pkt.haslayer(TCP):
            l = pkt[TCP]
            return int(l.sport), int(l.dport)
        if pkt.haslayer(UDP):
            l = pkt[UDP]
            return int(l.sport), int(l.dport)
    except Exception:
        pass
    return None, None


def _summary(pkt, proto: str, src_ip, dst_ip, sport, dport) -> str:
    """Short, metadata-only summary. No DNS query names, no payloads."""
    try:
        from scapy.layers.inet import TCP  # type: ignore
        if proto == "TCP" and pkt.haslayer(TCP):
            flags = int(pkt[TCP].flags)
            label = []
            if flags & 0x02: label.append("SYN")
            if flags & 0x10: label.append("ACK")
            if flags & 0x01: label.append("FIN")
            if flags & 0x04: label.append("RST")
            if flags & 0x08: label.append("PSH")
            flag_str = " ".join(label) or "TCP"
            return f"{flag_str} {src_ip}:{sport} -> {dst_ip}:{dport}"
        if proto == "DNS":
            return f"DNS {src_ip} -> {dst_ip}"
        if proto == "ARP":
            return f"ARP {pkt.summary()[:80]}"
        if proto in ("UDP", "ICMP", "IP"):
            port = f":{sport}->{dport}" if sport and dport else ""
            return f"{proto} {src_ip}{port} -> {dst_ip}"
    except Exception:
        pass
    return f"{proto} {src_ip} -> {dst_ip}"


def normalize(pkt) -> PacketRecord:
    proto = _proto_name(pkt)
    sport, dport = _ports(pkt)

    src_ip = dst_ip = None
    src_mac = dst_mac = None

    try:
        from scapy.layers.l2 import Ether, ARP  # type: ignore
        from scapy.layers.inet import IP  # type: ignore
        if pkt.haslayer(Ether):
            e = pkt[Ether]
            src_mac = getattr(e, "src", None)
            dst_mac = getattr(e, "dst", None)
        if pkt.haslayer(IP):
            ip = pkt[IP]
            src_ip = ip.src
            dst_ip = ip.dst
        elif pkt.haslayer(ARP):
            a = pkt[ARP]
            src_ip = a.psrc
            dst_ip = a.pdst
    except Exception:
        pass

    try:
        pkt_len = len(pkt)
    except Exception:
        pkt_len = 0

    return PacketRecord(
        ts=time.time(),
        src_mac=src_mac,
        dst_mac=dst_mac,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=proto,
        src_port=sport,
        dst_port=dport,
        length=pkt_len,
        summary=_summary(pkt, proto, src_ip, dst_ip, sport, dport),
    )


class PacketCapturer:
    """
    Wraps scapy's AsyncSniffer. Starts a background thread that receives
    every packet on the given interface and pushes normalized records into
    the output queue. Stops cleanly when stop() is called.
    """

    def __init__(self, iface: str, out_queue: "queue.Queue[PacketRecord]",
                 bpf: Optional[str] = None):
        self.iface = iface
        self.queue = out_queue
        self.bpf = bpf
        self._sniffer = None
        self._count = 0
        self._lock = threading.Lock()
        self._stopped = False

    @property
    def count(self) -> int:
        with self._lock:
            return self._count

    def _handle(self, pkt) -> None:
        try:
            rec = normalize(pkt)
        except Exception as e:
            log.debug("normalize failed: %s", e)
            return
        with self._lock:
            self._count += 1
        try:
            self.queue.put_nowait(rec)
        except queue.Full:
            try:
                self.queue.get_nowait()
                self.queue.put_nowait(rec)
            except Exception:
                pass

    def start(self) -> None:
        try:
            from scapy.all import AsyncSniffer  # type: ignore
        except Exception as e:
            log.error("scapy unavailable: %s", e)
            return

        try:
            kwargs = {
                "iface": self.iface,
                "prn": self._handle,
                "store": False,
            }
            if self.bpf:
                kwargs["filter"] = self.bpf
            self._sniffer = AsyncSniffer(**kwargs)
            self._sniffer.start()
            log.info("Packet capture started on iface=%s (bpf=%s)",
                     self.iface, self.bpf or "none")
        except Exception as e:
            log.error("sniff start failed: %s", e)
            self._sniffer = None

    def stop(self) -> None:
        if self._stopped:
            return
        self._stopped = True
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None
        log.info("Packet capture stopped (captured %d packets)", self.count)