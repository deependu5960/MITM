"""Packet capture worker — sniffs, normalizes, and queues records."""
from __future__ import annotations
import logging
import queue
import threading
import time
from typing import Optional

from .models import PacketRecord

log = logging.getLogger("mitm.capture")


def _proto_name(pkt) -> str:
    """Best-effort protocol label — metadata only, no payload inspection."""
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


def _ports(pkt) -> tuple[Optional[int], Optional[int]]:
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
    """
    Build a short metadata-only summary. We deliberately do NOT include
    DNS query names or TCP payload text — only flags and endpoints.
    """
    try:
        from scapy.layers.inet import TCP  # type: ignore
        if proto == "TCP" and pkt.haslayer(TCP):
            flags = pkt[TCP].flags
            label = []
            if flags & 0x02: label.append("SYN")
            if flags & 0x10: label.append("ACK")
            if flags & 0x01: label.append("FIN")
            if flags & 0x04: label.append("RST")
            flag_str = " ".join(label) or "TCP"
            return f"{flag_str} {src_ip}:{sport} -> {dst_ip}:{dport}"
        if proto == "DNS":
            return f"DNS {src_ip} -> {dst_ip}"
        if proto == "ARP":
            return f"ARP {pkt.summary()[:70]}"
        if proto in ("UDP", "ICMP", "IP"):
            port = f":{sport}->{dport}" if sport and dport else ""
            return f"{proto} {src_ip}{port} -> {dst_ip}"
    except Exception:
        pass
    return f"{proto} {src_ip} -> {dst_ip}"


def normalize(pkt) -> PacketRecord:
    """Turn a scapy packet into a PacketRecord — metadata only."""
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

    return PacketRecord(
        ts=time.time(),
        src_mac=src_mac,
        dst_mac=dst_mac,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=proto,
        src_port=sport,
        dst_port=dport,
        length=len(pkt),
        summary=_summary(pkt, proto, src_ip, dst_ip, sport, dport),
    )


class PacketCapturer(threading.Thread):
    """
    Sniffs on `iface` and pushes normalized PacketRecords into `out_queue`.
    Uses scapy's `sniff` with a stop_filter tied to a threading.Event so
    it exits promptly when asked to stop.
    """

    def __init__(self, iface: str, out_queue: "queue.Queue[PacketRecord]",
                 bpf: Optional[str] = None):
        super().__init__(daemon=True)
        self.iface = iface
        self.queue = out_queue
        self.bpf = bpf
        self._stop = threading.Event()
        self._count = 0

    def stop(self) -> None:
        self._stop.set()

    @property
    def count(self) -> int:
        return self._count

    def _handle(self, pkt) -> None:
        if self._stop.is_set():
            return
        try:
            rec = normalize(pkt)
        except Exception as e:
            log.debug("normalize failed: %s", e)
            return
        self._count += 1
        try:
            self.queue.put_nowait(rec)
        except queue.Full:
            # Drop oldest by popping one and re-inserting; keeps GUI current
            try:
                self.queue.get_nowait()
                self.queue.put_nowait(rec)
            except Exception:
                pass

    def run(self) -> None:
        log.info("Packet capture started on iface=%s", self.iface)
        try:
            from scapy.all import sniff  # type: ignore
        except Exception as e:
            log.error("scapy unavailable: %s", e)
            return

        try:
            sniff(
                iface=self.iface,
                prn=self._handle,
                store=False,
                stop_filter=lambda _: self._stop.is_set(),
                timeout=1,  # poll every 1s so stop works
            )
        except Exception as e:
            log.error("sniff error: %s", e)
        log.info("Packet capture stopped (captured %d packets)", self._count)