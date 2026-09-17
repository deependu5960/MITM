"""Orchestrates a scan: ping → ARP → multi-source hostname → vendor → type."""
from __future__ import annotations
import ipaddress
import logging
import platform
import re
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Set

from . import hostname as hostname_mod
from . import network, vendor


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("discovery")


_lock = threading.Lock()
_thread: Optional[threading.Thread] = None

_state: Dict = {
    "scanning": False,
    "stage": "idle",
    "devices": [],
    "last_scan": None,
    "error": None,
    "iface": None,
    "local_name": None,
    "progress": 0,
    "mdns_stats": {},
}


def get_state() -> Dict:
    with _lock:
        return {
            "scanning": _state["scanning"],
            "stage": _state["stage"],
            "devices": list(_state["devices"]),
            "last_scan": _state["last_scan"],
            "error": _state["error"],
            "iface": dict(_state["iface"]) if _state["iface"] else None,
            "local_name": _state["local_name"],
            "progress": _state["progress"],
            "mdns_stats": dict(_state["mdns_stats"]),
        }


def _set(stage: str = None, progress: int = None) -> None:
    with _lock:
        if stage is not None:
            _state["stage"] = stage
        if progress is not None:
            _state["progress"] = progress


# ---------------------------------------------------------------------------
# Ping + ARP
# ---------------------------------------------------------------------------
def _ping(ip: str, timeout_ms: int = 700) -> bool:
    system = platform.system().lower()
    try:
        cmd = (["ping", "-n", "1", "-w", str(timeout_ms), ip]
               if system == "windows"
               else ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip])
        r = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=(timeout_ms / 1000.0) + 0.5)
        return r.returncode == 0
    except Exception:
        return False


def _arp_table() -> Dict[str, str]:
    out_map: Dict[str, str] = {}
    system = platform.system().lower()
    try:
        if system == "windows":
            text = subprocess.check_output(["arp", "-a"], stderr=subprocess.DEVNULL,
                                           text=True, encoding="utf-8", errors="ignore")
            for line in text.splitlines():
                m = re.match(r"\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+", line)
                if m:
                    mac = m.group(2).replace("-", ":").upper()
                    if mac != "FF:FF:FF:FF:FF:FF":
                        out_map[m.group(1)] = mac
        else:
            try:
                text = subprocess.check_output(["ip", "neigh"], stderr=subprocess.DEVNULL,
                                               text=True)
            except Exception:
                text = subprocess.check_output(["arp", "-n"], stderr=subprocess.DEVNULL,
                                               text=True)
            for line in text.splitlines():
                m = re.match(r"(\d+\.\d+\.\d+\.\d+).*?([0-9a-fA-F:]{17})", line)
                if m:
                    out_map[m.group(1)] = m.group(2).upper()
    except Exception:
        pass
    return out_map


# ---------------------------------------------------------------------------
# The scan
# ---------------------------------------------------------------------------
def _run_scan() -> None:
    try:
        hostname_mod.clear_passive()

        iface = network.get_primary()
        if not iface:
            raise RuntimeError("No active network interface found.")

        with _lock:
            _state["iface"] = iface
            _state["local_name"] = network.local_hostname()

        local_ip = iface["ip"]
        cidr = iface["cidr"]
        local_name = network.local_hostname()

        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            raise RuntimeError(f"Invalid network: {cidr}")

        hosts = network.enumerate_hosts(cidr)

        # ---- Stage 1: passive mDNS listener (background) ----
        _set("Listening for device broadcasts", 10)
        listener = threading.Thread(
            target=hostname_mod.mdns_listen, kwargs={"duration": 12.0}, daemon=True,
        )
        listener.start()

        log.info("=" * 66)
        log.info("Scan started — network %s  local IP %s", cidr, local_ip)
        log.info("=" * 66)

        # ---- Stage 2: ping sweep ----
        _set("Pinging hosts", 25)
        live: List[str] = []
        with ThreadPoolExecutor(max_workers=96) as ex:
            for ip, ok in zip(hosts, ex.map(_ping, hosts)):
                if ok:
                    live.append(ip)
        log.info("Ping sweep: %d/%d hosts responded", len(live), len(hosts))

        # ---- Stage 3: send active mDNS probes to prod silent devices ----
        _set("Probing devices", 45)

        def _probe(ip: str) -> None:
            try:
                hostname_mod.query_mdns_active(ip, timeout=0.3)
            except Exception:
                pass

        with ThreadPoolExecutor(max_workers=64) as ex:
            list(ex.map(_probe, hosts))

        # ---- Stage 4: wait for passive listener ----
        _set("Collecting broadcasts", 60)
        listener.join(timeout=14.0)

        stats = hostname_mod.passive_stats()
        log.info("mDNS passive: packets=%d records=%d services=%d started=%s bind_error=%s",
                 stats.get("packets", 0),
                 stats.get("records", 0),
                 stats.get("services", 0),
                 stats.get("started", False),
                 stats.get("bind_error"))

        # ---- Stage 5: read ARP table ----
        _set("Reading ARP cache", 70)
        time.sleep(0.4)
        arp = _arp_table()
        log.info("ARP table: %d entries", len(arp))

        # ---- Merge all IP sources ----
        all_ips: Set[str] = set(live)
        for ip in arp:
            try:
                if ipaddress.ip_address(ip) in net:
                    all_ips.add(ip)
            except Exception:
                pass
        for ip in hostname_mod.get_passive():
            try:
                if ipaddress.ip_address(ip) in net:
                    all_ips.add(ip)
            except Exception:
                pass
        all_ips.add(local_ip)

        ordered = sorted(all_ips, key=lambda x: tuple(int(p) for p in x.split(".")))

        try:
            gateway = str(next(net.hosts()))
        except Exception:
            gateway = None

        # ---- Stage 6: resolve hostname for each device ----
        _set("Resolving hostnames", 85)

        def enrich(ip: str) -> Dict:
            mac = arp.get(ip)
            vend = vendor.lookup(mac)
            if vendor.is_randomized(mac) and vend == "Unknown":
                vend = "Randomized MAC"

            info = hostname_mod.resolve(ip, local_ip=local_ip, local_name=local_name)
            name = info["hostname"]
            services = info["services"]
            source = info["source"]
            trace = info.get("trace", {})

            # If no hostname but we do have service evidence, use a
            # service-derived category as the display name. This is
            # not a fake hostname — it's what the device itself broadcast.
            if not name and services:
                label = hostname_mod.label_from_services(services)
                if label:
                    name = label
                    source = "services"

            dev_type = hostname_mod.guess_type(
                name=name, services=services, vendor=vend,
                is_gateway=(ip == gateway), is_self=(ip == local_ip),
            )

            trace_str = " ".join(
                f"{k}={'YES' if v else 'no'}" for k, v in trace.items()
            )
            if name:
                log.info("  %-15s  ARP=%-17s  source=%-13s  name=%s",
                         ip, mac or "—", source, name)
            else:
                log.warning("  %-15s  ARP=%-17s  NO NAME  vendor=%s  type=%s",
                            ip, mac or "—", vend, dev_type)
            log.info("      trace: %s", trace_str)

            return {
                "ip": ip,
                "mac": mac,
                "hostname": name,
                "vendor": vend,
                "type": dev_type,
                "services": services,
                "name_source": source,
                "status": "online",
                "is_gateway": ip == gateway,
                "is_self": ip == local_ip,
                "last_seen": time.time(),
            }

        with ThreadPoolExecutor(max_workers=24) as ex:
            devices = list(ex.map(enrich, ordered))

        named = sum(1 for d in devices if d["hostname"])
        unknown = len(devices) - named
        log.info("-" * 66)
        log.info("Scan complete: %d devices, %d named, %d unknown",
                 len(devices), named, unknown)
        log.info("-" * 66)

        sources = {}
        for d in devices:
            sources[d["name_source"]] = sources.get(d["name_source"], 0) + 1
        log.info("Name source breakdown: %s", sources)

        with _lock:
            _state["devices"] = devices
            _state["last_scan"] = time.time()
            _state["error"] = None
            _state["stage"] = "idle"
            _state["progress"] = 100
            _state["mdns_stats"] = stats

    except Exception as e:
        log.exception("Scan failed")
        with _lock:
            _state["error"] = str(e)
            _state["last_scan"] = time.time()
            _state["stage"] = "idle"
            _state["progress"] = 0
    finally:
        with _lock:
            _state["scanning"] = False
        global _thread
        _thread = None


def start_scan() -> bool:
    global _thread
    with _lock:
        if _state["scanning"]:
            return False
        _state["scanning"] = True
        _state["error"] = None
        _state["stage"] = "starting"
        _state["progress"] = 0
    _thread = threading.Thread(target=_run_scan, daemon=True)
    _thread.start()
    return True