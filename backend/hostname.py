"""Multi-source hostname resolution with per-source debug output.

Order of sources (first hit wins):
  1. Passive mDNS listener  — catches phone / IoT broadcasts during scan.
  2. Active mDNS PTR        — asks directly.
  3. NetBIOS name query     — Windows PCs.
  4. LLMNR                  — modern Windows.
  5. Reverse DNS            — any device with PTR record.
  6. Local OS hostname      — for our own IP.

Never fabricates a name. If nothing answers, returns None and lets the UI
display "Unknown Device".
"""
from __future__ import annotations
import logging
import re
import socket
import struct
import threading
import time
from typing import Dict, List, Optional, Set, Tuple

log = logging.getLogger("hostname")

# ---------------------------------------------------------------------------
# Passive mDNS cache
# ---------------------------------------------------------------------------
_passive_lock = threading.Lock()
_passive: Dict[str, Dict[str, Set[str]]] = {}
_passive_stats = {"packets": 0, "records": 0, "bind_error": None, "started": False}


def _record_name(ip: str, name: str) -> None:
    name = name.strip().rstrip(".")
    if not name or name.startswith("_") or len(name) < 2:
        return
    if name.lower().endswith(".local"):
        name = name[:-6]
    if not name:
        return
    with _passive_lock:
        _passive.setdefault(ip, {"names": set(), "services": set()})["names"].add(name)
        _passive_stats["records"] += 1


def _record_service(ip: str, service: str) -> None:
    service = service.strip().rstrip(".")
    if not service:
        return
    with _passive_lock:
        _passive.setdefault(ip, {"names": set(), "services": set()})["services"].add(service)


def get_passive() -> Dict[str, Dict[str, List[str]]]:
    with _passive_lock:
        return {ip: {"names": list(v["names"]), "services": list(v["services"])}
                for ip, v in _passive.items()}


def clear_passive() -> None:
    with _passive_lock:
        _passive.clear()
        _passive_stats["packets"] = 0
        _passive_stats["records"] = 0


def passive_stats() -> Dict:
    with _passive_lock:
        return dict(_passive_stats)


# ---------------------------------------------------------------------------
# DNS name decoding (shared)
# ---------------------------------------------------------------------------
def _skip_name(data: bytes, off: int) -> int:
    for _ in range(128):
        if off >= len(data):
            return off
        n = data[off]
        if n == 0:
            return off + 1
        if n & 0xC0:
            return off + 2
        off += 1 + n
    return off


def _read_name(data: bytes, off: int) -> Tuple[Optional[str], int]:
    labels: List[str] = []
    jumped = False
    orig = off
    for _ in range(128):
        if off >= len(data):
            break
        n = data[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0:
            if off + 1 >= len(data):
                break
            ptr = ((n & 0x3F) << 8) | data[off + 1]
            if not jumped:
                orig = off + 2
                jumped = True
            off = ptr
            continue
        off += 1
        if off + n > len(data):
            break
        labels.append(data[off:off + n].decode("latin-1", errors="ignore"))
        off += n
    return (".".join(labels) or None), (orig if jumped else off)


# ---------------------------------------------------------------------------
# mDNS passive listener
# ---------------------------------------------------------------------------
def _parse_mdns(data: bytes, src_ip: str) -> None:
    try:
        if len(data) < 12:
            return
        flags, qd, an, ns, ar = struct.unpack(">HHHHH", data[2:12])
        if not (flags & 0x8000):
            return
        off = 12
        for _ in range(qd):
            off = _skip_name(data, off)
            off += 4
            if off >= len(data):
                return
        for _ in range(an + ns + ar):
            name, off = _read_name(data, off)
            if off + 10 > len(data):
                return
            rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            rdata = off
            end = off + rdlen
            if rtype == 1 and rdlen == 4:
                ip = ".".join(str(b) for b in data[rdata:end])
                if ip == src_ip and name:
                    _record_name(src_ip, name)
            elif rtype == 12:
                target, _ = _read_name(data, rdata)
                if target:
                    _record_service(src_ip, target)
            elif rtype == 33 and rdlen >= 6:
                target, _ = _read_name(data, rdata + 6)
                if target:
                    _record_name(src_ip, target)
            off = end
    except Exception:
        pass


def mdns_listen(duration: float = 8.0) -> None:
    """Passive mDNS listener — catches device broadcasts."""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except Exception:
            pass
        try:
            sock.bind(("", 5353))
        except OSError as e:
            with _passive_lock:
                _passive_stats["bind_error"] = f"{e.__class__.__name__}: {e}"
            log.warning("mDNS bind failed on UDP 5353: %s", e)
            log.warning("If avahi-daemon is running, stop it: sudo systemctl stop avahi-daemon")
            return
        mreq = struct.pack("4sl", socket.inet_aton("224.0.0.251"), socket.INADDR_ANY)
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        except OSError as e:
            with _passive_lock:
                _passive_stats["bind_error"] = f"multicast join failed: {e}"
            log.warning("multicast join failed: %s", e)
            return
        with _passive_lock:
            _passive_stats["started"] = True
        sock.settimeout(0.5)
        end = time.time() + duration
        while time.time() < end:
            try:
                data, addr = sock.recvfrom(9000)
                with _passive_lock:
                    _passive_stats["packets"] += 1
                _parse_mdns(data, addr[0])
            except socket.timeout:
                continue
            except Exception:
                continue
    except Exception as e:
        log.warning("mdns_listen fatal: %s", e)
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Active queries
# ---------------------------------------------------------------------------
def _ptr_query(ip: str, mcast: str, port: int, timeout: float) -> Optional[str]:
    try:
        rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
        qname = b""
        for label in rev.split("."):
            qname += bytes([len(label)]) + label.encode()
        qname += b"\x00"
        packet = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0) + qname + struct.pack(">HH", 12, 1)

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(packet, (mcast, port))
            data, _ = s.recvfrom(4096)
        finally:
            s.close()

        an = struct.unpack(">H", data[6:8])[0] if len(data) >= 8 else 0
        if an == 0:
            return None
        off = 12
        off = _skip_name(data, off)
        off += 4
        for _ in range(an):
            _name, off = _read_name(data, off)
            if off + 10 > len(data):
                return None
            rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            if rtype == 12:
                target, _ = _read_name(data, off)
                if target:
                    return target
            off += rdlen
    except Exception:
        return None
    return None


def query_mdns_active(ip: str, timeout: float = 0.8) -> Optional[str]:
    n = _ptr_query(ip, "224.0.0.251", 5353, timeout)
    if n:
        return n.replace(".local", "").replace(".local.", "")
    return None


def query_llmnr(ip: str, timeout: float = 0.6) -> Optional[str]:
    n = _ptr_query(ip, "224.0.0.252", 5355, timeout)
    if n:
        return n.replace(".local", "")
    return None


def query_netbios(ip: str, timeout: float = 0.6) -> Optional[str]:
    """NetBIOS name query via UDP 137."""
    try:
        tid = b"\xab\xcd"
        flags = b"\x01\x00"
        qd = b"\x00\x01"
        rest = b"\x00\x00\x00\x00\x00\x00"
        name = b"*" + b" " * 15
        enc = bytearray()
        for i in range(0, 32, 2):
            enc.append(((name[i] - 0x41) & 0x0F) << 4 | ((name[i + 1] - 0x41) & 0x0F))
        qname = bytes([32]) + bytes(enc) + b"\x00"
        packet = tid + flags + qd + rest + qname + b"\x00\x21" + b"\x00\x01"

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(packet, (ip, 137))
            data, _ = s.recvfrom(2048)
        finally:
            s.close()

        for i in range(len(data) - 18):
            chunk = data[i:i + 16]
            if chunk[15] == 0x00:
                nm = chunk[:15].decode("ascii", errors="ignore").strip()
                if nm and len(nm) >= 2 and all(32 <= ord(c) < 127 for c in nm):
                    if not nm.startswith("\x00") and not nm.startswith("*"):
                        return nm
    except Exception:
        return None
    return None


def query_reverse_dns(ip: str, timeout: float = 0.5) -> Optional[str]:
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        name, _, _ = socket.gethostbyaddr(ip)
        return name.rstrip(".") if name else None
    except Exception:
        return None
    finally:
        socket.setdefaulttimeout(old)


# ---------------------------------------------------------------------------
# Resolve — returns name + debug trace
# ---------------------------------------------------------------------------
def resolve(ip: str, local_ip: Optional[str] = None,
            local_name: Optional[str] = None, debug: bool = False) -> Dict:
    """
    Returns {
      "hostname": str | None,
      "services": [str],
      "source":   str,
      "trace":    { mdns_passive, mdns_active, netbios, llmnr, dns, local }
    }
    """
    trace = {
        "mdns_passive": False,
        "mdns_active": False,
        "netbios": False,
        "llmnr": False,
        "dns": False,
        "local": False,
    }

    # Own device
    if local_ip and ip == local_ip and local_name:
        trace["local"] = True
        return {"hostname": local_name, "services": [], "source": "local", "trace": trace}

    # 1. Passive mDNS cache
    with _passive_lock:
        entry = _passive.get(ip)
    services: List[str] = []
    if entry:
        services = list(entry.get("services", []))
        candidates = [n for n in entry.get("names", []) if n and not n.startswith("_")]
        if candidates:
            candidates.sort(key=len)
            trace["mdns_passive"] = True
            return {"hostname": candidates[0], "services": services,
                    "source": "mdns-passive", "trace": trace}

    # 2. Active mDNS
    n = query_mdns_active(ip)
    if n:
        trace["mdns_active"] = True
        return {"hostname": n, "services": services, "source": "mdns-active", "trace": trace}

    # 3. NetBIOS
    n = query_netbios(ip)
    if n:
        trace["netbios"] = True
        return {"hostname": n, "services": services, "source": "netbios", "trace": trace}

    # 4. LLMNR
    n = query_llmnr(ip)
    if n:
        trace["llmnr"] = True
        return {"hostname": n, "services": services, "source": "llmnr", "trace": trace}

    # 5. Reverse DNS
    n = query_reverse_dns(ip)
    if n:
        trace["dns"] = True
        return {"hostname": n, "services": services, "source": "dns", "trace": trace}

    return {"hostname": None, "services": services, "source": "none", "trace": trace}


# ---------------------------------------------------------------------------
# Device type from name + services + vendor
# ---------------------------------------------------------------------------
def guess_type(name: Optional[str], services: List[str], vendor: str,
               is_gateway: bool, is_self: bool) -> str:
    if is_self:
        return "This Device"
    if is_gateway:
        return "Router"

    n = (name or "").lower()
    v = (vendor or "").lower()
    svc = " ".join(services).lower()

    if "_googlecast" in svc:
        return "Chromecast"
    if "_airplay" in svc or "_raop" in svc or "_companion-link" in svc:
        return "Apple Device"
    if "_androidtvremote" in svc:
        return "Android TV"
    if "_ipp" in svc or "_printer" in svc or "_pdl-datastream" in svc:
        return "Printer"
    if "_spotify-connect" in svc:
        return "Speaker"
    if "_homekit" in svc:
        return "Smart Home"

    if any(k in n for k in ("iphone", "android", "galaxy", "pixel", "redmi",
                            "poco", "oneplus", "moto", "phone")):
        return "Phone"
    if "ipad" in n or "tablet" in n:
        return "Tablet"
    if any(k in n for k in ("macbook", "imac", "mac-mini", "mac-pro")):
        return "Mac"
    if any(k in n for k in ("laptop", "desktop", "pc-", "-pc",
                            "thinkpad", "inspiron", "latitude", "xps")):
        return "Computer"
    if any(k in n for k in ("printer", "hp-", "canon", "epson", "brother")):
        return "Printer"
    if any(k in n for k in ("tv", "roku", "firestick", "bravia", "webos")):
        return "TV"
    if any(k in n for k in ("nas", "synology", "qnap", "freenas")):
        return "NAS"
    if any(k in n for k in ("echo", "alexa", "nest", "homepod", "sonos")):
        return "Smart Home"
    if any(k in n for k in ("xbox", "playstation", "nintendo", "switch")):
        return "Console"
    if any(k in n for k in ("camera", "ipcam", "hikvision", "dahua")):
        return "Camera"

    if "apple" in v:
        return "Apple Device"
    if "samsung" in v or "xiaomi" in v or "huawei" in v:
        return "Mobile Device"
    if "raspberry" in v:
        return "Raspberry Pi"
    if any(x in v for x in ("vmware", "virtualbox", "qemu", "hyper-v")):
        return "Virtual Machine"
    if any(x in v for x in ("hp", "dell", "lenovo", "asus", "intel", "realtek")):
        return "Computer"
    if any(x in v for x in ("cisco", "netgear", "tp-link", "d-link")):
        return "Network Device"
    if any(x in v for x in ("epson", "canon", "brother")):
        return "Printer"

    return "Unknown"