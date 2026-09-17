"""Multi-source hostname resolution.

Sources (in the order the final answer is decided):
  1. Passive mDNS listener (during scan) — catches phone/IoT broadcasts.
  2. Active mDNS PTR query                — asks printers/Macs/some phones.
  3. NetBIOS name query (UDP 137)         — Windows PCs.
  4. LLMNR query (UDP 5355)               — modern Windows.
  5. Reverse DNS                          — any device with PTR record.
  6. Local machine's own name             — for our own IP.

The passive listener is what makes phones appear. Without it, phones that
never answer an active query stay invisible. This mirrors what Bettercap
does in net.probe.
"""
from __future__ import annotations
import re
import socket
import struct
import threading
import time
from typing import Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Shared passive cache — filled by the listener while scanning
# ---------------------------------------------------------------------------
_passive_lock = threading.Lock()
_passive: Dict[str, Dict[str, Set[str]]] = {}


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


# ---------------------------------------------------------------------------
# DNS name decoder (used by mDNS + LLMNR parsers)
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
    return ".".join(labels) or None, (orig if jumped else off)


# ---------------------------------------------------------------------------
# mDNS passive listener — the fix for missing phone names
# ---------------------------------------------------------------------------
def _parse_mdns(data: bytes, src_ip: str) -> None:
    try:
        if len(data) < 12:
            return
        flags, qd, an, ns, ar = struct.unpack(">HHHHH", data[2:12])
        if not (flags & 0x8000):
            return  # not a response
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


def mdns_listen(duration: float = 6.0) -> None:
    """Listen to mDNS multicast for `duration` seconds, populating the cache."""
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
        except OSError:
            return  # port in use — best effort
        mreq = struct.pack("4sl", socket.inet_aton("224.0.0.251"), socket.INADDR_ANY)
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        except OSError:
            return  # no multicast on this interface
        sock.settimeout(0.5)
        end = time.time() + duration
        while time.time() < end:
            try:
                data, addr = sock.recvfrom(9000)
                _parse_mdns(data, addr[0])
            except socket.timeout:
                continue
            except Exception:
                continue
    except Exception:
        pass
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
        packet = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0)
        packet += qname + struct.pack(">HH", 12, 1)

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
        for _ in range(1):
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


def query_mdns(ip: str, timeout: float = 0.8) -> Optional[str]:
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
    try:
        tid = b"\xab\xcd"; flags = b"\x01\x00"; qd = b"\x00\x01"
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
                    return nm
    except Exception:
        return None
    return None


def query_reverse_dns(ip: str, timeout: float = 0.4) -> Optional[str]:
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
# Public: resolve one IP to its best name + extra info
# ---------------------------------------------------------------------------
def resolve(ip: str, local_ip: Optional[str] = None,
            local_name: Optional[str] = None) -> Dict:
    """
    Returns:
      {
        "hostname": str | None,
        "services": [str],
        "source":   str  # which method produced the name (for transparency)
      }
    """
    # Own device — use OS hostname directly
    if local_ip and ip == local_ip and local_name:
        return {"hostname": local_name, "services": [], "source": "local"}

    # 1. Passive cache first — this is where phone names come from
    with _passive_lock:
        entry = _passive.get(ip)
    services: List[str] = []
    if entry:
        services = list(entry.get("services", []))
        candidates = [n for n in entry.get("names", []) if n and not n.startswith("_")]
        if candidates:
            candidates.sort(key=len)
            return {"hostname": candidates[0], "services": services, "source": "mdns-passive"}

    # 2. Active mDNS
    n = query_mdns(ip)
    if n:
        return {"hostname": n, "services": services, "source": "mdns-active"}

    # 3. NetBIOS (Windows PCs)
    n = query_netbios(ip)
    if n:
        return {"hostname": n, "services": services, "source": "netbios"}

    # 4. LLMNR
    n = query_llmnr(ip)
    if n:
        return {"hostname": n, "services": services, "source": "llmnr"}

    # 5. Reverse DNS
    n = query_reverse_dns(ip)
    if n:
        return {"hostname": n, "services": services, "source": "dns"}

    # 6. Nothing — return services (may help type inference) but no name
    return {"hostname": None, "services": services, "source": "none"}


# ---------------------------------------------------------------------------
# Guess device type from name + services + vendor
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

    # Service-based evidence first (strongest)
    if "_googlecast" in svc:
        return "Chromecast"
    if "_airplay" in svc or "_raop" in svc:
        return "Apple Device"
    if "_companion-link" in svc:
        return "Apple Device"
    if "_androidtvremote" in svc:
        return "Android TV"
    if "_ipp" in svc or "_printer" in svc or "_pdl-datastream" in svc:
        return "Printer"
    if "_spotify-connect" in svc:
        return "Speaker"
    if "_homekit" in svc:
        return "Smart Home"

    # Name-based evidence
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

    # Vendor-based fallback (only if name didn't tell us)
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