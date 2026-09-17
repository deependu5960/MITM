"""Multi-source hostname resolution with service-based device labelling.

Sources, in the order the final name is decided:
  1. Passive mDNS listener  — catches phone / IoT / Chromecast broadcasts.
  2. Active mDNS PTR        — asks the device directly.
  3. NetBIOS name query     — Windows PCs (UDP 137).
  4. LLMNR                  — modern Windows (UDP 5355).
  5. Reverse DNS            — any device with a PTR record.
  6. Local OS hostname      — for our own IP.

Two additional helpers sit on top:
  - label_from_services()   — turns mDNS service names into a friendly
                              device category ("Chromecast", "iPhone", …).
  - guess_type()            — combines name + services + vendor into a
                              final device type.

Never invents a hostname. If nothing answers, returns None and the GUI
shows "Unknown Device" (or a service-derived category if one exists).
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


# ===========================================================================
# Passive mDNS cache
# ===========================================================================
_passive_lock = threading.Lock()
_passive: Dict[str, Dict[str, Set[str]]] = {}
_passive_stats = {
    "packets": 0,
    "records": 0,
    "services": 0,
    "bind_error": None,
    "started": False,
}


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
        _passive_stats["services"] += 1


def get_passive() -> Dict[str, Dict[str, List[str]]]:
    with _passive_lock:
        return {ip: {"names": list(v["names"]), "services": list(v["services"])}
                for ip, v in _passive.items()}


def clear_passive() -> None:
    with _passive_lock:
        _passive.clear()
        _passive_stats["packets"] = 0
        _passive_stats["records"] = 0
        _passive_stats["services"] = 0


def passive_stats() -> Dict:
    with _passive_lock:
        return dict(_passive_stats)


# ===========================================================================
# DNS name encoding / decoding (shared)
# ===========================================================================
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
        try:
            labels.append(data[off:off + n].decode("utf-8", errors="replace"))
        except Exception:
            labels.append(data[off:off + n].decode("latin-1", errors="ignore"))
        off += n
    name = ".".join(labels) if labels else None
    return name, (orig if jumped else off)


# ===========================================================================
# mDNS passive listener
# ===========================================================================
def _parse_mdns(data: bytes, src_ip: str) -> None:
    """
    Parse an mDNS packet — BOTH queries and responses.

    Most home-LAN mDNS traffic is queries. Devices ask "who has
    _googlecast._tcp.local?" constantly, and the service name in the
    question is enough to fingerprint the asking IP.

    Additionally, some devices append their own hostname as an A record in
    the ADDITIONAL section of a query. We capture that too.
    """
    try:
        if len(data) < 12:
            return

        flags, qd, an, ns, ar = struct.unpack(">HHHHH", data[2:12])
        off = 12

        # ---- QUESTIONS (present in both queries and responses) ----
        for _ in range(qd):
            name, off = _read_name(data, off)
            if off + 4 > len(data):
                return
            qtype, qclass = struct.unpack(">HH", data[off:off + 4])
            off += 4
            if name and qtype == 12:
                _record_service(src_ip, name)

        # ---- ANSWER + AUTHORITY + ADDITIONAL records ----
        for _ in range(an + ns + ar):
            if off >= len(data):
                return
            name, off = _read_name(data, off)
            if off + 10 > len(data):
                return
            rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            rdata = off
            end = off + rdlen
            if end > len(data):
                return

            if rtype == 1 and rdlen == 4:
                # A record — "<name> is at <ip>"
                ip = ".".join(str(b) for b in data[rdata:end])
                if ip == src_ip and name:
                    _record_name(src_ip, name)

            elif rtype == 12:
                # PTR — service announcement
                target, _ = _read_name(data, rdata)
                if target:
                    _record_service(src_ip, target)
                    if "in-addr.arpa" in (name or "").lower():
                        _record_name(src_ip, target)

            elif rtype == 33 and rdlen >= 6:
                # SRV — "<target>.local is serving <service>"
                target, _ = _read_name(data, rdata + 6)
                if target:
                    _record_name(src_ip, target)

            elif rtype == 16:
                # TXT — look for fn= / name= / model= fields
                try:
                    i = rdata
                    while i < end:
                        ln = data[i]
                        i += 1
                        if i + ln > end:
                            break
                        entry = data[i:i + ln].decode("utf-8", errors="ignore")
                        i += ln
                        m = re.match(r"^(fn|name|model|md)=(.+)$", entry, re.IGNORECASE)
                        if m:
                            val = m.group(2).strip()
                            if val and 2 <= len(val) <= 64 and not val.isdigit():
                                _record_name(src_ip, val)
                except Exception:
                    pass

            off = end

    except Exception:
        pass


def mdns_listen(duration: float = 12.0) -> None:
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
            log.warning("If avahi-daemon is running, stop it:")
            log.warning("  sudo systemctl stop avahi-daemon.socket avahi-daemon.service")
            return

        mreq = struct.pack("4sl", socket.inet_aton("224.0.0.251"), socket.INADDR_ANY)
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        except OSError as e:
            with _passive_lock:
                _passive_stats["bind_error"] = f"multicast join failed: {e}"
            log.warning("mDNS multicast join failed: %s", e)
            return

        with _passive_lock:
            _passive_stats["started"] = True

        sock.settimeout(0.5)
        end_time = time.time() + duration
        while time.time() < end_time:
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


# ===========================================================================
# Active queries
# ===========================================================================
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
            if off >= len(data):
                return None
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


# ===========================================================================
# Service → label mapping
# ===========================================================================
def label_from_services(services: List[str]) -> Optional[str]:
    """
    Turn mDNS service strings into a friendly device label.
    Uses evidence the device itself broadcast — never invents a name.
    """
    svc = " ".join(services).lower()

    # Google / Android
    if "_googlecast" in svc:
        return "Chromecast"
    if "_androidtvremote2" in svc or "_androidtvremote" in svc:
        return "Android TV"
    if "_googlezone" in svc:
        return "Google Home"

    # Apple
    if "_companion-link" in svc or "_apple-mobdev2" in svc:
        return "iPhone"
    if "_airplay" in svc and "_raop" in svc:
        return "Apple TV"
    if "_raop" in svc:
        return "AirPlay Speaker"
    if "_airplay" in svc:
        return "AirPlay Device"
    if "_homekit" in svc or "_hap._tcp" in svc:
        return "HomeKit Accessory"
    if "_rdlink" in svc or "_sleep-proxy" in svc:
        return "Apple Device"

    # Amazon
    if "_amzn-wplay" in svc or "_amazonecho" in svc:
        return "Amazon Echo"
    if "_amzn-alexa" in svc:
        return "Amazon Device"

    # Printers
    if "_ipp" in svc or "_pdl-datastream" in svc or "_printer" in svc:
        return "Printer"
    if "_scanner" in svc:
        return "Scanner"

    # Media / speakers
    if "_spotify-connect" in svc:
        return "Speaker"
    if "_sonos" in svc:
        return "Sonos Speaker"
    if "_mediaremotetv" in svc:
        return "Smart TV"

    # Smart home
    if "_matter" in svc or "_matterc" in svc:
        return "Matter Device"
    if "_tuya" in svc:
        return "Smart Device"

    # Computers
    if "_smb" in svc or "_workstation" in svc:
        return "Windows PC"
    if "_afpovertcp" in svc:
        return "Mac"
    if "_ssh" in svc or "_sftp-ssh" in svc:
        return "Linux Device"

    return None


# ===========================================================================
# Public: resolve one IP using every source
# ===========================================================================
def resolve(ip: str, local_ip: Optional[str] = None,
            local_name: Optional[str] = None) -> Dict:
    """
    Returns:
      {
        "hostname": str | None,
        "services": [str],
        "source":   str,
        "trace":    {mdns_passive, mdns_active, netbios, llmnr, dns, local}
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


# ===========================================================================
# Device type from name + services + vendor
# ===========================================================================
def guess_type(name: Optional[str], services: List[str], vendor: str, is_gateway: bool, is_self: bool) -> str:
    """
    Determine the device type. Priority order:
      1. What the device itself told us (mDNS services).
      2. What its hostname looks like.
      3. What its MAC vendor suggests.
    """
    if is_self:
        return "This Device"
    if is_gateway:
        return "Router"

    n = (name or "").lower()
    v = (vendor or "").lower()
    svc = " ".join(services).lower()

    # =================================================================
    # 1. Service evidence — the device itself says what it is
    # =================================================================
    # Google / Chromecast / Android TV
    if "_googlecast" in svc or "googlecast" in n:
        return "Chromecast"
    if "_androidtvremote2" in svc or "_androidtvremote" in svc or "androidtv" in n:
        return "Android TV"
    if "_googlezone" in svc:
        return "Smart Speaker"
    if "_googleprint" in svc:
        return "Printer"

    # Apple
    if "_companion-link" in svc or "_apple-mobdev2" in svc or "iphone" in n:
        return "Phone"
    if "_airplay" in svc and "_raop" in svc:
        return "TV"
    if "_raop" in svc:
        return "Smart Speaker"
    if "_airplay" in svc:
        return "Apple Device"
    if "_homekit" in svc or "_hap._tcp" in svc:
        return "Smart Home"
    if "_rdlink" in svc or "_sleep-proxy" in svc:
        return "Apple Device"
    if "_afpovertcp" in svc or "_smb" in svc and "mac" in n:
        return "Mac"

    # Amazon
    if "_amzn-wplay" in svc or "_amazonecho" in svc or "echo" in n or "alexa" in n:
        return "Smart Speaker"
    if "_amzn-alexa" in svc:
        return "Smart Speaker"

    # Printers
    if "_ipp" in svc or "_pdl-datastream" in svc or "_printer" in svc or "_uscan" in svc:
        return "Printer"
    if "_scanner" in svc:
        return "Scanner"

    # Media / speakers
    if "_spotify-connect" in svc:
        return "Smart Speaker"
    if "_sonos" in svc:
        return "Smart Speaker"
    if "_mediaremotetv" in svc or "_airport" in svc or "appletv" in n:
        return "TV"
    if "_sleep-proxy" in svc and "_airplay" not in svc:
        return "Apple Device"

    # Smart home / IoT
    if "_matter" in svc or "_matterc" in svc:
        return "Smart Home"
    if "_tuya" in svc:
        return "Smart Home"
    if "_hue" in svc or "philips" in n:
        return "Smart Home"

    # Computers
    if "_smb" in svc or "_workstation" in svc:
        if "mac" in n or "imac" in n or "macbook" in n:
            return "Mac"
        return "Computer"
    if "_ssh" in svc or "_sftp-ssh" in svc:
        return "Server"
    if "_rfb" in svc:  # VNC
        return "Computer"

    # =================================================================
    # 2. Hostname evidence
    # =================================================================
    # Phones
    if any(k in n for k in ("iphone", "android", "galaxy", "pixel", "redmi",
                            "poco", "oneplus", "moto", "xiaomi", "huawei",
                            "realme", "oppo", "vivo", "nothing",
                            "-phone", "phone-", "moto-")):
        return "Phone"
    if n.startswith("android_"):
        return "Phone"
    if "iphone" in n or "ipad" in n:
        return "Tablet" if "ipad" in n else "Phone"

    # Tablets
    if any(k in n for k in ("ipad", "tablet", "tab-", "tab_", "galaxy-tab")):
        return "Tablet"

    # Macs
    if any(k in n for k in ("macbook", "imac", "mac-mini", "mac-mini-",
                            "mac-pro", "mac-studio", "air")):
        if "mac" in n:
            return "Mac"

    # Laptops / desktops
    if any(k in n for k in ("laptop", "notebook", "thinkpad", "inspiron",
                            "latitude", "xps", "surface", "vivobook",
                            "ideapad", "pavilion", "probook", "elitebook")):
        return "Laptop"
    if any(k in n for k in ("desktop", "pc-", "-pc", "workstation",
                            "precision", "optiplex", "thinkcentre")):
        return "Computer"

    # Windows-specific
    if n.startswith("desktop-") or n.startswith("win-"):
        return "Computer"

    # Printers
    if any(k in n for k in ("printer", "hp-", "canon", "epson", "brother",
                            "lexmark", "xerox", "officejet", "deskjet",
                            "laserjet", "pixma", "workforce")):
        return "Printer"

    # TVs
    if any(k in n for k in ("tv", "roku", "firestick", "fire-tv", "bravia",
                            "webos", "tizen", "appletv", "chromecast",
                            "shield", "lgtv", "samsungtv", "vizio")):
        return "TV"

    # NAS
    if any(k in n for k in ("nas", "synology", "diskstation", "qnap",
                            "freenas", "truenas", "readynas")):
        return "NAS"

    # Speakers
    if any(k in n for k in ("echo", "alexa", "nest", "homepod", "sonos",
                            "harman", "bose", "jbl", "soundbar")):
        return "Smart Speaker"

    # Consoles
    if any(k in n for k in ("xbox", "playstation", "ps4", "ps5", "nintendo",
                            "switch")):
        return "Console"

    # Cameras
    if any(k in n for k in ("camera", "ipcam", "hikvision", "dahua", "reolink",
                            "wyze", "arlo", "ring-")):
        return "Camera"

    # Routers / network gear
    if any(k in n for k in ("router", "gateway", "fritz", "openwrt", "unifi",
                            "ubiquiti", "mikrotik", "edgerouter", "orbi",
                            "velop", "deco")):
        return "Router"

    # =================================================================
    # 3. Vendor evidence (weakest — only when nothing else matched)
    # =================================================================
    if "apple" in v:
        return "Apple Device"
    if "raspberry" in v:
        return "Raspberry Pi"
    if any(x in v for x in ("vmware", "virtualbox", "qemu", "hyper-v", "xen")):
        return "Virtual Machine"
    if "intel" in v or "realtek" in v or "broadcom" in v:
        return "Computer"
    if any(x in v for x in ("hp", "dell", "lenovo", "asus", "acer",
                            "msi", "toshiba", "samsung electronics")):
        return "Computer"
    if any(x in v for x in ("cisco", "netgear", "tp-link", "d-link",
                            "ubiquiti", "mikrotik", "aruba", "ruckus")):
        return "Network Device"
    if any(x in v for x in ("epson", "canon", "brother", "lexmark", "xerox")):
        return "Printer"
    if any(x in v for x in ("sonos", "bose", "harman", "jbl", "sony")):
        return "Smart Speaker"
    if "samsung" in v or "xiaomi" in v or "huawei" in v or "oneplus" in v:
        return "Phone"
    if "google" in v or "nest" in v:
        return "Chromecast"
    if "amazon" in v:
        return "Smart Speaker"
    if "lg" in v or "philips" in v or "vizio" in v:
        return "TV"
    if "hikvision" in v or "dahua" in v or "reolink" in v:
        return "Camera"
    if "nintendo" in v:
        return "Console"
    if "microsoft" in v:
        return "Computer"

    return "Unknown"