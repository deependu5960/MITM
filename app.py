import ipaddress
import platform
import re
import socket
import struct
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from flask import Flask, jsonify, render_template

from backend_oui import lookup_vendor, is_randomized_mac

app = Flask(__name__)

state = {
    "scanning": False,
    "devices": [],
    "last_scan": None,
    "error": None,
    "local_ip": None,
    "network": None,
    "gateway": None,
}


# ---------------------------------------------------------------------------
# Network detection
# ---------------------------------------------------------------------------
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def get_network_cidr(local_ip):
    parts = local_ip.split(".")
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"


def get_gateway():
    system = platform.system().lower()
    try:
        if system == "windows":
            out = subprocess.check_output(
                ["ipconfig"], stderr=subprocess.DEVNULL, text=True,
                encoding="utf-8", errors="ignore",
            )
            for line in out.splitlines():
                if "Default Gateway" in line:
                    m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                    if m:
                        return m.group(1)
        else:
            out = subprocess.check_output(
                ["ip", "route"], stderr=subprocess.DEVNULL, text=True,
            )
            for line in out.splitlines():
                if line.startswith("default"):
                    return line.split()[2]
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Ping + ARP
# ---------------------------------------------------------------------------
def ping(ip, timeout_ms=700):
    system = platform.system().lower()
    try:
        if system == "windows":
            cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
        else:
            cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]
        r = subprocess.run(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=(timeout_ms / 1000.0) + 0.5,
        )
        return r.returncode == 0
    except Exception:
        return False


def read_arp_table():
    table = {}
    system = platform.system().lower()
    try:
        if system == "windows":
            out = subprocess.check_output(
                ["arp", "-a"], stderr=subprocess.DEVNULL, text=True,
                encoding="utf-8", errors="ignore",
            )
            for line in out.splitlines():
                m = re.match(
                    r"\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+",
                    line,
                )
                if m:
                    mac = m.group(2).replace("-", ":").upper()
                    if mac != "FF:FF:FF:FF:FF:FF":
                        table[m.group(1)] = mac
        else:
            try:
                out = subprocess.check_output(
                    ["ip", "neigh"], stderr=subprocess.DEVNULL, text=True,
                )
            except Exception:
                out = subprocess.check_output(
                    ["arp", "-n"], stderr=subprocess.DEVNULL, text=True,
                )
            for line in out.splitlines():
                m = re.match(r"(\d+\.\d+\.\d+\.\d+).*?([0-9a-fA-F:]{17})", line)
                if m:
                    table[m.group(1)] = m.group(2).upper()
    except Exception:
        pass
    return table


# ===========================================================================
# ACTIVE NAME DISCOVERY — the same protocols Bettercap/Ettercap use
# ===========================================================================

def query_mdns_reverse(ip, timeout=0.8):
    """Send an mDNS PTR query for the IP. Most Apple/phone/IoT devices reply."""
    try:
        rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
        qname = b""
        for label in rev.split("."):
            qname += bytes([len(label)]) + label.encode()
        qname += b"\x00"

        # DNS header: id=0, flags=0, qdcount=1
        packet = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0)
        packet += qname + struct.pack(">HH", 12, 1)  # PTR, IN

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(packet, ("224.0.0.251", 5353))
            data, _ = s.recvfrom(4096)
        finally:
            s.close()

        # Parse the DNS response to find PTR records
        return _parse_mdns_ptr(data)
    except Exception:
        return None


def _parse_mdns_ptr(data):
    """Minimal DNS response parser to extract PTR target names."""
    try:
        if len(data) < 12:
            return None
        # Header: id(2) flags(2) qd(2) an(2) ns(2) ar(2)
        ancount = struct.unpack(">H", data[6:8])[0]
        if ancount == 0:
            return None

        offset = 12
        # Skip question section
        while offset < len(data) and data[offset] != 0:
            if data[offset] & 0xC0:  # compression pointer
                offset += 2
                break
            offset += data[offset] + 1
        offset += 5  # null + qtype + qclass

        # Parse answers
        for _ in range(ancount):
            if offset >= len(data):
                break
            # Skip name (with compression pointers)
            while offset < len(data) and data[offset] != 0:
                if data[offset] & 0xC0:
                    offset += 2
                    break
                offset += data[offset] + 1
            if offset >= len(data):
                break
            offset += 1  # null byte
            if offset + 10 > len(data):
                break
            rtype = struct.unpack(">H", data[offset:offset+2])[0]
            rdlength = struct.unpack(">H", data[offset+8:offset+10])[0]
            offset += 10
            if rtype == 12:  # PTR
                name = _decode_dns_name(data, offset)
                if name:
                    return name
            offset += rdlength
    except Exception:
        pass
    return None


def _decode_dns_name(data, offset):
    """Decode a DNS name (with compression) into a string."""
    labels = []
    seen = set()
    for _ in range(20):
        if offset >= len(data) or offset in seen:
            break
        seen.add(offset)
        length = data[offset]
        if length == 0:
            break
        if length & 0xC0:  # pointer
            if offset + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            offset = ptr
            continue
        offset += 1
        if offset + length > len(data):
            break
        label = data[offset:offset+length].decode("latin-1", errors="ignore")
        labels.append(label)
        offset += length
    if not labels:
        return None
    name = ".".join(labels)
    return name if len(name) > 2 else None


def query_netbios(ip, timeout=0.6):
    """NetBIOS Name Service query — Windows PCs and old devices answer."""
    try:
        # NetBIOS name query for "*" (wildcard) to get the node's name table
        # Transaction ID
        tid = b"\xab\xcd"
        # Flags: standard query, recursion desired
        flags = b"\x01\x00"
        # Questions: 1
        qd = b"\x00\x01"
        # Answer/Authority/Additional: 0
        rest = b"\x00\x00\x00\x00\x00\x00"
        # QNAME: encode "*" as NetBIOS name (32 bytes, padded with spaces)
        name = b"*" + b" " * 15  # 16 chars
        encoded = bytearray()
        for i in range(0, 32, 2):
            encoded.append(((name[i] - 0x41) & 0x0F) << 4 | ((name[i+1] - 0x41) & 0x0F))
        qname = bytes([32]) + bytes(encoded) + b"\x00"
        # QTYPE: NBSTAT (0x0021), QCLASS: IN (0x0001)
        qtype = b"\x00\x21"
        qclass = b"\x00\x01"

        packet = tid + flags + qd + rest + qname + qtype + qclass

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(packet, (ip, 137))
            data, _ = s.recvfrom(2048)
        finally:
            s.close()

        return _parse_netbios_response(data)
    except Exception:
        return None


def _parse_netbios_response(data):
    """Parse NetBIOS node status response to extract the computer name."""
    try:
        if len(data) < 56:
            return None
        # Skip header (12 bytes), question, etc. — the name table starts
        # at the end of the packet. We look for the first "<00> UNIQUE" entry.
        # A simpler approach: find a 15-char ASCII string followed by 0x00.
        for i in range(len(data) - 18):
            # NetBIOS names are 16 bytes: 15 chars + type byte
            chunk = data[i:i+16]
            if chunk[15] == 0x00:  # type 00 = workstation name
                name = chunk[:15].decode("ascii", errors="ignore").strip()
                # Filter out garbage and group names
                if name and len(name) >= 2 and all(32 <= ord(c) < 127 for c in name):
                    if not name.startswith("\x00"):
                        return name
    except Exception:
        pass
    return None


def query_llmnr(ip, timeout=0.5):
    """LLMNR query — modern Windows and some Linux devices answer."""
    try:
        # Build a simple LLMNR PTR query for the IP
        rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
        qname = b""
        for label in rev.split("."):
            qname += bytes([len(label)]) + label.encode()
        qname += b"\x00"

        # LLMNR header (similar to DNS)
        packet = struct.pack(">HHHHHH", 0x1234, 0x0000, 1, 0, 0, 0)
        packet += qname + struct.pack(">HH", 12, 1)  # PTR, IN

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(packet, ("224.0.0.252", 5355))
            data, _ = s.recvfrom(2048)
        finally:
            s.close()

        # Reuse mDNS parser (LLMNR uses the same DNS format)
        return _parse_mdns_ptr(data)
    except Exception:
        return None


def query_ssdp(ip, timeout=0.6):
    """SSDP/UPnP M-SEARCH — routers, TVs, consoles, media servers answer."""
    try:
        msg = (
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            'MAN: "ssdp:discover"\r\n'
            "MX: 1\r\n"
            "ST: ssdp:all\r\n"
            "\r\n"
        ).encode()

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        try:
            s.sendto(msg, ("239.255.255.250", 1900))
            data, _ = s.recvfrom(4096)
        finally:
            s.close()

        text = data.decode("latin-1", errors="ignore")
        # Look for SERVER or LOCATION headers
        for line in text.splitlines():
            line = line.strip()
            if line.lower().startswith("server:"):
                server = line.split(":", 1)[1].strip()
                if server and len(server) > 3:
                    return server.split("/")[0].strip()
            if line.lower().startswith("location:"):
                loc = line.split(":", 1)[1].strip()
                # Extract a name from the URL host
                m = re.search(r"//([^/:]+)", loc)
                if m:
                    return m.group(1)
    except Exception:
        return None
    return None


# ---------------------------------------------------------------------------
# Master name resolver — try every protocol, return first hit
# ---------------------------------------------------------------------------
def resolve_device_name(ip):
    """
    Actively query the device using the same protocols Bettercap/Ettercap use.
    Order: mDNS (most devices) → NetBIOS (Windows) → LLMNR (modern Windows)
    → SSDP (routers/TVs) → reverse DNS (fallback).
    """
    # mDNS first — best hit rate for phones, Macs, printers, IoT
    name = query_mdns_reverse(ip)
    if name:
        # Strip common suffixes and clean up
        name = name.replace(".local", "").replace(".local.", "")
        if name and len(name) > 1:
            return name

    # NetBIOS — Windows workstation names
    name = query_netbios(ip)
    if name:
        return name

    # LLMNR — modern Windows fallback
    name = query_llmnr(ip)
    if name:
        name = name.replace(".local", "")
        if name and len(name) > 1:
            return name

    # SSDP — routers and media devices
    name = query_ssdp(ip)
    if name:
        return name

    # Reverse DNS — last resort (usually empty on home LANs)
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(0.4)
        name, _, _ = socket.gethostbyaddr(ip)
        if name:
            return name.rstrip(".")
    except Exception:
        pass
    finally:
        socket.setdefaulttimeout(old)

    return None


# ---------------------------------------------------------------------------
# Friendly device type
# ---------------------------------------------------------------------------
def guess_type(name, vendor, is_gateway, is_self):
    if is_self:
        return "This device"
    if is_gateway:
        return "Router / Gateway"

    n = (name or "").lower()
    v = (vendor or "").lower()

    if any(k in n for k in ("iphone", "android", "galaxy", "pixel", "phone",
                            "oneplus", "redmi", "poco", "moto")):
        return "Phone"
    if any(k in n for k in ("ipad", "tablet", "tab-")):
        return "Tablet"
    if any(k in n for k in ("macbook", "imac", "mac-mini", "mac-pro")):
        return "Mac"
    if any(k in n for k in ("laptop", "desktop", "pc-", "-pc", "surface",
                            "thinkpad", "inspiron", "latitude", "xps")):
        return "Computer"
    if any(k in n for k in ("printer", "hp-", "canon", "epson", "brother",
                            "lexmark", "xerox")):
        return "Printer"
    if any(k in n for k in ("tv", "roku", "chromecast", "firestick",
                            "appletv", "bravia", "webos", "tizen")):
        return "TV / Media"
    if any(k in n for k in ("nas", "synology", "qnap", "freenas")):
        return "NAS"
    if any(k in n for k in ("echo", "alexa", "nest", "homepod", "sonos",
                            "home", "smart")):
        return "Smart Home"
    if any(k in n for k in ("xbox", "playstation", "ps4", "ps5", "switch",
                            "nintendo")):
        return "Console"
    if any(k in n for k in ("camera", "cam-", "ipcam", "hikvision", "dahua")):
        return "Camera"
    if any(k in n for k in ("router", "gateway", "fritz", "openwrt",
                            "unifi", "ubiquiti", "mikrotik")):
        return "Router / Gateway"

    if "apple" in v:
        return "Apple Device"
    if "samsung" in v:
        return "Samsung Device"
    if "raspberry" in v:
        return "Raspberry Pi"
    if any(x in v for x in ("vmware", "virtualbox", "qemu", "hyper-v")):
        return "Virtual Machine"
    if any(x in v for x in ("hp", "dell", "lenovo", "asus", "intel", "realtek")):
        return "Computer"
    if any(x in v for x in ("cisco", "netgear", "tp-link", "d-link", "huawei")):
        return "Network Device"
    if any(x in v for x in ("epson", "canon", "lexmark", "xerox")):
        return "Printer"

    return "Device"


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------
def do_scan():
    try:
        local_ip = get_local_ip()
        cidr = get_network_cidr(local_ip)
        gateway = get_gateway()

        state["local_ip"] = local_ip
        state["network"] = cidr
        state["gateway"] = gateway

        net = ipaddress.ip_network(cidr, strict=False)
        hosts = [str(h) for h in net.hosts()]

        # 1. Ping sweep
        live = []
        with ThreadPoolExecutor(max_workers=64) as ex:
            for ip, ok in zip(hosts, ex.map(ping, hosts)):
                if ok:
                    live.append(ip)

        # 2. ARP table
        time.sleep(0.5)
        arp = read_arp_table()

        # 3. Combine
        all_ips = set(live)
        for ip in arp:
            try:
                if ipaddress.ip_address(ip) in net:
                    all_ips.add(ip)
            except Exception:
                pass
        all_ips.add(local_ip)

        sorted_ips = sorted(
            all_ips,
            key=lambda x: tuple(int(p) for p in x.split(".")),
        )

        # 4. Enrich with active name discovery
        def enrich(ip):
            mac = arp.get(ip)
            name = resolve_device_name(ip)
            is_self = ip == local_ip
            is_gw = ip == gateway

            vendor = lookup_vendor(mac)
            if is_randomized_mac(mac) and vendor == "Unknown":
                vendor = "Randomized MAC"

            return {
                "ip": ip,
                "mac": mac,
                "hostname": name,
                "is_self": is_self,
                "is_gateway": is_gw,
                "vendor": vendor,
                "type": guess_type(name, vendor, is_gw, is_self),
                "responsive": ip in live,
            }

        with ThreadPoolExecutor(max_workers=16) as ex:
            devices = list(ex.map(enrich, sorted_ips))

        state["devices"] = devices
        state["last_scan"] = time.time()
        state["error"] = None

    except Exception as e:
        state["error"] = str(e)
    finally:
        state["scanning"] = False


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/info")
def api_info():
    local_ip = state["local_ip"] or get_local_ip()
    cidr = state["network"] or get_network_cidr(local_ip)
    return jsonify({
        "local_ip": local_ip,
        "network": cidr,
        "gateway": state["gateway"] or get_gateway(),
    })


@app.route("/api/devices")
def api_devices():
    return jsonify({
        "scanning": state["scanning"],
        "last_scan": state["last_scan"],
        "error": state["error"],
        "devices": state["devices"],
        "local_ip": state["local_ip"],
        "network": state["network"],
        "gateway": state["gateway"],
    })


@app.route("/api/scan", methods=["POST"])
def api_scan():
    if state["scanning"]:
        return jsonify({"success": False, "message": "Scan already running"}), 409
    state["scanning"] = True
    state["error"] = None
    threading.Thread(target=do_scan, daemon=True).start()
    return jsonify({"success": True})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)