import ipaddress
import platform
import re
import socket
import struct
import subprocess
import threading
import time
from collections import defaultdict
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


# ===========================================================================
# Passive mDNS cache — filled by listening to multicast while scanning
# ===========================================================================
_mdns_seen = {}
_mdns_seen_lock = threading.Lock()


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
# DNS name decoding helpers (shared by mDNS and LLMNR parsers)
# ===========================================================================
def _skip_dns_name(data, offset):
    for _ in range(128):
        if offset >= len(data):
            return offset
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0:
            return offset + 2
        offset += 1 + length
    return offset


def _read_dns_name(data, offset):
    labels = []
    jumped = False
    original_offset = offset
    for _ in range(128):
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0:
            if offset + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                original_offset = offset + 2
                jumped = True
            offset = ptr
            continue
        offset += 1
        if offset + length > len(data):
            break
        labels.append(data[offset:offset+length].decode("latin-1", errors="ignore"))
        offset += length
    name = ".".join(labels)
    return name, (original_offset if jumped else offset)


# ===========================================================================
# ACTIVE queries — ask each device for its name
# ===========================================================================
def query_mdns_reverse(ip, timeout=0.8):
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
            s.sendto(packet, ("224.0.0.251", 5353))
            data, _ = s.recvfrom(4096)
        finally:
            s.close()

        return _parse_mdns_ptr(data)
    except Exception:
        return None


def _parse_mdns_ptr(data):
    try:
        if len(data) < 12:
            return None
        ancount = struct.unpack(">H", data[6:8])[0]
        if ancount == 0:
            return None

        offset = 12
        while offset < len(data) and data[offset] != 0:
            if data[offset] & 0xC0:
                offset += 2
                break
            offset += data[offset] + 1
        offset += 5

        for _ in range(ancount):
            if offset >= len(data):
                break
            while offset < len(data) and data[offset] != 0:
                if data[offset] & 0xC0:
                    offset += 2
                    break
                offset += data[offset] + 1
            if offset >= len(data):
                break
            offset += 1
            if offset + 10 > len(data):
                break
            rtype = struct.unpack(">H", data[offset:offset+2])[0]
            rdlength = struct.unpack(">H", data[offset+8:offset+10])[0]
            offset += 10
            if rtype == 12:
                name, _ = _read_dns_name(data, offset)
                if name:
                    return name
            offset += rdlength
    except Exception:
        pass
    return None


def query_netbios(ip, timeout=0.6):
    try:
        tid = b"\xab\xcd"
        flags = b"\x01\x00"
        qd = b"\x00\x01"
        rest = b"\x00\x00\x00\x00\x00\x00"
        name = b"*" + b" " * 15
        encoded = bytearray()
        for i in range(0, 32, 2):
            encoded.append(((name[i] - 0x41) & 0x0F) << 4 | ((name[i+1] - 0x41) & 0x0F))
        qname = bytes([32]) + bytes(encoded) + b"\x00"
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
    try:
        if len(data) < 56:
            return None
        for i in range(len(data) - 18):
            chunk = data[i:i+16]
            if chunk[15] == 0x00:
                name = chunk[:15].decode("ascii", errors="ignore").strip()
                if name and len(name) >= 2 and all(32 <= ord(c) < 127 for c in name):
                    if not name.startswith("\x00"):
                        return name
    except Exception:
        pass
    return None


def query_llmnr(ip, timeout=0.5):
    try:
        rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
        qname = b""
        for label in rev.split("."):
            qname += bytes([len(label)]) + label.encode()
        qname += b"\x00"

        packet = struct.pack(">HHHHHH", 0x1234, 0x0000, 1, 0, 0, 0)
        packet += qname + struct.pack(">HH", 12, 1)

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(packet, ("224.0.0.252", 5355))
            data, _ = s.recvfrom(2048)
        finally:
            s.close()

        return _parse_mdns_ptr(data)
    except Exception:
        return None


def query_ssdp(ip, timeout=0.6):
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
        for line in text.splitlines():
            line = line.strip()
            if line.lower().startswith("server:"):
                server = line.split(":", 1)[1].strip()
                if server and len(server) > 3:
                    return server.split("/")[0].strip()
            if line.lower().startswith("location:"):
                loc = line.split(":", 1)[1].strip()
                m = re.search(r"//([^/:]+)", loc)
                if m:
                    return m.group(1)
    except Exception:
        return None
    return None


def resolve_device_name(ip):
    """Active resolution — ask the device directly."""
    name = query_mdns_reverse(ip)
    if name:
        name = name.replace(".local", "").replace(".local.", "")
        if name and len(name) > 1:
            return name

    name = query_netbios(ip)
    if name:
        return name

    name = query_llmnr(ip)
    if name:
        name = name.replace(".local", "")
        if name and len(name) > 1:
            return name

    name = query_ssdp(ip)
    if name:
        return name

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


# ===========================================================================
# PASSIVE mDNS listener — catches phones, IoT, Chromecast, AirPlay broadcasts
# ===========================================================================
def _record_name(ip, name):
    name = name.rstrip(".")
    if not name or name.startswith("_"):
        return
    if name.endswith(".local"):
        name = name[:-6]
    if not name or len(name) < 2:
        return
    with _mdns_seen_lock:
        entry = _mdns_seen.setdefault(ip, {"names": set(), "services": set()})
        entry["names"].add(name)


def _record_service(ip, service):
    service = service.rstrip(".")
    if not service:
        return
    with _mdns_seen_lock:
        entry = _mdns_seen.setdefault(ip, {"names": set(), "services": set()})
        entry["services"].add(service)


def _parse_mdns_packet(data, src_ip):
    try:
        if len(data) < 12:
            return

        flags, qd, an, ns, ar = struct.unpack(">HHHHH", data[2:12])
        if not (flags & 0x8000):
            return

        offset = 12

        for _ in range(qd):
            offset = _skip_dns_name(data, offset)
            offset += 4
            if offset >= len(data):
                return

        total_records = an + ns + ar
        for _ in range(total_records):
            name, offset = _read_dns_name(data, offset)
            if offset + 10 > len(data):
                return
            rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", data[offset:offset+10])
            offset += 10
            rdata_start = offset
            rdata_end = offset + rdlen

            if rtype == 1 and rdlen == 4:
                ip = ".".join(str(b) for b in data[rdata_start:rdata_end])
                if ip == src_ip and name:
                    _record_name(src_ip, name)

            elif rtype == 12:
                target, _ = _read_dns_name(data, rdata_start)
                if target:
                    _record_service(src_ip, target)

            elif rtype == 33:
                if rdlen >= 6:
                    target, _ = _read_dns_name(data, rdata_start + 6)
                    if target:
                        _record_name(src_ip, target)

            offset = rdata_end
    except Exception:
        pass


def mdns_listen(duration=5.0):
    """Listen to mDNS multicast for a few seconds. Fills _mdns_seen."""
    sock = None
    try:
        MCAST_GRP = "224.0.0.251"
        MCAST_PORT = 5353

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except Exception:
            pass
        sock.bind(("", MCAST_PORT))

        mreq = struct.pack("4sl", socket.inet_aton(MCAST_GRP), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.settimeout(0.5)

        end_time = time.time() + duration
        while time.time() < end_time:
            try:
                data, addr = sock.recvfrom(9000)
                _parse_mdns_packet(data, addr[0])
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


def get_passive_names():
    with _mdns_seen_lock:
        return {ip: {"names": list(v["names"]), "services": list(v["services"])}
                for ip, v in _mdns_seen.items()}


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
        with _mdns_seen_lock:
            _mdns_seen.clear()

        local_ip = get_local_ip()
        cidr = get_network_cidr(local_ip)
        gateway = get_gateway()

        state["local_ip"] = local_ip
        state["network"] = cidr
        state["gateway"] = gateway

        net = ipaddress.ip_network(cidr, strict=False)
        hosts = [str(h) for h in net.hosts()]

        # 1. Start passive mDNS listener in the background
        listener = threading.Thread(
            target=mdns_listen, kwargs={"duration": 5.0}, daemon=True,
        )
        listener.start()

        # 2. Ping sweep
        live = []
        with ThreadPoolExecutor(max_workers=64) as ex:
            for ip, ok in zip(hosts, ex.map(ping, hosts)):
                if ok:
                    live.append(ip)

        # 3. Send active mDNS queries to prod devices into replying
        def poke(ip):
            try:
                query_mdns_reverse(ip, timeout=0.4)
            except Exception:
                pass

        with ThreadPoolExecutor(max_workers=32) as ex:
            list(ex.map(poke, hosts))

        # 4. Wait for the listener to finish
        listener.join(timeout=6.0)

        # 5. ARP table
        time.sleep(0.3)
        arp = read_arp_table()

        # 6. Merge all sources
        all_ips = set(live)
        for ip in arp:
            try:
                if ipaddress.ip_address(ip) in net:
                    all_ips.add(ip)
            except Exception:
                pass
        all_ips.add(local_ip)

        passive = get_passive_names()
        for ip in passive:
            try:
                if ipaddress.ip_address(ip) in net:
                    all_ips.add(ip)
            except Exception:
                pass

        sorted_ips = sorted(
            all_ips,
            key=lambda x: tuple(int(p) for p in x.split(".")),
        )

        # 7. Enrich each device
        def enrich(ip):
            mac = arp.get(ip)
            is_self = ip == local_ip
            is_gw = ip == gateway

            name = None
            services = []
            entry = passive.get(ip)
            if entry:
                names = entry.get("names", [])
                services = entry.get("services", [])
                candidates = [n for n in names if not n.startswith("_")]
                if candidates:
                    candidates.sort(key=len)
                    name = candidates[0]

            if not name:
                name = resolve_device_name(ip)

            if not name and services:
                for svc in services:
                    s = svc.lower()
                    if "googlecast" in s:
                        name = "Chromecast"
                        break
                    if "airplay" in s or "raop" in s:
                        name = "AirPlay Device"
                        break
                    if "companion-link" in s:
                        name = "Apple Device"
                        break
                    if "androidtv" in s:
                        name = "Android TV"
                        break
                    if "spotify" in s:
                        name = "Spotify Connect"
                        break
                    if "printer" in s or "ipp" in s:
                        name = "Printer"
                        break

            vendor = lookup_vendor(mac)
            if is_randomized_mac(mac) and vendor == "Unknown":
                vendor = "Randomized MAC"

            return {
                "ip": ip,
                "mac": mac,
                "hostname": name,
                "services": services,
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