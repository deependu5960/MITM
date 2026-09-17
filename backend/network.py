"""Local interface detection using psutil."""
from __future__ import annotations
import ipaddress
import socket
from typing import Dict, List, Optional
import psutil


def _interfaces() -> List[Dict]:
    out: List[Dict] = []
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    for name, snics in addrs.items():
        st = stats.get(name)
        if st is not None and not st.isup:
            continue
        for snic in snics:
            if snic.family != socket.AF_INET:
                continue
            if snic.address.startswith(("127.", "169.254.")):
                continue
            netmask = snic.netmask or "255.255.255.0"
            try:
                iface = ipaddress.IPv4Interface(f"{snic.address}/{netmask}")
            except ValueError:
                continue
            out.append({
                "name": name,
                "ip": snic.address,
                "netmask": netmask,
                "network": str(iface.network.network_address),
                "cidr": str(iface.network),
                "prefix": iface.network.prefixlen,
            })
    return out


def get_primary() -> Optional[Dict]:
    ifaces = _interfaces()
    if not ifaces:
        return None
    preferred = ("wi", "wl", "en", "eth", "wlan", "ethernet", "wi-fi")
    for i in ifaces:
        n = i["name"].lower()
        if any(p in n for p in preferred):
            return i
    return ifaces[0]


def local_hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "This device"


def enumerate_hosts(cidr: str, cap: int = 1024) -> List[str]:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return []
    if net.num_addresses - 2 > cap:
        try:
            net = ipaddress.ip_network(f"{net.network_address}/24", strict=False)
        except ValueError:
            return []
    return [str(h) for h in net.hosts()]