"""IP forwarding + iptables helpers."""
from __future__ import annotations
import logging
import subprocess

log = logging.getLogger("mitm.forwarding")


def get_ip_forward() -> bool:
    try:
        with open("/proc/sys/net/ipv4/ip_forward") as f:
            return f.read().strip() == "1"
    except Exception:
        return False


def set_ip_forward(enabled: bool) -> bool:
    """Enable/disable kernel IP forwarding."""
    try:
        val = "1" if enabled else "0"
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write(val)
        log.info("ip_forward set to %s", val)
        return True
    except Exception as e:
        log.error("Cannot set ip_forward: %s", e)
        return False


def _run(cmd: list[str]) -> bool:
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=5)
        return True
    except Exception as e:
        log.warning("Command %s failed: %s", " ".join(cmd), e)
        return False


def enable_forwarding(iface: str) -> bool:
    """
    Enable IP forwarding and add a rule allowing traffic between the
    victim and the gateway to be relayed by this host.
    """
    ok = set_ip_forward(True)
    # Allow forwarding on the lab interface. We do NOT flush existing rules —
    # we add a specific ACCEPT for the lab interface and remember nothing
    # else so we don't destroy the user's firewall.
    _run(["iptables", "-I", "FORWARD", "1", "-i", iface, "-j", "ACCEPT"])
    _run(["iptables", "-I", "FORWARD", "1", "-o", iface, "-j", "ACCEPT"])
    return ok


def disable_forwarding(iface: str) -> None:
    """
    Remove only the rules we added, then turn off ip_forward.
    Safe to call even if the rules aren't present.
    """
    _run(["iptables", "-D", "FORWARD", "-i", iface, "-j", "ACCEPT"])
    _run(["iptables", "-D", "FORWARD", "-o", iface, "-j", "ACCEPT"])
    set_ip_forward(False)