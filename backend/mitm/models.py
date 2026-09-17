"""Data models for the MITM lab module."""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional
import time


class MitmState(str, Enum):
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    ERROR = "error"


@dataclass
class PacketRecord:
    ts: float
    src_mac: Optional[str]
    dst_mac: Optional[str]
    src_ip: Optional[str]
    dst_ip: Optional[str]
    protocol: str          # ARP / DNS / TCP / UDP / ICMP / OTHER
    src_port: Optional[int]
    dst_port: Optional[int]
    length: int
    summary: str           # short, metadata-only, e.g. "TCP SYN 192.168.56.20:51234 -> 1.1.1.1:443"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class MitmSession:
    state: MitmState = MitmState.STOPPED
    victim_ip: Optional[str] = None
    victim_mac: Optional[str] = None
    gateway_ip: Optional[str] = None
    gateway_mac: Optional[str] = None
    attacker_iface: Optional[str] = None
    attacker_ip: Optional[str] = None
    attacker_mac: Optional[str] = None
    started_at: Optional[float] = None
    stopped_at: Optional[float] = None
    error: Optional[str] = None
    forwarded: bool = False

    def to_dict(self) -> dict:
        return {
            "state": self.state.value,
            "victim_ip": self.victim_ip,
            "victim_mac": self.victim_mac,
            "gateway_ip": self.gateway_ip,
            "gateway_mac": self.gateway_mac,
            "attacker_iface": self.attacker_iface,
            "attacker_ip": self.attacker_ip,
            "attacker_mac": self.attacker_mac,
            "started_at": self.started_at,
            "stopped_at": self.stopped_at,
            "error": self.error,
            "forwarded": self.forwarded,
        }