"""Data models for the MITM lab module."""
from __future__ import annotations
from dataclasses import dataclass, asdict
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
    protocol: str
    src_port: Optional[int]
    dst_port: Optional[int]
    length: int
    summary: str
    flow_key: Optional[str] = None      # set when the packet belongs to a tracked flow

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Flow:
    key: str                            # "dst_ip:dst_port:protocol"
    dst_ip: str
    dst_port: Optional[int]
    protocol: str
    hostname: Optional[str] = None      # resolved via SNI / HTTP Host / DNS cache
    category: str = "unknown"
    first_seen: float = 0.0
    last_seen: float = 0.0
    packets: int = 0
    bytes: int = 0
    direction: str = "outbound"         # outbound | inbound

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class MitmSession:
    state: MitmState = MitmState.STOPPED
    victim_ip: Optional[str] = None
    victim_name: Optional[str] = None
    victim_mac: Optional[str] = None
    gateway_ip: Optional[str] = None
    gateway_name: Optional[str] = None
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
            "victim_name": self.victim_name,
            "victim_mac": self.victim_mac,
            "gateway_ip": self.gateway_ip,
            "gateway_name": self.gateway_name,
            "gateway_mac": self.gateway_mac,
            "attacker_iface": self.attacker_iface,
            "attacker_ip": self.attacker_ip,
            "attacker_mac": self.attacker_mac,
            "started_at": self.started_at,
            "stopped_at": self.stopped_at,
            "error": self.error,
            "forwarded": self.forwarded,
        }