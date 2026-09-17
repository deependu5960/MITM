"""Application configuration and safety boundary."""
from __future__ import annotations
import os
from dataclasses import dataclass, field
from typing import List


@dataclass
class Config:
    # ---------- Lab boundary ----------
    # Empty list = no restriction. If non-empty, only these CIDRs are allowed
    # to be MITM targets. Example: ["192.168.56.0/24"]
    LAB_SUBNETS: List[str] = field(default_factory=lambda: [
        s.strip() for s in os.environ.get("NETSCOPE_LAB_SUBNETS", "").split(",") if s.strip()
    ])

    # ---------- Runtime ----------
    HOST: str = os.environ.get("NETSCOPE_HOST", "127.0.0.1")
    PORT: int = int(os.environ.get("NETSCOPE_PORT", "5000"))
    DEBUG: bool = os.environ.get("NETSCOPE_DEBUG", "0") == "1"

    # ---------- Packet capture ----------
    MAX_PACKETS: int = 5000           # ring buffer size for the GUI
    PACKET_QUEUE_MAX: int = 10000     # internal queue bound
    MITM_ARP_INTERVAL: float = 1.5    # seconds between ARP re-poison packets

    # ---------- Safety ----------
    # Set to False in config only if you accept the risk. Default True.
    REQUIRE_CONFIRMATION: bool = True


CONFIG = Config()