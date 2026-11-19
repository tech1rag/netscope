"""Running statistics for the summary screen."""
from __future__ import annotations

import threading
from collections import Counter, deque
from typing import Optional

from .capture import PacketRecord
from .utils import remote_ip


class Stats:
    def __init__(self, keep_recent: int = 500):
        self.lock = threading.Lock()
        self.packets = 0
        self.bytes = 0
        self.first_ts: Optional[float] = None
        self.last_ts: Optional[float] = None
        self.protocols: Counter = Counter()      # "TCP" -> packets
        self.ports: Counter = Counter()          # (proto, port, service) -> packets
        self.flags: Counter = Counter()          # "SYN+ACK" -> packets
        self.talkers: dict[str, list[int]] = {}  # remote ip -> [packets, bytes]
        self.dns_names: Counter = Counter()
        self.recent: deque = deque(maxlen=keep_recent)

    def add(self, rec: PacketRecord) -> None:
        with self.lock:
            self.packets += 1
            self.bytes += rec.size
            if self.first_ts is None:
                self.first_ts = rec.time
            self.last_ts = rec.time
            self.protocols[rec.proto] += 1
            if rec.svc_port is not None:
                self.ports[(rec.proto, rec.svc_port, rec.service)] += 1
            if rec.flags:
                self.flags[rec.flags] += 1
            entry = self.talkers.setdefault(remote_ip(rec.src, rec.dst), [0, 0])
            entry[0] += 1
            entry[1] += rec.size
            if rec.dns_name:
                self.dns_names[rec.dns_name] += 1
            self.recent.append(rec)

    @property
    def duration(self) -> float:
        if self.first_ts is None or self.last_ts is None:
            return 0.0
        return self.last_ts - self.first_ts
