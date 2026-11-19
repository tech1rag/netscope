"""Capture layer: turns raw scapy packets into simple PacketRecord objects."""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable, Optional

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import (  # noqa: E402
    ARP, DNS, DNSRR, ICMP, IP, TCP, UDP, AsyncSniffer, IPv6, PcapWriter, conf,
)

from .utils import COMMON_PORTS, format_flags  # noqa: E402

QTYPES = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 65: "HTTPS"}
ICMP_TYPES = {0: "Echo reply", 3: "Destination unreachable", 8: "Echo request", 11: "Time exceeded"}
ICMP6_TYPES = {
    128: "Echo request", 129: "Echo reply", 133: "Router solicitation",
    134: "Router advertisement", 135: "Neighbor solicitation", 136: "Neighbor advertisement",
}


@dataclass
class PacketRecord:
    time: float
    proto: str            # transport: TCP, UDP, ICMP, ICMPv6, ARP, Other
    src: str
    dst: str
    size: int
    sport: Optional[int] = None
    dport: Optional[int] = None
    flags: str = ""       # TCP flags, e.g. "SYN+ACK"
    service: str = ""     # application guess from the port, e.g. "HTTPS"
    svc_port: Optional[int] = None
    info: str = ""        # DNS / ICMP / ARP details
    dns_name: str = ""


def _service(proto: str, sport: Optional[int], dport: Optional[int]):
    """Guess the application from the ports. Returns (name, port)."""
    if sport is None or dport is None:
        return "", None
    known = [p for p in (dport, sport) if p in COMMON_PORTS]
    port = known[0] if known else min(sport, dport)
    name = COMMON_PORTS.get(port, "")
    if proto == "UDP" and port == 443:
        name = "QUIC"
    return name, port


def _as_list(field, limit: int = 4) -> list:
    """scapy 2.6+ gives lists for DNS qd/an; older versions give a chained packet."""
    if field is None:
        return []
    if isinstance(field, (list, tuple)):
        return list(field)[:limit]
    out, node = [], field
    while node is not None and isinstance(node, DNSRR) and len(out) < limit:
        out.append(node)
        node = node.payload if isinstance(node.payload, DNSRR) else None
    return out or [field]


def _dns_details(dns) -> tuple[str, str]:
    """Return (queried name, human-readable summary) for a DNS packet."""
    try:
        question = _as_list(dns.qd, 1)[0]
        name = question.qname.decode(errors="ignore").rstrip(".")
        qtype = QTYPES.get(question.qtype, str(question.qtype))
    except Exception:
        return "", "DNS message"
    if dns.qr == 0:
        return name, f"Query {qtype} {name}"
    answers = []
    try:
        for rr in _as_list(dns.an):
            data = rr.rdata
            if isinstance(data, bytes):
                data = data.decode(errors="ignore")
            elif isinstance(data, list):
                data = " ".join(d.decode(errors="ignore") if isinstance(d, bytes) else str(d) for d in data)
            answers.append(str(data).rstrip("."))
    except Exception:
        pass
    if answers:
        return name, f"Answer {name} -> {', '.join(answers)}"
    return name, f"Answer {name} (no records, rcode {dns.rcode})"


def parse_packet(pkt) -> Optional[PacketRecord]:
    """Convert a scapy packet to a PacketRecord (None if it is not IP/ARP)."""
    ts = float(pkt.time)
    size = len(pkt)

    if pkt.haslayer(ARP):
        a = pkt[ARP]
        info = f"Who has {a.pdst}? Tell {a.psrc}" if a.op == 1 else f"{a.psrc} is at {a.hwsrc}"
        return PacketRecord(ts, "ARP", a.psrc, a.pdst, size, info=info)

    if pkt.haslayer(IP):
        l3 = pkt[IP]
    elif pkt.haslayer(IPv6):
        l3 = pkt[IPv6]
    else:
        return None

    proto, sport, dport, flags, info, dns_name = "Other", None, None, "", "", ""

    if pkt.haslayer(TCP):
        t = pkt[TCP]
        proto, sport, dport = "TCP", int(t.sport), int(t.dport)
        flags = format_flags(int(t.flags))
    elif pkt.haslayer(UDP):
        u = pkt[UDP]
        proto, sport, dport = "UDP", int(u.sport), int(u.dport)
    elif pkt.haslayer(ICMP):
        code = pkt[ICMP].type
        proto, info = "ICMP", ICMP_TYPES.get(code, f"type {code}")
    elif pkt.haslayer(IPv6) and pkt[IPv6].nh == 58:
        payload = bytes(l3.payload)
        code = payload[0] if payload else -1
        proto, info = "ICMPv6", ICMP6_TYPES.get(code, f"type {code}")

    service, svc_port = _service(proto, sport, dport)

    if proto in ("UDP", "TCP") and pkt.haslayer(DNS):
        dns_name, info = _dns_details(pkt[DNS])
        if not service:
            service = "DNS"

    return PacketRecord(ts, proto, l3.src, l3.dst, size, sport, dport, flags,
                        service, svc_port, info, dns_name)


@dataclass
class PacketFilter:
    """What the user wants to see. Used both as a BPF string and in Python."""
    ips: frozenset = frozenset()
    domain: Optional[str] = None
    ports: tuple = ()
    proto: Optional[str] = None   # tcp | udp | icmp | dns | arp

    def bpf(self) -> str:
        parts = []
        if self.ips:
            host = " or ".join(f"host {ip}" for ip in sorted(self.ips))
            if self.domain:
                host += " or port 53"   # DNS lookups for the domain go to a resolver, not the target
            parts.append(f"({host})")
        proto_bpf = {"tcp": "tcp", "udp": "udp", "icmp": "(icmp or icmp6)", "arp": "arp", "dns": "port 53"}
        if self.proto:
            parts.append(proto_bpf[self.proto])
        if self.ports:
            parts.append("(" + " or ".join(f"port {p}" for p in self.ports) + ")")
        return " and ".join(parts)

    def describe(self) -> str:
        return self.bpf() or "all traffic"

    def matches(self, rec: PacketRecord) -> bool:
        if self.proto:
            if self.proto == "dns":
                if rec.service != "DNS":
                    return False
            elif self.proto == "icmp":
                if not rec.proto.startswith("ICMP"):
                    return False
            elif rec.proto.lower() != self.proto:
                return False
        if self.ports and rec.sport not in self.ports and rec.dport not in self.ports:
            return False
        if self.ips and rec.src not in self.ips and rec.dst not in self.ips:
            # Not the target's traffic, but keep DNS lookups for the target domain.
            return bool(self.domain and rec.dns_name and self.domain in rec.dns_name.lower())
        return True


def list_interfaces() -> list[tuple[str, str, str]]:
    """Return (name, ip, description) for each network interface."""
    try:
        return [(i.name, getattr(i, "ip", "") or "", getattr(i, "description", "") or "")
                for i in conf.ifaces.values()]
    except Exception:
        from scapy.all import get_if_list
        return [(n, "", "") for n in get_if_list()]


class CaptureSession:
    """Runs the sniffer in a background thread and feeds matching records to a callback."""

    def __init__(self, flt: PacketFilter, *, iface: Optional[str] = None,
                 offline: Optional[str] = None, write: Optional[str] = None,
                 on_record: Optional[Callable[[PacketRecord], None]] = None,
                 max_packets: int = 0):
        self.flt = flt
        self.on_record = on_record
        self.max_packets = max_packets
        self.count = 0
        self._writer = PcapWriter(write, sync=True) if write else None
        kwargs = {"prn": self._handle, "store": False}
        if offline:
            kwargs["offline"] = offline
        else:
            if iface:
                kwargs["iface"] = iface
            if flt.bpf():
                kwargs["filter"] = flt.bpf()
        self._sniffer = AsyncSniffer(**kwargs)

    def _handle(self, pkt) -> None:
        if self.max_packets and self.count >= self.max_packets:
            return
        rec = parse_packet(pkt)
        if rec is None or not self.flt.matches(rec):
            return
        self.count += 1
        if self._writer:
            self._writer.write(pkt)
        if self.on_record:
            self.on_record(rec)

    def start(self) -> None:
        self._sniffer.start()

    @property
    def finished(self) -> bool:
        if self.max_packets and self.count >= self.max_packets:
            return True
        thread = getattr(self._sniffer, "thread", None)
        return thread is not None and not thread.is_alive()

    @property
    def error(self) -> Optional[str]:
        exc = getattr(self._sniffer, "exception", None)
        return str(exc) if exc else None

    def stop(self) -> None:
        try:
            self._sniffer.stop()
        except Exception:
            pass   # already finished (e.g. a pcap file that was read completely)
        if self._writer:
            self._writer.close()
