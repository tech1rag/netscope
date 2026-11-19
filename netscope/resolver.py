"""Resolve the target (domain or IP) and collect basic DNS details."""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urlparse

import dns.exception
import dns.resolver
import dns.reversename


@dataclass
class TargetInfo:
    raw: str
    host: str
    kind: str                                   # "ip" or "domain"
    ips: list = field(default_factory=list)
    records: list = field(default_factory=list)  # (type, value, ttl)
    reverse: dict = field(default_factory=dict)  # ip -> hostname
    errors: list = field(default_factory=list)


def clean_target(raw: str) -> str:
    """Accept 'https://Example.com:8080/path' and return 'example.com'."""
    t = raw.strip()
    if "://" in t:
        t = urlparse(t).hostname or t
    else:
        t = t.split("/")[0]
    if t.count(":") == 1:        # host:port (but not IPv6)
        t = t.split(":")[0]
    return t.strip("[]").lower().rstrip(".")


def _make_resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.lifetime = 4
    return r


def _reverse(resolver, ip: str) -> str:
    try:
        rev = dns.reversename.from_address(ip)
        return str(resolver.resolve(rev, "PTR")[0]).rstrip(".")
    except Exception:
        return ""


def resolve_target(raw: str) -> TargetInfo:
    host = clean_target(raw)
    resolver = _make_resolver()
    try:
        ipaddress.ip_address(host)
        kind = "ip"
    except ValueError:
        kind = "domain"

    info = TargetInfo(raw=raw, host=host, kind=kind)

    if kind == "ip":
        info.ips = [host]
    else:
        for rtype in ("A", "AAAA", "CNAME", "NS", "MX", "TXT"):
            try:
                answer = resolver.resolve(host, rtype)
            except dns.resolver.NXDOMAIN:
                info.errors.append(f"'{host}' does not exist (NXDOMAIN). Check the spelling.")
                break
            except Exception:
                continue   # no records of this type, or a timeout
            ttl = answer.rrset.ttl
            for r in answer:
                if rtype in ("A", "AAAA"):
                    value = r.address
                    if value not in info.ips:
                        info.ips.append(value)
                elif rtype in ("CNAME", "NS"):
                    value = str(r.target).rstrip(".")
                elif rtype == "MX":
                    value = f"{r.preference} {str(r.exchange).rstrip('.')}"
                else:
                    value = b"".join(r.strings).decode(errors="ignore")
                    value = value if len(value) <= 70 else value[:67] + "..."
                info.records.append((rtype, value, ttl))
        if not info.ips and not info.errors:
            try:   # fall back to the OS resolver
                for fam, _, _, _, addr in socket.getaddrinfo(host, None):
                    if addr[0] not in info.ips:
                        info.ips.append(addr[0])
            except OSError:
                info.errors.append(f"Could not resolve '{host}'. Check the spelling and your connection.")

    for ip in info.ips[:4]:
        name = _reverse(resolver, ip)
        if name:
            info.reverse[ip] = name
            if kind == "ip":
                info.records.append(("PTR", name, None))
    return info
