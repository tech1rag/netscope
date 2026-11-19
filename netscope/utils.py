"""Small helpers shared across modules."""
from __future__ import annotations

import ipaddress
import os

# Ports we can name without asking the OS.
COMMON_PORTS = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP",
    443: "HTTPS", 465: "SMTPS", 587: "SMTP", 853: "DoT", 993: "IMAPS",
    995: "POP3S", 1900: "SSDP", 3306: "MySQL", 3389: "RDP", 5353: "mDNS",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-alt", 8443: "HTTPS-alt",
    27017: "MongoDB",
}

# TCP flag bits, in the order we like to display them.
TCP_FLAG_BITS = [
    (0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"),
    (0x10, "ACK"), (0x20, "URG"), (0x40, "ECE"), (0x80, "CWR"),
]


def format_flags(value: int) -> str:
    """0x12 -> 'SYN+ACK'."""
    names = [name for bit, name in TCP_FLAG_BITS if value & bit]
    return "+".join(names) if names else "NONE"


def is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def remote_ip(src: str, dst: str) -> str:
    """Pick the 'other side' of a packet: the public address if there is one."""
    if is_public(dst):
        return dst
    if is_public(src):
        return src
    return dst


def human_bytes(n: float) -> str:
    if n < 1024:
        return f"{int(n)} B"
    for unit in ("KB", "MB", "GB"):
        n /= 1024
        if n < 1024 or unit == "GB":
            return f"{n:.1f} {unit}"
    return f"{n:.1f} GB"


def fmt_duration(seconds: float) -> str:
    seconds = int(max(seconds, 0))
    m, s = divmod(seconds, 60)
    h, m = divmod(m, 60)
    return f"{h:d}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"


def has_capture_privileges() -> bool:
    """True if we are root (Linux/macOS) or Administrator (Windows)."""
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return True
