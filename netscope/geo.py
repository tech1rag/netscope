"""IP geolocation using the free ipwho.is service (no API key needed).

Lookups run in background threads and are cached, so the live view never freezes.
Note: this sends the IP addresses you look up to ipwho.is. Use --no-geo to disable.
"""
from __future__ import annotations

import ipaddress
import json
import threading
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Optional


@dataclass
class GeoInfo:
    ip: str
    country: str = ""
    country_code: str = ""
    region: str = ""
    city: str = ""
    org: str = ""
    asn: str = ""
    lat: Optional[float] = None
    lon: Optional[float] = None
    note: str = ""   # used for private / special addresses

    @property
    def label(self) -> str:
        if self.note:
            return self.note
        parts = [p for p in (self.city, self.country_code or self.country) if p]
        return ", ".join(parts) or "Unknown"


class GeoLocator:
    URL = "https://ipwho.is/{ip}"

    def __init__(self, enabled: bool = True, max_lookups: int = 100):
        self.enabled = enabled
        self.max_lookups = max_lookups
        self._cache: dict[str, object] = {}   # ip -> GeoInfo or False (failed)
        self._pending: set[str] = set()
        self._lookups = 0
        self._lock = threading.Lock()
        self._pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="geo")

    @staticmethod
    def _special(ip: str) -> Optional[GeoInfo]:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return GeoInfo(ip, note="Invalid address")
        if addr.is_loopback:
            return GeoInfo(ip, note="Loopback")
        if addr.is_multicast:
            return GeoInfo(ip, note="Multicast")
        if addr.is_private or addr.is_link_local:
            return GeoInfo(ip, note="Private network")
        if not addr.is_global:
            return GeoInfo(ip, note="Reserved")
        return None

    def _fetch(self, ip: str) -> None:
        result: object = False
        try:
            req = urllib.request.Request(self.URL.format(ip=ip), headers={"User-Agent": "netscope/1.0"})
            with urllib.request.urlopen(req, timeout=4) as resp:
                data = json.load(resp)
            if data.get("success"):
                conn = data.get("connection") or {}
                result = GeoInfo(
                    ip=ip,
                    country=data.get("country", "") or "",
                    country_code=data.get("country_code", "") or "",
                    region=data.get("region", "") or "",
                    city=data.get("city", "") or "",
                    org=conn.get("org") or conn.get("isp") or "",
                    asn=str(conn.get("asn") or ""),
                    lat=data.get("latitude"),
                    lon=data.get("longitude"),
                )
        except Exception:
            pass
        with self._lock:
            self._cache[ip] = result
            self._pending.discard(ip)

    def get(self, ip: str) -> Optional[GeoInfo]:
        """Non-blocking: return cached info now, or start a lookup and return None."""
        if not self.enabled:
            return None
        special = self._special(ip)
        if special:
            return special
        with self._lock:
            cached = self._cache.get(ip)
            if isinstance(cached, GeoInfo):
                return cached
            if cached is False or ip in self._pending or self._lookups >= self.max_lookups:
                return None
            self._pending.add(ip)
            self._lookups += 1
        self._pool.submit(self._fetch, ip)
        return None

    def lookup(self, ip: str) -> Optional[GeoInfo]:
        """Blocking version, used for the target and the summary."""
        if not self.enabled:
            return None
        special = self._special(ip)
        if special:
            return special
        with self._lock:
            cached = self._cache.get(ip)
        if cached is None:
            self._fetch(ip)
            cached = self._cache.get(ip)
        return cached if isinstance(cached, GeoInfo) else None

    def close(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)
