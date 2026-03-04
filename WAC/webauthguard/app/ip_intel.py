import os
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import httpx

try:
    from .request_utils import normalize_public_ip, normalize_country_code
except ImportError:
    from request_utils import normalize_public_ip, normalize_country_code


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
        return value if value > 0 else default
    except ValueError:
        return default


@dataclass
class IPIntel:
    ip: str | None
    country_code: str | None
    vpn_suspected: bool


class IPIntelResolver:
    def __init__(self) -> None:
        self.enabled = os.environ.get("IP_INTEL_ENABLED", "true").lower() == "true"
        self.timeout_seconds = _env_int("IP_INTEL_TIMEOUT_SECONDS", 3)
        self.cache_ttl_seconds = _env_int("IP_INTEL_CACHE_TTL_SECONDS", 3600)
        self.allow_egress_fallback = os.environ.get("IP_INTEL_ALLOW_EGRESS_FALLBACK", "true").lower() == "true"
        self.egress_cache_ttl_seconds = _env_int("IP_INTEL_EGRESS_CACHE_TTL_SECONDS", 300)
        self._cache: dict[str, tuple[datetime, IPIntel]] = {}
        self._egress_ip_cache: tuple[datetime, str] | None = None
        self._lock = threading.Lock()

    async def lookup(self, ip: str | None) -> IPIntel:
        lookup_ip = normalize_public_ip(ip)
        if not lookup_ip and self.allow_egress_fallback:
            lookup_ip = await self._resolve_egress_public_ip()

        if not self.enabled or not lookup_ip:
            return IPIntel(ip=lookup_ip, country_code=None, vpn_suspected=False)

        cached = self._cache_get(lookup_ip)
        if cached:
            return cached

        intel = await self._lookup_ip_api(lookup_ip)
        if intel is None:
            intel = await self._lookup_ipwhois(lookup_ip)
        if intel is None:
            intel = IPIntel(ip=lookup_ip, country_code=None, vpn_suspected=False)

        self._cache_set(lookup_ip, intel)
        return intel

    async def _lookup_ip_api(self, ip: str) -> IPIntel | None:
        url = f"http://ip-api.com/json/{ip}?fields=status,countryCode,proxy,hosting"
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.get(url)
                if response.status_code != 200:
                    return None
                data = response.json()
        except Exception:
            return None

        if data.get("status") != "success":
            return None

        country_code = normalize_country_code(data.get("countryCode"))
        vpn_suspected = bool(data.get("proxy")) or bool(data.get("hosting"))
        return IPIntel(ip=ip, country_code=country_code, vpn_suspected=vpn_suspected)

    async def _lookup_ipwhois(self, ip: str) -> IPIntel | None:
        url = f"https://ipwho.is/{ip}"
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.get(url)
                if response.status_code != 200:
                    return None
                data = response.json()
        except Exception:
            return None

        if data.get("success") is False:
            return None

        country_code = normalize_country_code(data.get("country_code"))
        security = data.get("security") or {}
        connection = data.get("connection") or {}
        vpn_suspected = (
            bool(security.get("vpn"))
            or bool(security.get("proxy"))
            or bool(security.get("tor"))
            or str(connection.get("type", "")).lower() in {"hosting", "proxy"}
        )
        return IPIntel(ip=ip, country_code=country_code, vpn_suspected=vpn_suspected)

    def _cache_get(self, ip: str) -> IPIntel | None:
        now = datetime.now(timezone.utc)
        with self._lock:
            item = self._cache.get(ip)
            if not item:
                return None
            cached_at, intel = item
            if (now - cached_at).total_seconds() > self.cache_ttl_seconds:
                self._cache.pop(ip, None)
                return None
            return intel

    def _cache_set(self, ip: str, intel: IPIntel) -> None:
        with self._lock:
            self._cache[ip] = (datetime.now(timezone.utc), intel)

    async def _resolve_egress_public_ip(self) -> str | None:
        cached = self._egress_cache_get()
        if cached:
            return cached

        ip = await self._lookup_ipify()
        if not ip:
            ip = await self._lookup_ipwhois_for_egress()
        if not ip:
            return None

        self._egress_cache_set(ip)
        return ip

    async def _lookup_ipify(self) -> str | None:
        url = "https://api.ipify.org?format=json"
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.get(url)
                if response.status_code != 200:
                    return None
                data = response.json()
        except Exception:
            return None

        return normalize_public_ip(data.get("ip"))

    async def _lookup_ipwhois_for_egress(self) -> str | None:
        url = "https://ipwho.is/"
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.get(url)
                if response.status_code != 200:
                    return None
                data = response.json()
        except Exception:
            return None

        if data.get("success") is False:
            return None
        return normalize_public_ip(data.get("ip"))

    def _egress_cache_get(self) -> str | None:
        now = datetime.now(timezone.utc)
        with self._lock:
            if not self._egress_ip_cache:
                return None
            cached_at, cached_ip = self._egress_ip_cache
            if (now - cached_at).total_seconds() > self.egress_cache_ttl_seconds:
                self._egress_ip_cache = None
                return None
            return cached_ip

    def _egress_cache_set(self, ip: str) -> None:
        with self._lock:
            self._egress_ip_cache = (datetime.now(timezone.utc), ip)
