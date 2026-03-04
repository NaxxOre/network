import ipaddress
import httpx
from fastapi import Request


def _is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _parse_ip(value: str) -> ipaddress._BaseAddress | None:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def normalize_public_ip(value: str | None) -> str | None:
    if not value:
        return None
    candidate = value.strip()
    if not candidate:
        return None
    parsed = _parse_ip(candidate)
    if not parsed:
        return None
    if (
        parsed.is_private
        or parsed.is_loopback
        or parsed.is_link_local
        or parsed.is_multicast
        or parsed.is_reserved
        or parsed.is_unspecified
    ):
        return None
    return str(parsed)


def normalize_country_code(value: str | None) -> str | None:
    if not value:
        return None
    candidate = value.strip().upper()
    if len(candidate) != 2 or not candidate.isalpha():
        return None
    return candidate


def resolve_source_ip(request: Request) -> str | None:
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        for part in forwarded_for.split(","):
            candidate = part.strip()
            if candidate and _is_valid_ip(candidate):
                return candidate

    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        candidate = real_ip.strip()
        if candidate and _is_valid_ip(candidate):
            return candidate

    return request.client.host if request.client else None


def extract_acl_link(link_header: str) -> str | None:
    if not link_header:
        return None
    parts = [p.strip() for p in link_header.split(",")]
    for p in parts:
        if 'rel="acl"' in p or "rel=acl" in p:
            start = p.find("<")
            end = p.find(">")
            if start != -1 and end != -1 and end > start:
                return p[start + 1:end]
    return None


def resource_url_for(resource_base: str, subpath: str) -> str:
    return f"{resource_base}/r/{subpath}"


async def fetch_acl_for(resource_base: str, subpath: str) -> str:
    async with httpx.AsyncClient(timeout=5) as client:
        r = await client.get(f"{resource_base}/acl/{subpath}")
        r.raise_for_status()
        return r.text
