import socket
from urllib.parse import urlparse

from ping3 import ping


def _normalize_host(host: str) -> str:
    host = (host or "").strip()
    if not host:
        return ""

    # Accept full URLs in the input field and extract only hostname.
    parsed = urlparse(host if "://" in host else f"//{host}")
    cleaned = parsed.hostname or host
    return cleaned.strip().strip("/")


def ping_host(host):
    normalized_host = _normalize_host(host)
    if not normalized_host:
        return {
            "host": host,
            "normalized_host": normalized_host,
            "status": "DOWN",
            "alive": False,
            "response_time_ms": None,
            "found": False,
            "reason": "Host vazio ou invalido"
        }

    try:
        resolved_ip = socket.gethostbyname(normalized_host)
    except socket.gaierror:
        return {
            "host": host,
            "normalized_host": normalized_host,
            "status": "DOWN",
            "alive": False,
            "response_time_ms": None,
            "found": False,
            "reason": "Falha na resolucao DNS do host"
        }

    try:
        result = ping(normalized_host, timeout=5)
        if result is None or result is False:
            return {
                "host": host,
                "normalized_host": normalized_host,
                "resolved_ip": resolved_ip,
                "alive": False,
                "status": "DOWN",
                "response_time_ms": None,
                "found": True,
                "reason": "Host resolveu, mas nao respondeu ao ICMP (timeout/firewall)"
            }

        return {
            "host": host,
            "normalized_host": normalized_host,
            "resolved_ip": resolved_ip,
            "alive": True,
            "status": "UP",
            "response_time_ms": round(result * 1000, 2),
            "found": True
        }

    except Exception as e:
        return {
            "host": host,
            "normalized_host": normalized_host,
            "status": "Failed to ping host",
            "found": False,
            "error": str(e)
        }
