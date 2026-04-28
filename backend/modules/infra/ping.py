import socket
import subprocess
import sys
from urllib.parse import urlparse


def _normalize_host(host: str) -> str:
    host = (host or "").strip()
    if not host:
        return ""
    parsed = urlparse(host if "://" in host else f"//{host}")
    cleaned = parsed.hostname or host
    return cleaned.strip().strip("/")


def _tcp_reachable(host: str, timeout: int = 5) -> tuple[bool, int | None]:
    """Fallback: verifica alcançabilidade via TCP nas portas 443 e 80."""
    for port in (443, 80):
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True, port
        except (socket.timeout, ConnectionRefusedError, OSError):
            continue
    return False, None


def _system_ping(host: str) -> bool:
    """Fallback: usa o binário 'ping' do sistema operacional."""
    flag = "-n" if sys.platform == "win32" else "-c"
    try:
        result = subprocess.run(
            ["ping", flag, "1", "-W", "3", host],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False


def ping_host(host: str) -> dict:
    normalized_host = _normalize_host(host)

    if not normalized_host:
        return {
            "host": host,
            "normalized_host": normalized_host,
            "status": "DOWN",
            "alive": False,
            "response_time_ms": None,
            "found": False,
            "reason": "Host vazio ou inválido",
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
            "reason": "Falha na resolução DNS do host",
        }

    try:
        from ping3 import ping

        result = ping(normalized_host, timeout=5)

        if result is None or result is False:
            tcp_alive, tcp_port = _tcp_reachable(normalized_host)
            return {
                "host": host,
                "normalized_host": normalized_host,
                "resolved_ip": resolved_ip,
                "alive": tcp_alive,
                "status": "UP (TCP)" if tcp_alive else "DOWN",
                "response_time_ms": None,
                "found": True,
                "reason": (
                    f"ICMP bloqueado; alcançável via TCP porta {tcp_port}"
                    if tcp_alive
                    else "Host resolveu, mas não respondeu a ICMP nem TCP"
                ),
            }

        return {
            "host": host,
            "normalized_host": normalized_host,
            "resolved_ip": resolved_ip,
            "alive": True,
            "status": "UP",
            "response_time_ms": round(result * 1000, 2),
            "found": True,
        }

    except PermissionError:
        pass
    except Exception as e:
        pass


    if _system_ping(normalized_host):
        return {
            "host": host,
            "normalized_host": normalized_host,
            "resolved_ip": resolved_ip,
            "alive": True,
            "status": "UP (system ping)",
            "response_time_ms": None,
            "found": True,
            "reason": "ICMP via ping do sistema",
        }
    tcp_alive, tcp_port = _tcp_reachable(normalized_host)
    return {
        "host": host,
        "normalized_host": normalized_host,
        "resolved_ip": resolved_ip,
        "alive": tcp_alive,
        "status": f"UP (TCP:{tcp_port})" if tcp_alive else "DOWN",
        "response_time_ms": None,
        "found": True,
        "reason": (
            f"Sem permissão para ICMP; alcançável via TCP porta {tcp_port}"
            if tcp_alive
            else "Sem permissão para ICMP e sem resposta TCP"
        ),
    }
