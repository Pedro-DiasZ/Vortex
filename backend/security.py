import ipaddress
import re
import socket
from urllib.parse import urlparse

from fastapi import HTTPException


HOST_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9.-]+(?<!-)$")
MAX_TEXT_SIZE = 100_000
def _bad_request(message: str) -> None:
    raise HTTPException(status_code=400, detail=message)


def _normalize_hostname(value: str) -> str:
    value = (value or "").strip()
    if not value:
        _bad_request("Host vazio ou invalido.")

    parsed = urlparse(value if "://" in value else f"//{value}")
    host = (parsed.hostname or value).strip().rstrip(".")

    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        _bad_request("Host com caracteres invalidos.")

    labels = host.split(".")
    has_bad_label = any(
        not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
        for label in labels
    )

    if not HOST_RE.match(host) or has_bad_label:
        _bad_request("Host em formato invalido.")

    return host.lower()


def assert_domain(value: str) -> str:
    return _normalize_hostname(value)


def _is_public_ip(raw_ip: str) -> bool:
    try:
        ip = ipaddress.ip_address(raw_ip)
    except ValueError:
        return False
    return ip.is_global


def assert_public_host(value: str) -> str:
    host = _normalize_hostname(value)

    if _is_public_ip(host):
        return host

    try:
        ip = ipaddress.ip_address(host)
        if not ip.is_global:
            _bad_request("Alvos internos ou privados nao sao permitidos.")
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        _bad_request("Falha ao resolver o host informado.")

    resolved_ips = {info[4][0] for info in infos}
    if not resolved_ips or any(not _is_public_ip(ip) for ip in resolved_ips):
        _bad_request("Alvos internos ou privados nao sao permitidos.")

    return host


def assert_public_ip(value: str) -> str:
    value = (value or "").strip()
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        _bad_request("IP em formato invalido.")

    if not ip.is_global:
        _bad_request("IPs internos ou privados nao sao permitidos.")

    return str(ip)


def assert_public_url(value: str) -> str:
    value = (value or "").strip()
    if not value:
        _bad_request("URL vazia ou invalida.")
    if "://" not in value:
        value = f"https://{value}"

    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        _bad_request("A URL deve usar http ou https.")

    host = assert_public_host(parsed.hostname)
    port = f":{parsed.port}" if parsed.port else ""
    path = parsed.path or ""
    query = f"?{parsed.query}" if parsed.query else ""
    return f"{parsed.scheme}://{host}{port}{path}{query}"


def assert_port(port: int) -> int:
    if port < 1 or port > 65535:
        _bad_request("Porta fora do intervalo permitido.")
    return port


def limit_text(value: str, max_size: int = MAX_TEXT_SIZE) -> str:
    value = value or ""
    if len(value) > max_size:
        _bad_request("Conteudo muito grande para analise.")
    return value
