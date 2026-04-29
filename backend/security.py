import ipaddress
import re
import socket
import time
from collections import defaultdict, deque
from urllib.parse import urlparse

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware


HOST_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9.-]+(?<!-)$")
MAX_TEXT_SIZE = 100_000
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_DEFAULT = 60
RATE_LIMIT_STRICT = 20

STRICT_PATHS = (
    "/api/blacklists",
    "/api/dns-propagation",
    "/api/http-status",
    "/api/ping",
    "/api/port-checker",
    "/api/security/hibp/password",
    "/api/smtp",
    "/api/ssl",
    "/api/uptime",
)


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


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self.requests = defaultdict(deque)

    async def dispatch(self, request: Request, call_next):
        if not request.url.path.startswith("/api"):
            return await call_next(request)

        forwarded_for = request.headers.get("x-forwarded-for", "")
        client_ip = forwarded_for.split(",", 1)[0].strip() if forwarded_for else ""
        client_ip = client_ip or (request.client.host if request.client else "unknown")
        key = (client_ip, request.url.path)
        limit = RATE_LIMIT_STRICT if request.url.path in STRICT_PATHS else RATE_LIMIT_DEFAULT
        now = time.monotonic()
        bucket = self.requests[key]

        while bucket and now - bucket[0] > RATE_LIMIT_WINDOW:
            bucket.popleft()

        if len(bucket) >= limit:
            return JSONResponse(
                status_code=429,
                content={"detail": "Muitas requisicoes. Tente novamente em instantes."},
            )

        bucket.append(now)
        return await call_next(request)
