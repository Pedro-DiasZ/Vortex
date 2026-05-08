import socket

import httpx
import requests

from backend.security import (
    assert_allowed_public_port,
    assert_public_host,
    assert_public_url,
)


DEFAULT_HTTP_TIMEOUT = 8
DEFAULT_SOCKET_TIMEOUT = 5
DEFAULT_SMTP_TIMEOUT = 5
DEFAULT_SSL_TIMEOUT = 5
DEFAULT_DNS_TIMEOUT = 4
MAX_RESPONSE_BYTES = 1_000_000

DEFAULT_HEADERS = {
    "User-Agent": "VortexTools/1.0",
}


def _validate_content_length(headers) -> None:
    raw_length = headers.get("content-length")
    if not raw_length:
        return

    try:
        content_length = int(raw_length)
    except ValueError:
        return

    if content_length > MAX_RESPONSE_BYTES:
        raise ValueError("Resposta externa excede o tamanho maximo permitido.")


def safe_requests_get(url, timeout=DEFAULT_HTTP_TIMEOUT, allow_redirects=False):
    safe_url = assert_public_url(url)
    timeout = timeout or DEFAULT_HTTP_TIMEOUT
    response = requests.get(
        safe_url,
        timeout=timeout,
        allow_redirects=allow_redirects,
        headers=DEFAULT_HEADERS,
        stream=True,
    )
    _validate_content_length(response.headers)
    return response


def safe_httpx_get(url, timeout=DEFAULT_HTTP_TIMEOUT, follow_redirects=False):
    safe_url = assert_public_url(url)
    timeout = timeout or DEFAULT_HTTP_TIMEOUT
    response = httpx.get(
        safe_url,
        timeout=timeout,
        follow_redirects=follow_redirects,
        headers=DEFAULT_HEADERS,
    )
    _validate_content_length(response.headers)
    return response


def safe_socket_connect(host, port, timeout=DEFAULT_SOCKET_TIMEOUT):
    safe_host = assert_public_host(host)
    safe_port = assert_allowed_public_port(port)
    timeout = timeout or DEFAULT_SOCKET_TIMEOUT
    return socket.create_connection((safe_host, safe_port), timeout=timeout)
