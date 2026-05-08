import smtplib
import socket

from fastapi import HTTPException

from backend.network import DEFAULT_SMTP_TIMEOUT
from backend.security import assert_allowed_smtp_port, assert_public_host

def check_smtp(host: str, port: int) -> dict:
    safe_host = assert_public_host(host)
    safe_port = assert_allowed_smtp_port(port)
    smtp_class = smtplib.SMTP_SSL if safe_port == 465 else smtplib.SMTP
    try:
        with smtp_class(safe_host, safe_port, timeout=DEFAULT_SMTP_TIMEOUT) as server:
            banner = server.welcome.decode('utf-8', errors='ignore') if server.welcome else "No banner received"
            code, message = server.ehlo()
            return {
                "host": safe_host,
                "port": safe_port,
                "online": True,
                "banner": banner.strip(),
                "status": "Ready" if code == 250 else f"Response code: {code}",
                "found": True
            }
    except HTTPException:
        raise
    except (smtplib.SMTPException, socket.error, Exception):
        return {
            "host": safe_host,
            "port": safe_port,
            "online": False,
            "status": "Offline or Connection Error",
            "error": "Falha ao conectar ao servidor SMTP",
            "found": False
        }
