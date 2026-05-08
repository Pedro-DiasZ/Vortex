import ssl
import socket
from datetime import datetime

from fastapi import HTTPException

from backend.network import DEFAULT_SSL_TIMEOUT
from backend.security import assert_public_host


def _tuple_to_dict(items):
    return dict(x[0] for x in items or [])


def check_ssl(domain):
    raw_conn = None
    conn = None
    try:
        safe_domain = assert_public_host(domain)
        context = ssl.create_default_context()
        raw_conn = socket.create_connection((safe_domain, 443), timeout=DEFAULT_SSL_TIMEOUT)
        conn = context.wrap_socket(raw_conn, server_hostname=safe_domain)
        raw_conn = None
        cert = conn.getpeercert()
        issuer = _tuple_to_dict(cert.get("issuer"))
        subject = _tuple_to_dict(cert.get("subject"))
        issuer_name = issuer.get("organizationName", "Unknown")
        expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        starts = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
        days_remaining = (expires - datetime.utcnow()).days
        san = [
            value
            for key, value in cert.get("subjectAltName", [])
            if key.lower() == "dns"
        ]

        return {
            "domain": safe_domain,
            "valid": True,
            "issuer": issuer_name,
            "notBefore": cert.get('notBefore'),
            "notAfter": cert.get('notAfter'),
            "valid_from": starts.strftime("%Y-%m-%d"),
            "expires_on": expires.strftime("%Y-%m-%d"),
            "days_remaining": days_remaining,
            "subject": cert.get('subject'),
            "subject_summary": subject,
            "san": san,
            "status": "SSL certificate is valid",
            "found": True,
        }
    except HTTPException:
        raise
    except ssl.SSLError:
        return {"domain": domain, "valid": False, "error": "Erro no certificado SSL", "status": "SSL certificate error", "found": False}
    except socket.error:
        return {"domain": domain, "valid": False, "error": "Falha de conexao SSL", "status": "Socket error", "found": False}
    except Exception:
        return {"domain": domain, "valid": False, "error": "Falha ao verificar certificado SSL", "status": "Failed to check SSL certificate", "found": False}
    finally:
        if conn:
            conn.close()
        if raw_conn:
            raw_conn.close()
