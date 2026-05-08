import ssl
import socket
from datetime import datetime


def _tuple_to_dict(items):
    return dict(x[0] for x in items or [])


def check_ssl(domain):
    conn = None
    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
        conn.settimeout(10)
        conn.connect((domain, 443))
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
            "domain": domain,
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
    except ssl.SSLError as e:
        return {"domain": domain, "valid": False, "error": str(e), "status": "SSL certificate error", "found": False}
    except socket.error as e:
        return {"domain": domain, "valid": False, "error": str(e), "status": "Socket error", "found": False}
    except Exception as e:
        return {"domain": domain, "valid": False, "error": str(e), "status": "Failed to check SSL certificate", "found": False}
    finally:
        if conn:
            conn.close()
