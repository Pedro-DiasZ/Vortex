import ssl
import socket
from datetime import datetime

def check_ssl(domain):
    conn = None
    try:
        context =ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        issuer = dict(x[0] for x in cert.get("issuer", []))
        issuer_name = issuer.get("organizationName", "Unknown")
        expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        days_remaining = (expires - datetime.utcnow()).days
        return {
            "domain": domain,
            "valid": True,
            "issuer": issuer_name,
            "notBefore": cert.get('notBefore'),
            "notAfter": cert.get('notAfter'),
            "subject": cert.get('subject'),
            "status": "SSL certificate is valid",
            "found": True,
            "days_remaining": days_remaining,
            "expires_on": expires.strftime("%Y-%m-%d"),
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
