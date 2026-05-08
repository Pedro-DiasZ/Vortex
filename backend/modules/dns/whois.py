import whois
from fastapi import HTTPException

from backend.security import assert_domain

def format_date(date):
    if isinstance(date, list):
        date = date[0]
    if date:
        return date.strftime("%Y-%m-%d")
    return None

def get_whois_info(domain):
    try:
        safe_domain = assert_domain(domain)
        w = whois.whois(safe_domain)
        return {
            "domain_name": w.domain_name,
            "registrar": w.registrar,
            "creation_date": format_date(w.creation_date),
            "expiration_date": format_date(w.expiration_date),
            "updated_date": format_date(w.updated_date),
            "name_servers": w.name_servers,
            "status": "WHOIS information retrieved successfully",
            "found": True
        }
    except HTTPException:
        raise
    except Exception:
        return {"error": "Falha ao consultar WHOIS", "status": "Failed to retrieve WHOIS information", "found": False}
