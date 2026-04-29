import whois

def format_date(date):
    if isinstance(date, list):
        date = date[0]
    if date:
        return date.strftime("%Y-%m-%d")
    return None

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
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
    except Exception as e:
        return {"error": str(e), "status": "Failed to retrieve WHOIS information", "found": False}