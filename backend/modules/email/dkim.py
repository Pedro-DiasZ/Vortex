import dns.resolver

COMMON_SELECTORS = ["default", "google", "mail", "s1", "s2", "k1", "dkim", "smtp", "email"]

def check_dkim(domain, selector=None):
    selectors_to_try = [selector] if selector else COMMON_SELECTORS

    for sel in selectors_to_try:
        try:
            dkim_domain = f"{sel}._domainkey.{domain}"
            records = dns.resolver.resolve(dkim_domain, 'TXT')
            for record in records:
                text = record.to_text().strip('"')
                if text.startswith('v=DKIM1'):
                    return {"found": True, "record": text, "selector": sel, "status": "DKIM record found"}
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            continue
        except Exception as e:
            continue

    return {"found": False, "record": None, "selector": None, "status": "No DKIM record found"}