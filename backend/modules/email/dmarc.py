import dns.resolver

def check_dmarc(domain):
    try:
        dmarc_domain = f"_dmarc.{domain}"
        records = dns.resolver.resolve(dmarc_domain, 'TXT')
        for record in records:
            text = record.to_text().strip('"')  
            if text.startswith('v=DMARC1'):
                return {"found": True, "record": text, "status": "DMARC record found"}
        return {"found": False, "record": None, "status": "No DMARC record found"}
    except dns.resolver.NoAnswer:
        return {"found": False, "record": None, "status": "No TXT records found for DMARC"}
    except dns.resolver.NXDOMAIN:
        return {"found": False, "record": None, "status": "Domain not found for DMARC"}