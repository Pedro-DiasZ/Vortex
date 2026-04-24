import dns.resolver

def check_spf(domain):
    try:
        records = dns.resolver.resolve(domain, 'TXT')
        for record in records:
            text = record.to_text().strip('"')  
            if text.startswith('v=spf1'):
                return {"found": True, "record": text, "status": "SPF record found"}
        return {"found": False, "record": None, "status": "No SPF record found"}
    except dns.resolver.NoAnswer:
        return {"found": False, "record": None, "status": "No TXT records found"}
    except dns.resolver.NXDOMAIN:
        return {"found": False, "record": None, "status": "Domain not found"}
    