import dns.resolver

def dns_lookup(domain, record_type):
    try:
        records = dns.resolver.resolve(domain, record_type)
        result = [r.to_text() for r in records]
        return {
            "domain": domain,
            "type": record_type,
            "records": result,
            "found": True,
            "status": ""
        }
    except dns.resolver.NoAnswer:
        return {"found": False, "record": None, "status": f"No {record_type} records found"}
    except dns.resolver.NXDOMAIN:
        return {"found": False, "record": None, "status": f"Domain not found"}