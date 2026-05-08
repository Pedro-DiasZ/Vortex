import dns.resolver

from backend.network import DEFAULT_DNS_TIMEOUT
from backend.security import assert_domain

def dns_lookup(domain, record_type):
    try:
        safe_domain = assert_domain(domain)
        resolver = dns.resolver.Resolver()
        resolver.timeout = DEFAULT_DNS_TIMEOUT
        resolver.lifetime = DEFAULT_DNS_TIMEOUT
        records = resolver.resolve(safe_domain, record_type)
        result = [r.to_text() for r in records]
        return {
            "domain": safe_domain,
            "type": record_type,
            "records": result,
            "found": True,
            "status": ""
        }
    except dns.resolver.NoAnswer:
        return {"found": False, "record": None, "status": f"No {record_type} records found"}
    except dns.resolver.NXDOMAIN:
        return {"found": False, "record": None, "status": f"Domain not found"}
