import dns.resolver

from backend.network import DEFAULT_DNS_TIMEOUT
from backend.security import assert_domain

def check_propagation(domain: str, record_type: str = 'A') -> dict:
    safe_domain = assert_domain(domain)
    nameservers = {
        "Google": "8.8.8.8",
        "Cloudflare": "1.1.1.1",
        "Quad9": "9.9.9.9"
    }
    results = []
    unique_answers = set()
    for provider, ns in nameservers.items():
        try:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = [ns]
            resolver.timeout = DEFAULT_DNS_TIMEOUT
            resolver.lifetime = DEFAULT_DNS_TIMEOUT
            
            query = resolver.resolve(safe_domain, record_type)
            ips = [answer.to_text() for answer in query]
            ips.sort()
            
            unique_answers.add(tuple(ips))
            results.append({
                "provider": provider,
                "nameserver": ns,
                "ips": ips,
                "status": "Success"
            })  
        except Exception as e:
            results.append({
                "provider": provider,
                "nameserver": ns,
                "ips": [],
                "status": f"Error: {type(e).__name__}"
            })
    is_propagated = len(unique_answers) == 1 and len(results) == len([r for r in results if r["status"] == "Success"])
    return {
        "domain": safe_domain,
        "record_type": record_type,
        "results": results,
        "propagated": is_propagated,
        "found": len(unique_answers) > 0,
        "status": "Propagated" if is_propagated else "In propagation or mismatch"
    }
