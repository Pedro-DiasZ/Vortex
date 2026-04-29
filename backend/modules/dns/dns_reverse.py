import dns.reversename
import dns.resolver

def dns_reverse_resolver(ip):
    try:
        rev_name = dns.reversename.from_address(ip)
        reversed_dns = str(dns.resolver.resolve(rev_name, "PTR")[0])
        return {
            "ip": ip,
            "reversed_dns": reversed_dns,
            "found": True,
            "status": "PTR record found"
        }
    except dns.resolver.NoAnswer:
        return {"ip": ip, "reversed_dns": None, "found": False, "status": "No PTR record found"}
    except dns.resolver.NXDOMAIN:
        return {"ip": ip, "reversed_dns": None, "found": False, "status": "Domain not found"}
    except Exception as e:
        return {"ip": ip, "reversed_dns": None, "found": False, "status": f"Error: {str(e)}"}