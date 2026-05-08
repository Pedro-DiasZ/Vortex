import dns.resolver

from backend.network import DEFAULT_DNS_TIMEOUT
from backend.security import assert_public_ip

BLACKLISTS = [
    
    "zen.spamhaus.org",      
    "sbl.spamhaus.org",     
    "xbl.spamhaus.org",      
    "pbl.spamhaus.org",    
    "bl.spamcop.net",
    "b.barracudacentral.org",
    "dnsbl.sorbs.net",
    "spam.dnsbl.sorbs.net",
    "proxies.dnsbl.sorbs.net",
    "relays.dnsbl.sorbs.net",
    "dnsbl-1.uceprotect.net",
    "dnsbl-2.uceprotect.net",
    "dnsbl-3.uceprotect.net",
    "psbl.surriel.com",
    "db.wpbl.info",
    "bl.nordspam.com",
    "combined.abuse.ch",      
    "dnsbl.spfbl.net",
    "bl.mailspike.net",
    "ix.dnsbl.manitu.net",
    "bl.blocklist.de",
    "dnsbl.dronebl.org",
    "access.redhawk.org",
    "all.s5h.net",
    "virbl.dnsbl.bit.nl",
]



def check_blacklists(ip_adress):
    safe_ip = assert_public_ip(ip_adress)
    listed_on = []
    clean_on = []
    ip_reversed = ".".join(reversed(safe_ip.split(".")))
    resolver = dns.resolver.Resolver()
    resolver.timeout = DEFAULT_DNS_TIMEOUT
    resolver.lifetime = DEFAULT_DNS_TIMEOUT

    for bl in BLACKLISTS:
        query = f"{ip_reversed}.{bl}"
        try:
            resolver.resolve(query, 'A')
            listed_on.append(bl)
        except dns.resolver.NXDOMAIN:
            clean_on.append(bl)
        except Exception:
            continue

    return {
            "ip": safe_ip,
            "listed_on": listed_on,
            "clean_on": clean_on,
            "blacklisted": len(listed_on) > 0,
            "status": "Blacklisted" if listed_on else "Clean"
            }
