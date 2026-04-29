import dns.resolver

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
    listed_on = []
    clean_on = []
    ip_reversed = ".".join(reversed(ip_adress.split(".")))
    for bl in BLACKLISTS:
        query = f"{ip_reversed}.{bl}"
        try:
            dns.resolver.resolve(query, 'A')
            listed_on.append(bl)
        except dns.resolver.NXDOMAIN:
            clean_on.append(bl)
        except Exception as e:
            continue

    return {
            "ip": ip_adress,
            "listed_on": listed_on,
            "clean_on": clean_on,
            "blacklisted": len(listed_on) > 0,
            "status": "Blacklisted" if listed_on else "Clean"
            }
