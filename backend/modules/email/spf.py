import dns.resolver


def _resolve(name, record_type):
    resolver = dns.resolver.Resolver()
    resolver.timeout = 1.5
    resolver.lifetime = 3
    return resolver.resolve(name, record_type)

def resolve_spf_mechanism(mechanism, depth=0):
    """Resolve um mecanismo SPF e retorna lista de IPs/CIDRs."""
    if depth > 5:
        return []
    
    ips = []
    
    try:
        if mechanism.startswith('include:'):
            domain = mechanism[8:]
            records = _resolve(domain, 'TXT')
            for r in records:
                txt = r.to_text().strip('"')
                if txt.startswith('v=spf1'):
                    for part in txt.split():
                        if part.startswith('ip4:') or part.startswith('ip6:'):
                            ips.append(part)
                        elif part.startswith('include:'):
                            ips.extend(resolve_spf_mechanism(part, depth + 1))
                    break

        elif mechanism == 'mx' or mechanism.startswith('mx:'):
            domain = mechanism[3:] if mechanism.startswith('mx:') else None
            if domain:
                mx_records = _resolve(domain, 'MX')
                for mx in mx_records:
                    try:
                        a_records = _resolve(str(mx.exchange), 'A')
                        for a in a_records:
                            ips.append(f"ip4:{a.address}/32")
                    except Exception:
                        pass

        elif mechanism.startswith('a:'):
            domain = mechanism[2:]
            a_records = _resolve(domain, 'A')
            for a in a_records:
                ips.append(f"ip4:{a.address}/32")

    except Exception:
        pass

    return ips


def check_spf(domain):
    try:
        records = _resolve(domain, 'TXT')
        for record in records:
            text = record.to_text().strip('"')
            if text.startswith('v=spf1'):
                resolved = {}
                for part in text.split():
                    if part in ('v=spf1', '-all', '~all', '+all', '?all'):
                        continue

                    ips = []

                    if part.startswith('ip4:') or part.startswith('ip6:'):
                        ips = [part]

                    elif part.startswith('include:'):
                        ips = resolve_spf_mechanism(part)

                    elif part == 'mx':
                        try:
                            mx_records = _resolve(domain, 'MX')
                            for mx in mx_records:
                                try:
                                    a_records = _resolve(str(mx.exchange), 'A')
                                    for a in a_records:
                                        ips.append(f"ip4:{a.address}/32")
                                except Exception:
                                    pass
                        except Exception:
                            pass

                    elif part.startswith('mx:'):
                        ips = resolve_spf_mechanism(part)

                    elif part.startswith('a:'):
                        ips = resolve_spf_mechanism(part)

                    if ips:
                        resolved[part] = ips

                return {
                    "found": True,
                    "record": text,
                    "resolved": resolved,
                    "status": "SPF record found"
                }

        return {"found": False, "record": None, "resolved": {}, "status": "No SPF record found"}
    except dns.resolver.NoAnswer:
        return {"found": False, "record": None, "resolved": {}, "status": "No TXT records found"}
    except dns.resolver.NXDOMAIN:
        return {"found": False, "record": None, "resolved": {}, "status": "Domain not found"}
    except Exception as e:
        return {"found": False, "record": None, "resolved": {}, "status": "SPF check failed", "error": str(e)}
