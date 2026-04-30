import re

from backend.modules.dns.lookup import dns_lookup
from backend.modules.dns.whois import get_whois_info
from backend.modules.email.blks import check_blacklists
from backend.modules.email.dkim import check_dkim
from backend.modules.email.dmarc import check_dmarc
from backend.modules.email.spf import check_spf
from backend.security import assert_domain


def _run_check(errors: list, name: str, func, *args):
    try:
        return func(*args)
    except Exception as e:
        errors.append({"check": name, "error": str(e)})
        return {"found": False, "status": f"{name} check failed", "error": str(e)}


def _extract_ipv4_records(result: dict) -> list:
    records = result.get("records") if isinstance(result, dict) else None
    if not isinstance(records, list):
        return []

    return [
        record
        for record in records
        if isinstance(record, str) and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", record)
    ]


def collect_email_health_data(domain: str) -> dict:
    normalized_domain = assert_domain(domain)
    errors = []
    notes = []

    dns_checks = {
        "a": _run_check(errors, "dns_a", dns_lookup, normalized_domain, "A"),
        "aaaa": _run_check(errors, "dns_aaaa", dns_lookup, normalized_domain, "AAAA"),
        "mx": _run_check(errors, "dns_mx", dns_lookup, normalized_domain, "MX"),
        "txt": _run_check(errors, "dns_txt", dns_lookup, normalized_domain, "TXT"),
        "ns": _run_check(errors, "dns_ns", dns_lookup, normalized_domain, "NS"),
    }

    spf = _run_check(errors, "spf", check_spf, normalized_domain)
    dmarc = _run_check(errors, "dmarc", check_dmarc, normalized_domain)
    dkim = _run_check(errors, "dkim", check_dkim, normalized_domain)
    whois = _run_check(errors, "whois", get_whois_info, normalized_domain)

    notes.append(
        "DKIM depende do selector utilizado; sem selector informado, o Vortex apenas tenta selectors comuns."
    )

    a_records = _extract_ipv4_records(dns_checks["a"])
    blacklist = None
    if a_records:
        ips_to_check = a_records[:1]
        if len(a_records) > 1:
            notes.append(
                "Consulta de blacklist limitada ao primeiro IPv4 encontrado para evitar tempo excessivo de resposta."
            )

        blacklist = {
            ip: _run_check(errors, f"blacklist_{ip}", check_blacklists, ip)
            for ip in ips_to_check
        }
    else:
        notes.append("Consulta de blacklist não executada porque nenhum registro A IPv4 foi encontrado.")

    return {
        "domain": normalized_domain,
        "checks": {
            "mx": dns_checks["mx"],
            "spf": spf,
            "dmarc": dmarc,
            "dkim": dkim,
            "dns": dns_checks,
            "blacklist": blacklist,
            "whois": whois,
        },
        "errors": errors,
        "notes": notes,
    }
