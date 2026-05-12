from concurrent.futures import ThreadPoolExecutor, as_completed
import dns.exception
import dns.message
import dns.rcode
import dns.resolver
import requests


ALLOWED_RECORD_TYPES = {"A", "AAAA", "CNAME", "MX", "TXT", "NS"}

RESOLVERS = [
    {"id": "google-1", "country": "United States", "provider": "Google DNS", "resolver": "8.8.8.8", "doh": "https://dns.google/dns-query", "x": 27, "y": 40},
    {"id": "google-2", "country": "United States", "provider": "Google DNS", "resolver": "8.8.4.4", "doh": "https://dns.google/dns-query", "x": 15, "y": 45},
    {"id": "cloudflare-1", "country": "Global", "provider": "Cloudflare", "resolver": "1.1.1.1", "doh": "https://cloudflare-dns.com/dns-query", "x": 19, "y": 47},
    {"id": "cloudflare-2", "country": "Global", "provider": "Cloudflare", "resolver": "1.0.0.1", "doh": "https://cloudflare-dns.com/dns-query", "x": 50, "y": 34},
    {"id": "quad9-1", "country": "Switzerland", "provider": "Quad9", "resolver": "9.9.9.9", "doh": "https://dns.quad9.net/dns-query", "x": 52, "y": 40},
    {"id": "quad9-2", "country": "Switzerland", "provider": "Quad9", "resolver": "149.112.112.112", "doh": "https://dns.quad9.net/dns-query", "x": 54, "y": 35},
    {"id": "opendns-1", "country": "United States", "provider": "OpenDNS", "resolver": "208.67.222.222", "doh": "https://doh.opendns.com/dns-query", "x": 14, "y": 43},
    {"id": "opendns-2", "country": "United States", "provider": "OpenDNS", "resolver": "208.67.220.220", "doh": "https://doh.opendns.com/dns-query", "x": 29, "y": 43},
    {"id": "adguard-1", "country": "Global", "provider": "AdGuard DNS", "resolver": "94.140.14.14", "doh": "https://dns.adguard-dns.com/dns-query", "x": 58, "y": 52},
    {"id": "adguard-2", "country": "Global", "provider": "AdGuard DNS", "resolver": "94.140.15.15", "doh": "https://dns.adguard-dns.com/dns-query", "x": 78, "y": 70},
    {"id": "cleanbrowsing-1", "country": "United States", "provider": "CleanBrowsing", "resolver": "185.228.168.9", "doh": "https://doh.cleanbrowsing.org/doh/security-filter/", "x": 25, "y": 44},
    {"id": "cleanbrowsing-2", "country": "United States", "provider": "CleanBrowsing", "resolver": "185.228.169.9", "doh": "https://doh.cleanbrowsing.org/doh/security-filter/", "x": 17, "y": 41},
    {"id": "controld-1", "country": "Canada", "provider": "Control D", "resolver": "76.76.2.0", "doh": "https://freedns.controld.com/p0", "x": 21, "y": 26},
    {"id": "controld-2", "country": "Canada", "provider": "Control D", "resolver": "76.76.10.0", "doh": "https://freedns.controld.com/p0", "x": 29, "y": 30},
    {"id": "dns0", "country": "European Union", "provider": "DNS0.eu", "resolver": "193.110.81.0", "doh": "https://dns0.eu/dns-query", "x": 47, "y": 42},
    {"id": "br", "country": "Brazil", "provider": "Google DNS", "resolver": "8.8.8.8", "doh": "https://dns.google/dns-query", "x": 31, "y": 74},
    {"id": "ar", "country": "Argentina", "provider": "Cloudflare", "resolver": "1.1.1.1", "doh": "https://cloudflare-dns.com/dns-query", "x": 28, "y": 86},
    {"id": "uk", "country": "United Kingdom", "provider": "Quad9", "resolver": "9.9.9.9", "doh": "https://dns.quad9.net/dns-query", "x": 46, "y": 32},
    {"id": "de", "country": "Germany", "provider": "Cloudflare", "resolver": "1.0.0.1", "doh": "https://cloudflare-dns.com/dns-query", "x": 52, "y": 37},
    {"id": "fr", "country": "France", "provider": "OpenDNS", "resolver": "208.67.222.222", "doh": "https://doh.opendns.com/dns-query", "x": 48, "y": 41},
    {"id": "nl", "country": "Netherlands", "provider": "DNS0.eu", "resolver": "193.110.81.0", "doh": "https://dns0.eu/dns-query", "x": 49, "y": 31},
    {"id": "in", "country": "India", "provider": "Google DNS", "resolver": "8.8.4.4", "doh": "https://dns.google/dns-query", "x": 68, "y": 59},
    {"id": "sg", "country": "Singapore", "provider": "AdGuard DNS", "resolver": "94.140.14.14", "doh": "https://dns.adguard-dns.com/dns-query", "x": 76, "y": 70},
    {"id": "jp", "country": "Japan", "provider": "Quad9", "resolver": "149.112.112.112", "doh": "https://dns.quad9.net/dns-query", "x": 86, "y": 37},
    {"id": "kr", "country": "South Korea", "provider": "Control D", "resolver": "76.76.2.0", "doh": "https://freedns.controld.com/p0", "x": 81, "y": 42},
    {"id": "au", "country": "Australia", "provider": "Cloudflare", "resolver": "1.1.1.1", "doh": "https://cloudflare-dns.com/dns-query", "x": 86, "y": 88},
]


def _normalize_record_type(record_type: str) -> str:
    normalized = (record_type or "A").strip().upper()
    if normalized not in ALLOWED_RECORD_TYPES:
        raise ValueError("Unsupported DNS record type")
    return normalized


def _format_error(error: Exception) -> str:
    if isinstance(error, dns.resolver.NXDOMAIN):
        return "domain not found"
    if isinstance(error, dns.resolver.NoAnswer):
        return "no answer"
    if isinstance(error, dns.resolver.NoNameservers):
        return "no nameservers"
    if isinstance(error, dns.exception.Timeout):
        return "timeout"
    return type(error).__name__


def _answers_from_response(response: dns.message.Message) -> list[str]:
    if response.rcode() == dns.rcode.NXDOMAIN:
        raise dns.resolver.NXDOMAIN()

    answers = []
    for rrset in response.answer:
        for answer in rrset:
            answers.append(answer.to_text())
    return sorted(set(answers))


def _resolve_with_udp(resolver_config: dict, domain: str, record_type: str) -> list[str]:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [resolver_config["resolver"]]
    resolver.timeout = 2
    resolver.lifetime = 3
    query = resolver.resolve(domain, record_type)
    return sorted(answer.to_text() for answer in query)


def _resolve_with_doh(resolver_config: dict, domain: str, record_type: str) -> list[str]:
    doh_url = resolver_config.get("doh")
    if not doh_url:
        return []

    query = dns.message.make_query(domain, record_type)
    http_response = requests.post(
        doh_url,
        data=query.to_wire(),
        headers={
            "accept": "application/dns-message",
            "content-type": "application/dns-message",
        },
        timeout=5,
    )
    http_response.raise_for_status()
    return _answers_from_response(dns.message.from_wire(http_response.content))


def _check_resolver(resolver_config: dict, domain: str, record_type: str) -> dict:
    try:
        try:
            answers = _resolve_with_udp(resolver_config, domain, record_type)
            transport = "udp"
        except Exception:
            answers = _resolve_with_doh(resolver_config, domain, record_type)
            transport = "doh"

        return {
            **resolver_config,
            "status": "ok" if answers else "fail",
            "answers": answers,
            "error": None if answers else "empty response",
            "provider": resolver_config.get("provider") or resolver_config["country"],
            "nameserver": resolver_config["resolver"],
            "transport": transport,
            "ips": answers,
        }
    except Exception as error:
        return {
            **resolver_config,
            "status": "fail",
            "answers": [],
            "error": _format_error(error),
            "provider": resolver_config.get("provider") or resolver_config["country"],
            "nameserver": resolver_config["resolver"],
            "ips": [],
        }


def check_propagation(domain: str, record_type: str = "A", resolver_id: str | None = None) -> dict:
    record_type = _normalize_record_type(record_type)
    domain = (domain or "").strip().rstrip(".")
    selected_resolvers = RESOLVERS

    if resolver_id:
        selected_resolvers = [resolver for resolver in RESOLVERS if resolver["id"] == resolver_id]
        if not selected_resolvers:
            raise ValueError("Unknown DNS resolver")

    if resolver_id:
        results = [_check_resolver(selected_resolvers[0], domain, record_type)]
    else:
        results = []
        with ThreadPoolExecutor(max_workers=min(8, len(selected_resolvers))) as executor:
            futures = [executor.submit(_check_resolver, resolver, domain, record_type) for resolver in selected_resolvers]
            for future in as_completed(futures):
                results.append(future.result())
        order = {resolver["id"]: index for index, resolver in enumerate(RESOLVERS)}
        results.sort(key=lambda item: order.get(item["id"], 999))

    ok_results = [result for result in results if result["status"] == "ok"]
    failed_results = [result for result in results if result["status"] == "fail"]
    unique_answers = {tuple(result["answers"]) for result in ok_results}
    is_propagated = bool(ok_results) and len(ok_results) == len(results) and len(unique_answers) == 1

    return {
        "domain": domain,
        "type": record_type,
        "record_type": record_type,
        "total": len(results),
        "ok": len(ok_results),
        "failed": len(failed_results),
        "results": results,
        "propagated": is_propagated,
        "found": bool(ok_results),
        "status": "Propagated" if is_propagated else "In propagation or mismatch",
    }
