from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.exception
import dns.resolver


ALLOWED_RECORD_TYPES = {"A", "AAAA", "CNAME", "MX", "TXT", "NS"}

RESOLVERS = [
    {"id": "us-ny", "country": "United States NY", "resolver": "8.8.8.8", "x": 24, "y": 39},
    {"id": "us-la", "country": "United States LA", "resolver": "8.8.4.4", "x": 16, "y": 43},
    {"id": "ca", "country": "Canada", "resolver": "8.26.56.26", "x": 22, "y": 30},
    {"id": "br", "country": "Brazil", "resolver": "200.221.11.100", "x": 35, "y": 68},
    {"id": "ar", "country": "Argentina", "resolver": "200.49.158.1", "x": 31, "y": 79},
    {"id": "uk", "country": "United Kingdom", "resolver": "195.99.66.220", "x": 47, "y": 33},
    {"id": "de", "country": "Germany", "resolver": "217.237.151.51", "x": 51, "y": 36},
    {"id": "fr", "country": "France", "resolver": "80.67.169.40", "x": 49, "y": 40},
    {"id": "nl", "country": "Netherlands", "resolver": "213.46.228.196", "x": 50, "y": 34},
    {"id": "in", "country": "India", "resolver": "203.94.227.66", "x": 68, "y": 53},
    {"id": "sg", "country": "Singapore", "resolver": "165.21.83.88", "x": 75, "y": 62},
    {"id": "jp", "country": "Japan", "resolver": "202.12.27.33", "x": 84, "y": 43},
    {"id": "kr", "country": "South Korea", "resolver": "164.124.101.2", "x": 81, "y": 42},
    {"id": "cn", "country": "China", "resolver": "114.114.114.114", "x": 76, "y": 45},
    {"id": "au", "country": "Australia", "resolver": "203.50.2.71", "x": 82, "y": 76},
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


def _check_resolver(resolver_config: dict, domain: str, record_type: str) -> dict:
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [resolver_config["resolver"]]
        resolver.timeout = 3
        resolver.lifetime = 5

        query = resolver.resolve(domain, record_type)
        answers = sorted(answer.to_text() for answer in query)

        return {
            **resolver_config,
            "status": "ok" if answers else "fail",
            "answers": answers,
            "error": None if answers else "empty response",
            "provider": resolver_config["country"],
            "nameserver": resolver_config["resolver"],
            "ips": answers,
        }
    except Exception as error:
        return {
            **resolver_config,
            "status": "fail",
            "answers": [],
            "error": _format_error(error),
            "provider": resolver_config["country"],
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
