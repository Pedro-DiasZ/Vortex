from urllib.parse import urlparse

import requests

from backend.security import assert_domain


REQUEST_TIMEOUT = 15
MAX_CERTIFICATES = 50


def _normalize_domain(value: str) -> str:
    value = (value or "").strip()
    parsed = urlparse(value if "://" in value else f"//{value}")
    domain = (parsed.hostname or value).strip().rstrip(".")
    return assert_domain(domain)


def _empty_response(domain: str) -> dict:
    return {
        "domain": domain,
        "found": False,
        "count": 0,
        "certificates": [],
    }


def _response(domain: str, certificates: list[dict]) -> dict:
    return {
        "domain": domain,
        "found": bool(certificates),
        "count": len(certificates),
        "certificates": certificates,
    }


def _parse_crtsh_rows(rows) -> list[dict]:
    if isinstance(rows, dict):
        rows = [rows]

    seen = set()
    certificates = []

    for row in rows if isinstance(rows, list) else []:
        cert = {
            "issuer_name": row.get("issuer_name"),
            "common_name": row.get("common_name"),
            "name_value": row.get("name_value"),
            "not_before": row.get("not_before"),
            "not_after": row.get("not_after"),
            "entry_timestamp": row.get("entry_timestamp"),
        }
        key = (
            cert["name_value"],
            cert["issuer_name"],
            cert["not_before"],
            cert["not_after"],
        )

        if key in seen:
            continue

        seen.add(key)
        certificates.append(cert)

        if len(certificates) >= MAX_CERTIFICATES:
            break

    return certificates


def _parse_certspotter_rows(rows) -> list[dict]:
    seen = set()
    certificates = []

    for row in rows if isinstance(rows, list) else []:
        dns_names = row.get("dns_names") or []
        name_value = "\n".join(dns_names)
        cert = {
            "issuer_name": row.get("issuer", {}).get("name") if isinstance(row.get("issuer"), dict) else None,
            "common_name": dns_names[0] if dns_names else None,
            "name_value": name_value or None,
            "not_before": row.get("not_before"),
            "not_after": row.get("not_after"),
            "entry_timestamp": None,
        }
        key = (
            cert["name_value"],
            cert["issuer_name"],
            cert["not_before"],
            cert["not_after"],
        )

        if key in seen:
            continue

        seen.add(key)
        certificates.append(cert)

        if len(certificates) >= MAX_CERTIFICATES:
            break

    return certificates


def _fetch_crtsh(domain: str) -> list[dict]:
    response = requests.get(
        "https://crt.sh/",
        params={"q": f"%.{domain}", "output": "json"},
        headers={"Accept": "application/json"},
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()

    body = response.text.strip()
    if not body:
        return []

    try:
        rows = response.json()
    except ValueError:
        if "no certificates found" in body.lower():
            return []
        raise

    return _parse_crtsh_rows(rows)


def _fetch_certspotter(domain: str) -> list[dict]:
    response = requests.get(
        "https://api.certspotter.com/v1/issuances",
        params={
            "domain": domain,
            "include_subdomains": "true",
            "expand": "dns_names",
        },
        headers={"Accept": "application/json"},
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()
    return _parse_certspotter_rows(response.json())


def get_ct_logs(domain: str) -> dict:
    normalized_domain = ""
    crtsh_error = None

    try:
        normalized_domain = _normalize_domain(domain)
        try:
            return _response(normalized_domain, _fetch_crtsh(normalized_domain))
        except requests.exceptions.RequestException as e:
            crtsh_error = e
        except ValueError as e:
            crtsh_error = e

        try:
            return _response(normalized_domain, _fetch_certspotter(normalized_domain))
        except requests.exceptions.Timeout:
            return {
                **_empty_response(normalized_domain),
                "error": "Tempo esgotado ao consultar CT logs.",
            }
        except requests.exceptions.RequestException as e:
            error = crtsh_error or e
            return {
                **_empty_response(normalized_domain),
                "error": f"Falha ao consultar CT logs: {str(error)}",
            }
        except ValueError:
            return {
                **_empty_response(normalized_domain),
                "error": "Provedor de CT logs nao retornou um JSON valido.",
            }

    except requests.exceptions.Timeout:
        return {
            **_empty_response(normalized_domain or domain),
            "error": "Tempo esgotado ao consultar crt.sh.",
        }
    except requests.exceptions.RequestException as e:
        return {
            **_empty_response(normalized_domain or domain),
            "error": f"Falha ao consultar crt.sh: {str(e)}",
        }
    except Exception as e:
        return {
            **_empty_response(normalized_domain or domain),
            "error": str(e),
        }
