from urllib.parse import urlparse

import requests

from backend.security import assert_domain


def _normalize_domain(value: str) -> str:
    value = (value or "").strip()
    parsed = urlparse(value if "://" in value else f"//{value}")
    domain = (parsed.hostname or value).strip().rstrip(".")
    return assert_domain(domain)


def get_ct_logs(domain: str) -> dict:
    normalized_domain = ""

    try:
        normalized_domain = _normalize_domain(domain)
        response = requests.get(
            "https://crt.sh/",
            params={"q": f"%.{normalized_domain}", "output": "json"},
            timeout=15,
        )
        response.raise_for_status()

        try:
            rows = response.json()
        except ValueError:
            return {
                "domain": normalized_domain,
                "found": False,
                "error": "crt.sh não retornou um JSON válido.",
                "count": 0,
                "certificates": [],
            }

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

            if len(certificates) >= 50:
                break

        return {
            "domain": normalized_domain,
            "found": bool(certificates),
            "count": len(certificates),
            "certificates": certificates,
        }

    except requests.exceptions.Timeout:
        return {
            "domain": normalized_domain or domain,
            "found": False,
            "error": "Tempo esgotado ao consultar crt.sh.",
            "count": 0,
            "certificates": [],
        }
    except requests.exceptions.RequestException as e:
        return {
            "domain": normalized_domain or domain,
            "found": False,
            "error": f"Falha ao consultar crt.sh: {str(e)}",
            "count": 0,
            "certificates": [],
        }
    except Exception as e:
        return {
            "domain": normalized_domain or domain,
            "found": False,
            "error": str(e),
            "count": 0,
            "certificates": [],
        }
