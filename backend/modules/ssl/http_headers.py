import requests
from fastapi import HTTPException

from backend.network import DEFAULT_HTTP_TIMEOUT, safe_requests_get


def get_http_headers(domain):
    security_headers = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy"
    ]

    try:
        url = f"https://{domain}"
        response = safe_requests_get(url, timeout=DEFAULT_HTTP_TIMEOUT, allow_redirects=False)
        headers_recebidos = response.headers

        found_list = []
        missing_list = []

        for h in security_headers:
            if h in headers_recebidos:
                found_list.append(h)
            else:
                missing_list.append(h)

        return {
            "domain": domain,
            "status_code": response.status_code,
            "headers_found": found_list,
            "headers_missing": missing_list,
            "all_headers": dict(headers_recebidos),
            "found": True
        }

    except requests.exceptions.Timeout:
        return {
            "domain": domain,
            "error": "Timeout na requisicao",
            "status": "Failed to retrieve HTTP headers",
            "found": False
        }

    except requests.exceptions.RequestException:
        return {
            "domain": domain,
            "error": "Falha ao consultar os headers HTTP",
            "status": "Failed to retrieve HTTP headers",
            "found": False
        }

    except HTTPException:
        raise

    except Exception:
        return {
            "domain": domain,
            "error": "Falha ao consultar os headers HTTP",
            "status": "Failed to retrieve HTTP headers",
            "found": False
        }
