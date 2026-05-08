import requests
from fastapi import HTTPException

from backend.network import DEFAULT_HTTP_TIMEOUT, safe_requests_get


def check_uptime(url):
    if not url.startswith("http"):
        url = f"https://{url}"

    try:
        response = safe_requests_get(url, timeout=DEFAULT_HTTP_TIMEOUT, allow_redirects=False)
        return {
            "url": url,
            "status_code": response.status_code,
            "response_time_ms": round(response.elapsed.total_seconds() * 1000, 2),
            "status": "Up" if response.status_code == 200 else "Down",
            "found": True,
            "online": True
        }
    except requests.exceptions.Timeout:
        return {"url": url, "status": "Down", "error": "Timeout na requisicao"}
    except requests.exceptions.RequestException:
        return {"url": url, "status": "Down", "error": "Falha ao consultar a URL"}
    except HTTPException:
        raise
    except Exception:
        return {"url": url, "status": "Down", "error": "Falha ao consultar a URL"}
