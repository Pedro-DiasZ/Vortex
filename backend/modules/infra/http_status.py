import httpx
from fastapi import HTTPException

from backend.network import DEFAULT_HTTP_TIMEOUT, safe_httpx_get


def _normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return ""
    if "://" not in url:
        url = f"https://{url}"
    return url


def check_http_status(url: str) -> dict:
    normalized_url = _normalize_url(url)

    if not normalized_url:
        return {"url": url, "found": False, "status": "URL vazia ou inválida"}

    try:
        response = safe_httpx_get(
            normalized_url,
            follow_redirects=False,
            timeout=DEFAULT_HTTP_TIMEOUT,
        )

        redirect_chain = [str(r.url) for r in response.history]

        return {
            "url": url,
            "normalized_url": normalized_url,
            "final_url": str(response.url),
            "status_code": response.status_code,
            "status_text": _status_text(response.status_code),
            "response_time_ms": round(response.elapsed.total_seconds() * 1000, 2),
            "redirect_count": len(redirect_chain),
            "redirect_chain": redirect_chain,
            "tls": str(response.url).startswith("https"),
            "found": True,
            "status": "OK",
        }

    except httpx.TimeoutException:
        return {"url": url, "normalized_url": normalized_url, "found": False, "status": "Timeout na requisição"}
    except httpx.SSLError:
        return {"url": url, "normalized_url": normalized_url, "found": False, "status": "Erro SSL na conexao"}
    except httpx.ConnectError:
        return {"url": url, "normalized_url": normalized_url, "found": False, "status": "Falha na conexão com o host"}
    except HTTPException:
        raise
    except Exception:
        return {"url": url, "normalized_url": normalized_url, "found": False, "status": "Erro ao consultar a URL"}


def _status_text(code: int) -> str:
    texts = {
        200: "OK", 201: "Created", 204: "No Content",
        301: "Moved Permanently", 302: "Found", 304: "Not Modified",
        400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
        404: "Not Found", 405: "Method Not Allowed", 429: "Too Many Requests",
        500: "Internal Server Error", 502: "Bad Gateway",
        503: "Service Unavailable", 504: "Gateway Timeout",
    }
    return texts.get(code, "Unknown")
