import httpx
from urllib.parse import urlparse


def _normalize_host(host: str) -> str:
    host = (host or "").strip()
    if not host:
        return ""
    parsed = urlparse(host if "://" in host else f"//{host}")
    cleaned = parsed.hostname or host
    return cleaned.strip().strip("/")


def run_traceroute(host: str) -> dict:
    normalized_host = _normalize_host(host)

    if not normalized_host:
        return {"host": host, "found": False, "status": "Host vazio ou inválido"}

    try:
        response = httpx.get(
            f"https://api.hackertarget.com/traceroute/?q={normalized_host}",
            timeout=30,
        )

        if response.status_code != 200:
            return {"host": host, "found": False, "status": f"Erro HTTP: {response.status_code}"}

        output = response.text

        if "error" in output.lower():
            return {"host": host, "normalized_host": normalized_host, "found": False, "status": output.strip()}

        hops = _parse_hops(output)

        return {
            "host": host,
            "normalized_host": normalized_host,
            "found": True,
            "status": "OK",
            "hop_count": len(hops),
            "hops": hops,
            "raw": output,
        }

    except httpx.TimeoutException:
        return {"host": host, "normalized_host": normalized_host, "found": False, "status": "Timeout na requisição"}
    except Exception as e:
        return {"host": host, "normalized_host": normalized_host, "found": False, "status": f"Erro: {str(e)}"}


def _parse_hops(output: str) -> list:
    hops = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if not parts or not parts[0].isdigit():
            continue
        hops.append({"hop": int(parts[0]), "info": " ".join(parts[1:])})
    return hops
