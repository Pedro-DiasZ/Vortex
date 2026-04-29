import subprocess
import sys
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
        if sys.platform == "win32":
            cmd = ["tracert", "-d", "-h", "20", normalized_host]
        else:
            cmd = ["traceroute", "-m", "20", "-w", "3", normalized_host]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
        )

        output = result.stdout or result.stderr
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

    except subprocess.TimeoutExpired:
        return {"host": host, "normalized_host": normalized_host, "found": False, "status": "Timeout ao executar traceroute"}
    except FileNotFoundError:
        return {"host": host, "normalized_host": normalized_host, "found": False, "status": "Comando traceroute não encontrado no sistema"}
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
        hop_num = int(parts[0])
        rest = " ".join(parts[1:])
        hops.append({"hop": hop_num, "info": rest})
    return hops
