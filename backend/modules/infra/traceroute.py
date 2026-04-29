import subprocess
import sys
import socket
import dns.resolver
from urllib.parse import urlparse


def _normalize_host(host: str) -> str:
    host = (host or "").strip()
    if not host:
        return ""
    parsed = urlparse(host if "://" in host else f"//{host}")
    cleaned = parsed.hostname or host
    return cleaned.strip().strip("/")


def _resolve_mx(domain: str) -> str | None:
    """Retorna o host do MX de maior prioridade."""
    try:
        records = dns.resolver.resolve(domain, "MX")
        sorted_mx = sorted(records, key=lambda r: r.preference)
        return str(sorted_mx[0].exchange).rstrip(".")
    except Exception:
        return None


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


def run_traceroute(host: str, resolve_mx: bool = False) -> dict:
    normalized_host = _normalize_host(host)

    if not normalized_host:
        return {"host": host, "found": False, "status": "Host vazio ou inválido"}

    target = normalized_host
    mx_host = None

    # Se pediu MX, resolve o servidor de e-mail do domínio
    if resolve_mx:
        mx_host = _resolve_mx(normalized_host)
        if not mx_host:
            return {
                "host": host,
                "normalized_host": normalized_host,
                "found": False,
                "status": "Nenhum registro MX encontrado para o domínio",
            }
        target = mx_host

    try:
        resolved_ip = socket.gethostbyname(target)
    except socket.gaierror:
        return {
            "host": host,
            "normalized_host": normalized_host,
            "target": target,
            "found": False,
            "status": "Falha na resolução DNS do destino",
        }

    try:
        if sys.platform == "win32":
            cmd = ["tracert", "-d", "-h", "20", target]
        else:
            cmd = ["traceroute", "-m", "20", "-w", "3", target]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        output = result.stdout or result.stderr
        hops = _parse_hops(output)

        return {
            "host": host,
            "normalized_host": normalized_host,
            "target": target,
            "target_ip": resolved_ip,
            "mx_host": mx_host,
            "mode": "mx" if resolve_mx else "direct",
            "found": True,
            "status": "OK",
            "hop_count": len(hops),
            "hops": hops,
            "raw": output,
        }

    except subprocess.TimeoutExpired:
        return {"host": host, "target": target, "found": False, "status": "Timeout ao executar traceroute"}
    except FileNotFoundError:
        return {"host": host, "target": target, "found": False, "status": "Comando traceroute não encontrado no sistema"}
    except Exception as e:
        return {"host": host, "target": target, "found": False, "status": f"Erro: {str(e)}"}
