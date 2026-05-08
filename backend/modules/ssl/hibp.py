import hashlib

import httpx

from backend.network import DEFAULT_HTTP_TIMEOUT, safe_httpx_get


def check_password(password: str) -> dict:
    if not password:
        return {"found": False, "status": "Senha invalida"}

    try:
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]

        response = safe_httpx_get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=DEFAULT_HTTP_TIMEOUT,
        )

        if response.status_code != 200:
            return {"found": False, "status": f"Erro HTTP: {response.status_code}"}

        for line in response.text.splitlines():
            h, count = line.split(":")
            if h == suffix:
                return {
                    "found": True,
                    "times_exposed": int(count),
                    "status": f"Senha encontrada em {count} vazamentos",
                }

        return {
            "found": False,
            "times_exposed": 0,
            "status": "Senha nao encontrada em vazamentos conhecidos",
        }

    except httpx.TimeoutException:
        return {"found": False, "status": "Timeout na consulta"}
    except Exception:
        return {"found": False, "status": "Erro de conexao ao consultar vazamentos"}
