import hashlib
import httpx


def check_password(password: str) -> dict:
    if not password:
        return {"found": False, "status": "Senha inválida"}

    try:
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]

        response = httpx.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"user-agent": "VortexTools"},
            timeout=10,
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
            "status": "Senha não encontrada em vazamentos conhecidos",
        }

    except Exception as e:
        return {"found": False, "status": f"Erro de conexão: {str(e)}"}
