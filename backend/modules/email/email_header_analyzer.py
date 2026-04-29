import email
from email.parser import HeaderParser


def _local_header_diagnosis(data: dict) -> dict:
    signals = []
    if data.get("spf") == "Pass":
        signals.append("SPF passou")
    if data.get("dkim") == "Pass":
        signals.append("DKIM passou")
    if data.get("dmarc") == "Pass":
        signals.append("DMARC passou")

    missing_auth = [name for name in ("spf", "dkim", "dmarc") if data.get(name) == "Not Found"]
    if missing_auth:
        signals.append("Autenticacao nao encontrada: " + ", ".join(missing_auth).upper())

    risk = "low" if len(signals) >= 3 and not missing_auth else "unknown"
    summary = (
        "Cabecalho reconhecido, mas nao ha autenticacao SPF/DKIM/DMARC visivel."
        if missing_auth
        else "Cabecalho reconhecido com autenticacao de e-mail aprovada."
    )
    return {
        "enabled": True,
        "summary": summary,
        "risk": risk,
        "signals": signals[:3],
        "source": "local",
    }


def _merge_diagnosis(ai_diag: dict, fallback: dict) -> dict:
    if not ai_diag or not ai_diag.get("enabled"):
        return fallback

    generic = "Conteudo reconhecido, mas sem sinais suficientes"
    if not ai_diag.get("summary") or ai_diag.get("summary", "").startswith(generic):
        fallback["model"] = ai_diag.get("model")
        fallback["source"] = "local_fallback"
        return fallback

    return ai_diag


def _is_email_header(msg, raw_str: str) -> bool:
    if not raw_str or len(raw_str.strip()) < 20:
        return False

    header_hits = sum(
        1
        for name in (
            "From",
            "To",
            "Subject",
            "Date",
            "Message-ID",
            "Received",
            "Authentication-Results",
            "Return-Path",
        )
        if msg.get(name) or msg.get_all(name)
    )
    return header_hits >= 2

def analyze_header(raw_str: str) -> dict:
    try:
        parser = HeaderParser()
        msg = parser.parsestr(raw_str)
        if not _is_email_header(msg, raw_str):
            return {
                "found": False,
                "diagnostico": {
                    "enabled": False,
                    "summary": "",
                    "risk": "unknown",
                    "signals": [],
                    "reason": "Conteudo nao parece ser um cabecalho de e-mail.",
                },
            }

        data = {
            "from": msg.get("From"),
            "to": msg.get("To"),
            "subject": msg.get("Subject"),
            "body": msg.get_payload(),
            "date": msg.get("Date"),
            "message_id": msg.get("Message-ID"),
            "spf": "Not Found",
            "dkim": "Not Found",
            "dmarc": "Not Found",
            "origin_ip": "Unknown",
            "found": True
        }
        auth_results = msg.get("Authentication-Results", "")
        if auth_results:
            if "spf=pass" in auth_results.lower(): data["spf"] = "Pass"
            if "dkim=pass" in auth_results.lower(): data["dkim"] = "Pass"
            if "dmarc=pass" in auth_results.lower(): data["dmarc"] = "Pass"
        received = msg.get_all("Received")
        if received:
            pass
        from backend.ai.gemini import diagnose_email_content

        data["diagnostico"] = _merge_diagnosis(
            diagnose_email_content("cabecalho de e-mail", raw_str),
            _local_header_diagnosis(data),
        )
        return data
    except Exception as e:
        return {"found": False, "error": str(e)}
