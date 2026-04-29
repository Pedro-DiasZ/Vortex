import email
from email.parser import HeaderParser

<<<<<<< HEAD
=======
from backend.ai.gemini import diagnose_email_content


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

>>>>>>> d861339 (Aplicando IA)
def analyze_header(raw_str: str) -> dict:
    try:
        parser = HeaderParser()
        msg = parser.parsestr(raw_str)
<<<<<<< HEAD
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
=======
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
>>>>>>> d861339 (Aplicando IA)
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
<<<<<<< HEAD
        return data
    except Exception as e:
        return {"found": False, "error": str(e)}
=======
        data["diagnostico"] = diagnose_email_content("cabecalho de e-mail", raw_str)
        return data
    except Exception as e:
        return {"found": False, "error": str(e)}
>>>>>>> d861339 (Aplicando IA)
