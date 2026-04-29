import re
from email.parser import HeaderParser
from email.utils import parsedate_to_datetime


IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-zA-Z0-9_-]+)", re.IGNORECASE)


def _clean(value):
    return " ".join(str(value or "").replace("\r", " ").replace("\n", " ").split())


def _all_headers(msg, name):
    return [_clean(value) for value in (msg.get_all(name) or [])]


def _first_public_ip(text):
    for ip in IPV4_RE.findall(text or ""):
        parts = [int(part) for part in ip.split(".") if part.isdigit()]
        if len(parts) != 4:
            continue
        if parts[0] in (10, 127) or parts[:2] == [192, 168] or (parts[0] == 172 and 16 <= parts[1] <= 31):
            continue
        return ip
    return None


def _auth_status(auth_results):
    status = {"spf": "Not Found", "dkim": "Not Found", "dmarc": "Not Found"}
    details = []
    for header in auth_results:
        for method, result in AUTH_RE.findall(header):
            method = method.lower()
            normalized = result.lower()
            status[method] = normalized.capitalize()
            details.append({"method": method.upper(), "result": normalized, "raw": header[:240]})
    return status, details


def _risk_and_diagnosis(data, auth_details, received_count):
    signals = []
    recommendations = []
    score = 0

    for method in ("spf", "dkim", "dmarc"):
        value = data.get(method, "Not Found")
        if value == "Pass":
            signals.append(f"{method.upper()} aprovado")
        elif value == "Not Found":
            score += 1
            signals.append(f"{method.upper()} nao encontrado")
            recommendations.append(f"Verificar por que {method.upper()} nao aparece no Authentication-Results.")
        else:
            score += 2
            signals.append(f"{method.upper()} retornou {value}")
            recommendations.append(f"Investigar falha de {method.upper()} no provedor de envio.")

    if received_count == 0:
        score += 1
        signals.append("Sem cadeia Received")
        recommendations.append("Validar se o cabecalho bruto foi colado completo.")

    if not data.get("message_id"):
        score += 1
        signals.append("Message-ID ausente")

    if data.get("origin_ip") == "Unknown":
        recommendations.append("Conferir Received para identificar o IP de origem.")

    if score >= 4:
        risk = "high"
        summary = "Cabecalho com falhas relevantes de autenticacao ou rastreabilidade."
    elif score >= 2:
        risk = "medium"
        summary = "Cabecalho reconhecido, mas com sinais que merecem revisao."
    elif score == 1:
        risk = "low"
        summary = "Cabecalho parece consistente, com pequena pendencia de validacao."
    else:
        risk = "low"
        summary = "Cabecalho consistente e autenticacao de e-mail aprovada."

    return {
        "enabled": True,
        "summary": summary,
        "risk": risk,
        "score": score,
        "signals": signals[:5],
        "recommendations": recommendations[:4],
        "auth_details": auth_details[:6],
        "source": "local",
    }


def _is_email_header(msg, raw_str):
    if not raw_str or len(raw_str.strip()) < 20:
        return False
    names = ("From", "To", "Subject", "Date", "Message-ID", "Received", "Authentication-Results", "Return-Path")
    return sum(1 for name in names if msg.get(name) or msg.get_all(name)) >= 2


def analyze_header(raw_str: str) -> dict:
    try:
        msg = HeaderParser().parsestr(raw_str or "")
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

        received = _all_headers(msg, "Received")
        auth_results = _all_headers(msg, "Authentication-Results")
        auth_status, auth_details = _auth_status(auth_results)
        received_joined = " ".join(received)
        origin_ip = _first_public_ip(received_joined) or "Unknown"

        date_raw = msg.get("Date")
        parsed_date = None
        if date_raw:
            try:
                parsed_date = parsedate_to_datetime(date_raw).isoformat()
            except Exception:
                parsed_date = None

        data = {
            "from": _clean(msg.get("From")),
            "to": _clean(msg.get("To")),
            "reply_to": _clean(msg.get("Reply-To")),
            "return_path": _clean(msg.get("Return-Path")),
            "subject": _clean(msg.get("Subject")),
            "body": msg.get_payload(),
            "date": _clean(date_raw),
            "date_iso": parsed_date,
            "message_id": _clean(msg.get("Message-ID")),
            "spf": auth_status["spf"],
            "dkim": auth_status["dkim"],
            "dmarc": auth_status["dmarc"],
            "origin_ip": origin_ip,
            "received_count": len(received),
            "received_chain": received[:8],
            "authentication_results": auth_results[:4],
            "found": True,
        }
        data["diagnostico"] = _risk_and_diagnosis(data, auth_details, len(received))
        return data
    except Exception as e:
        return {"found": False, "error": str(e)}
