import re


PATTERNS = {
    "queue_id": r"\b([A-F0-9]{5,}|[A-Za-z0-9_-]{6,})\b(?=:)",
    "from": r"from=<([^>]+)>",
    "to": r"to=<([^>]+)>",
    "msg_id": r"(?:message-id|message_id)=<?([^>\s]+)>?",
    "sa_score": r"(?:SA score|score)=(-?[\d.]+)(?:/(\d+))?",
    "rule": r"(?:rule|rules?):\s*([^)\n\r]+)",
    "client_ip": r"(?:connect from|client=)[^\[\n\r]*\[?((?:\d{1,3}\.){3}\d{1,3})\]?",
    "relay": r"relay=([^,\s]+)",
    "relay_ip": r"relay=[^\[]+\[((?:\d{1,3}\.){3}\d{1,3})\]",
    "dsn": r"dsn=([\d.]+)",
    "status": r"status=([a-zA-Z0-9_-]+)",
    "delay": r"delay=([\d.]+)",
    "delays": r"delays=([^,\s]+)",
    "said": r"said:\s*(.+?)(?:\s*\(|$)",
}


def _extract(raw_log):
    extracted = {}
    for key, pattern in PATTERNS.items():
        match = re.search(pattern, raw_log, re.IGNORECASE)
        extracted[key] = match.group(1).strip() if match else None
    return extracted


def _is_email_log(raw_log):
    if not raw_log or len(raw_log.strip()) < 20:
        return False
    markers = (
        r"from=<[^>]+>",
        r"to=<[^>]+>",
        r"message-id=",
        r"status=",
        r"dsn=",
        r"relay=",
        r"reject:",
        r"connect from",
        r"postfix/",
        r"exim",
        r"mail",
        r"smtp",
    )
    return sum(1 for marker in markers if re.search(marker, raw_log, re.IGNORECASE)) >= 2


def _classify(raw_log, extracted, score_val):
    lowered = raw_log.lower()
    status_token = (extracted.get("status") or "").lower()
    dsn = extracted.get("dsn") or ""

    status = "Desconhecido"
    color = "var(--muted)"
    category = "unknown"

    if "reject:" in lowered or status_token in {"bounced", "deferred"} or dsn.startswith("5."):
        status = "Rejeitado"
        color = "var(--danger)"
        category = "failure"
    elif "quarantine" in lowered or "spam" in lowered and score_val >= 5:
        status = "Quarentena"
        color = "var(--warning)"
        category = "spam"
    elif status_token == "sent" or dsn.startswith("2."):
        status = "Entregue"
        color = "var(--success)"
        category = "success"
    elif dsn.startswith("4.") or "timeout" in lowered or "temporar" in lowered:
        status = "Temporario"
        color = "var(--warning)"
        category = "temporary"
    elif score_val >= 5:
        status = "Aceito (Spam)"
        color = "var(--warning)"
        category = "spam"

    return status, color, category


def _likely_cause(raw_log, extracted, category):
    lowered = raw_log.lower()
    if extracted.get("said"):
        return extracted["said"][:220]
    if "user unknown" in lowered or "recipient address rejected" in lowered:
        return "Destinatario inexistente ou recusado pelo servidor remoto."
    if "blocked" in lowered or "blacklist" in lowered or "dnsbl" in lowered:
        return "Envio possivelmente bloqueado por reputacao ou blacklist."
    if "spf" in lowered and "fail" in lowered:
        return "Falha de SPF detectada no log."
    if "dkim" in lowered and "fail" in lowered:
        return "Falha de DKIM detectada no log."
    if "dmarc" in lowered and "fail" in lowered:
        return "Falha de DMARC detectada no log."
    if "timeout" in lowered or category == "temporary":
        return "Falha temporaria de conexao ou timeout com o servidor remoto."
    if category == "success":
        return "Entrega aceita pelo servidor remoto."
    return "Nao foi possivel determinar uma causa especifica pelo log."


def _diagnosis(status, category, score_val, extracted, cause):
    signals = []
    recommendations = []
    if extracted.get("dsn"):
        signals.append(f"DSN {extracted['dsn']}")
    if extracted.get("relay"):
        signals.append(f"Relay {extracted['relay']}")
    if extracted.get("rule"):
        signals.append(f"Regra {extracted['rule']}")
    if score_val:
        signals.append(f"Score antispam {score_val}/5")

    if category == "success":
        risk = "low"
        summary = "Mensagem entregue com sucesso pelo servidor remoto."
    elif category == "temporary":
        risk = "medium"
        summary = "Entrega sofreu falha temporaria; pode haver retry automatico."
        recommendations.append("Verificar conectividade, DNS e resposta do relay remoto.")
    elif category == "spam":
        risk = "medium"
        summary = "Mensagem associada a spam/quarentena."
        recommendations.append("Revisar conteudo, reputacao do IP e autenticacao SPF/DKIM/DMARC.")
    elif category == "failure":
        risk = "high"
        summary = "Mensagem rejeitada ou devolvida pelo fluxo de e-mail."
        recommendations.append("Conferir causa do bounce e validacao do destinatario.")
    else:
        risk = "unknown"
        summary = "Log reconhecido, mas sem status final claro."
        recommendations.append("Cole mais linhas ao redor do mesmo queue id para contexto.")

    return {
        "enabled": True,
        "summary": summary,
        "risk": risk,
        "signals": signals[:5],
        "likely_cause": cause,
        "recommendations": recommendations[:4],
        "source": "local",
    }


def analyze_log(raw_log: str) -> dict:
    try:
        raw_log = raw_log or ""
        if not _is_email_log(raw_log):
            return {
                "found": False,
                "diagnostico": {
                    "enabled": False,
                    "summary": "",
                    "risk": "unknown",
                    "signals": [],
                    "reason": "Conteudo nao parece ser um log de e-mail.",
                },
            }

        extracted = _extract(raw_log)
        score_val = float(extracted["sa_score"]) if extracted.get("sa_score") else 0.0
        status, color, category = _classify(raw_log, extracted, score_val)
        cause = _likely_cause(raw_log, extracted, category)

        return {
            "found": True,
            "summary": {
                "status": status,
                "category": category,
                "color": color,
                "score": f"{score_val}/5",
                "rule": extracted.get("rule") or "Nenhuma regra especifica",
            },
            "details": {
                "queue_id": extracted.get("queue_id") or "N/A",
                "sender": extracted.get("from") or "Nao identificado",
                "recipient": extracted.get("to") or "Nao identificado",
                "origin_ip": extracted.get("client_ip") or "Desconhecido",
                "relay_ip": extracted.get("relay_ip") or "N/A",
                "relay_final": extracted.get("relay") or "N/A",
                "message_id": extracted.get("msg_id") or "N/A",
                "dsn_code": extracted.get("dsn") or "N/A",
                "delay": extracted.get("delay") or "N/A",
                "delays": extracted.get("delays") or "N/A",
            },
            "raw_analysis": "Analise concluida",
            "diagnostico": _diagnosis(status, category, score_val, extracted, cause),
        }

    except Exception as e:
        return {
            "found": False,
            "error": f"Erro ao processar log: {str(e)}",
            "color": "var(--danger)",
        }
