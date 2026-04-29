import re

<<<<<<< HEAD
def analyze_log(raw_log: str) -> dict:
    try:
        # Regex para capturar informações fundamentais
=======
from backend.ai.gemini import diagnose_email_content


def _is_email_log(raw_log: str) -> bool:
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
        r"SA score=",
        r"postfix/",
        r"exim",
        r"smtp",
    )
    return sum(1 for marker in markers if re.search(marker, raw_log, re.IGNORECASE)) >= 2


def analyze_log(raw_log: str) -> dict:
    try:
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

>>>>>>> d861339 (Aplicando IA)
        patterns = {
            "from": r"from=<([^>]+)>",
            "to": r"to=<([^>]+)>",
            "msg_id": r"message-id=([^ \n\r]+)",
            "sa_score": r"SA score=([\d\.]+)/(\d+)",
            "rule": r"rule: ([^)\n]+)",
            "client_ip": r"connect from [^\[\n]+\[([\d\.]+)\]",
            "relay": r"relay=([^ \[,]+)",
            "dsn": r"dsn=([\d\.]+)",
        }

<<<<<<< HEAD
        extracted = {k: (re.search(v, raw_log).group(1) if re.search(v, raw_log) else None) for k, v in patterns.items()}
        
        score_val = float(extracted["sa_score"]) if extracted["sa_score"] else 0.0
        

        status = "Desconhecido"
        color = "var(--muted)" 
        
        if "reject:" in raw_log:
            status = "Rejeitado"
            color = "var(--danger)"
        elif "to spam quarantine" in raw_log:
            status = "Quarentena"
            color = "var(--warning)"
        elif "status=sent" in raw_log:
=======
        extracted = {
            key: (match.group(1) if (match := re.search(pattern, raw_log, re.IGNORECASE)) else None)
            for key, pattern in patterns.items()
        }

        score_val = float(extracted["sa_score"]) if extracted["sa_score"] else 0.0

        status = "Desconhecido"
        color = "var(--muted)"

        lowered = raw_log.lower()
        if "reject:" in lowered:
            status = "Rejeitado"
            color = "var(--danger)"
        elif "to spam quarantine" in lowered:
            status = "Quarentena"
            color = "var(--warning)"
        elif "status=sent" in lowered:
>>>>>>> d861339 (Aplicando IA)
            if score_val >= 5:
                status = "Aceito (Spam)"
                color = "var(--warning)"
            else:
                status = "Entregue"
                color = "var(--success)"

        return {
            "found": True,
            "summary": {
                "status": status,
                "color": color,
                "score": f"{score_val}/5",
<<<<<<< HEAD
                "rule": extracted["rule"] or "Nenhuma regra específica"
            },
            "details": {
                "sender": extracted["from"] or "Não identificado",
                "recipient": extracted["to"] or "Não identificado",
                "origin_ip": extracted["client_ip"] or "Desconhecido",
                "relay_final": extracted["relay"] or "N/A",
                "message_id": extracted["msg_id"] or "N/A",
                "dsn_code": extracted["dsn"] or "N/A"
            },
            "raw_analysis": "Análise concluída"
=======
                "rule": extracted["rule"] or "Nenhuma regra especifica",
            },
            "details": {
                "sender": extracted["from"] or "Nao identificado",
                "recipient": extracted["to"] or "Nao identificado",
                "origin_ip": extracted["client_ip"] or "Desconhecido",
                "relay_final": extracted["relay"] or "N/A",
                "message_id": extracted["msg_id"] or "N/A",
                "dsn_code": extracted["dsn"] or "N/A",
            },
            "raw_analysis": "Analise concluida",
            "diagnostico": diagnose_email_content("log de e-mail", raw_log),
>>>>>>> d861339 (Aplicando IA)
        }

    except Exception as e:
        return {
<<<<<<< HEAD
            "found": False, 
            "error": f"Erro ao processar log: {str(e)}",
            "color": "var(--danger)"
        }
=======
            "found": False,
            "error": f"Erro ao processar log: {str(e)}",
            "color": "var(--danger)",
        }
>>>>>>> d861339 (Aplicando IA)
