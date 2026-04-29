import re

def analyze_log(raw_log: str) -> dict:
    try:
        # Regex para capturar informações fundamentais
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
        }

    except Exception as e:
        return {
            "found": False, 
            "error": f"Erro ao processar log: {str(e)}",
            "color": "var(--danger)"
        }