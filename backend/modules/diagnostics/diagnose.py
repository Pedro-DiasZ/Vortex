from backend.modules.diagnostics.response_generator import generate_response
from backend.modules.diagnostics.smtp_analyzer import analyze_smtp_error


ISSUE_MAP = {
    "spf": ("Falha na autenticacao SPF", "high", ["Validar registro SPF", "Autorizar o servidor de envio no SPF"], ["suporte", "administrador DNS"]),
    "dkim": ("Falha na autenticacao DKIM", "high", ["Conferir seletor DKIM", "Validar chave publica no DNS"], ["suporte", "administrador DNS"]),
    "dmarc": ("Rejeicao por politica DMARC", "high", ["Validar SPF/DKIM alinhados", "Revisar politica DMARC"], ["suporte", "administrador DNS"]),
    "mailbox_full": ("Caixa postal cheia", "medium", ["Liberar espaco", "Aumentar cota da caixa"], ["destinatario", "cliente"]),
    "authentication": ("Falha de autenticacao", "high", ["Validar usuario e senha", "Conferir porta e criptografia"], ["cliente", "suporte"]),
    "security_policy": ("Bloqueio por politica de seguranca", "high", ["Revisar autenticacao e conteudo", "Validar reputacao do envio"], ["suporte", "provedor externo"]),
    "external_block": ("Bloqueio externo ou blacklist", "critical", ["Checar blacklist", "Solicitar delisting quando aplicavel"], ["suporte", "provedor externo"]),
    "send_limit": ("Limite de envio atingido", "medium", ["Reduzir volume", "Aguardar janela de liberacao"], ["cliente", "suporte"]),
    "dns": ("Falha de DNS", "critical", ["Validar registros DNS", "Conferir MX/NS e propagacao"], ["administrador DNS", "suporte"]),
    "temporary_failure": ("Falha temporaria no servidor", "medium", ["Aguardar nova tentativa", "Monitorar disponibilidade"], ["suporte", "provedor externo"]),
    "permanent_failure": ("Falha permanente no envio", "high", ["Validar endereco e politicas", "Corrigir causa antes de reenviar"], ["remetente", "suporte"]),
}


def diagnose(data: dict) -> dict:
    log = (data.get("smtp_error") or data.get("log") or data.get("content") or "").strip()
    problem_type = (data.get("problem_type") or "Outro").strip()
    domain = (data.get("domain") or "").strip()
    sender = (data.get("sender_email") or "").strip()
    recipient = (data.get("recipient_email") or "").strip()

    if not any([log, domain, sender, recipient]):
        raise ValueError("Informe pelo menos um dominio, e-mail ou log tecnico.")

    smtp = analyze_smtp_error(log) if log else {}
    category = smtp.get("category", "")
    title, severity, steps, actors = ISSUE_MAP.get(category, (
        "Diagnostico inconclusivo",
        "medium",
        ["Coletar erro completo", "Executar checks de DNS, SMTP e reputacao"],
        ["suporte"],
    ))

    lower_log = log.lower()
    if "spf" in lower_log:
        title, severity, steps, actors = ISSUE_MAP["spf"]
    elif "dkim" in lower_log:
        title, severity, steps, actors = ISSUE_MAP["dkim"]
    elif "dmarc" in lower_log:
        title, severity, steps, actors = ISSUE_MAP["dmarc"]
    elif "nxdomain" in lower_log or "no mx" in lower_log:
        title, severity, steps, actors = ISSUE_MAP["dns"]

    causes = list(smtp.get("likely_causes") or [])
    if domain and "DNS" in problem_type.upper():
        causes.append("Registros DNS ausentes, incorretos ou ainda em propagacao.")
    if sender:
        causes.append(f"Configuracao ou autenticacao do remetente {sender} pode precisar de revisao.")
    if recipient:
        causes.append(f"Servidor ou caixa do destinatario {recipient} pode estar recusando a entrega.")

    response = generate_response({
        "problem_type": "DMARC" if "DMARC" in title else "SPF" if "SPF" in title else "DNS" if "DNS" in title else "Outro",
        "tone": "Tecnico",
        "domain": domain,
        "email_account": sender or recipient,
        "error_found": log[:500],
        "next_step": steps[0],
    })["response"]

    return {
        "probable_issue": title,
        "severity": severity,
        "problem_type": problem_type,
        "evidence": smtp.get("evidence") or ([log[:220]] if log else ["Dados informados sem log SMTP detalhado."]),
        "possible_causes": causes or ["Nao ha evidencias suficientes para apontar uma causa unica."],
        "next_steps": steps,
        "responsible_side": actors,
        "client_response": response,
        "smtp_analysis": smtp or None,
    }

