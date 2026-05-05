import re


SMTP_CODES = {
    "421": {
        "category": "temporary_failure",
        "severity": "medium",
        "title": "Servico SMTP temporariamente indisponivel",
        "technical": "O servidor retornou 421, normalmente indicando indisponibilidade temporaria ou limite de conexoes.",
        "simple": "O servidor de e-mail estava indisponivel no momento da tentativa.",
        "causes": ["Instabilidade no servidor", "Limite temporario de conexoes", "Manutencao ou greylisting"],
        "actions": ["Tentar reenviar mais tarde", "Verificar disponibilidade do servidor SMTP", "Conferir logs do provedor destinatario"],
        "side": "destinatario",
    },
    "450": {
        "category": "temporary_failure",
        "severity": "medium",
        "title": "Caixa ou recurso temporariamente indisponivel",
        "technical": "O codigo 450 indica falha temporaria para entregar a mensagem.",
        "simple": "A entrega nao foi aceita naquele momento, mas pode funcionar em nova tentativa.",
        "causes": ["Mailbox temporariamente bloqueada", "Greylisting", "Servidor de destino sobrecarregado"],
        "actions": ["Aguardar nova tentativa automatica", "Validar se a conta destinataria existe", "Confirmar politica do servidor destino"],
        "side": "destinatario",
    },
    "451": {
        "category": "temporary_failure",
        "severity": "medium",
        "title": "Erro local temporario",
        "technical": "O codigo 451 aponta falha temporaria no processamento da mensagem.",
        "simple": "O servidor nao conseguiu processar a mensagem naquele momento.",
        "causes": ["Falha temporaria de DNS", "Filtro antispam indisponivel", "Erro interno no servidor destino"],
        "actions": ["Reenviar apos alguns minutos", "Verificar DNS e conectividade", "Acionar o provedor se persistir"],
        "side": "destinatario",
    },
    "452": {
        "category": "mailbox_full",
        "severity": "medium",
        "title": "Armazenamento insuficiente",
        "technical": "O codigo 452 indica falta temporaria de espaco ou recursos para aceitar a mensagem.",
        "simple": "A caixa ou o servidor nao tinha espaco suficiente para receber a mensagem.",
        "causes": ["Caixa cheia", "Cota do servidor excedida", "Fila de e-mail saturada"],
        "actions": ["Liberar espaco na caixa", "Reduzir tamanho da mensagem", "Validar cota do plano"],
        "side": "destinatario",
    },
    "500": {
        "category": "permanent_failure",
        "severity": "medium",
        "title": "Comando SMTP nao reconhecido",
        "technical": "O codigo 500 indica erro de sintaxe ou comando SMTP invalido.",
        "simple": "O servidor nao entendeu o comando enviado pelo cliente de e-mail.",
        "causes": ["Cliente SMTP mal configurado", "Proxy alterando conexao", "Incompatibilidade de comando"],
        "actions": ["Revisar configuracao do cliente", "Testar outro cliente SMTP", "Validar logs de sessao SMTP"],
        "side": "remetente",
    },
    "501": {
        "category": "permanent_failure",
        "severity": "medium",
        "title": "Parametro SMTP invalido",
        "technical": "O codigo 501 indica parametro ou endereco em formato invalido.",
        "simple": "Algum endereco ou parametro enviado esta em formato incorreto.",
        "causes": ["Endereco de e-mail invalido", "Dominio mal formatado", "Parametro SMTP incorreto"],
        "actions": ["Conferir remetente e destinatario", "Remover caracteres especiais indevidos", "Testar envio simples"],
        "side": "remetente",
    },
    "502": {
        "category": "permanent_failure",
        "severity": "low",
        "title": "Comando nao implementado",
        "technical": "O codigo 502 indica que o servidor nao suporta o comando solicitado.",
        "simple": "O servidor de e-mail nao aceita um recurso usado pelo cliente.",
        "causes": ["Comando SMTP nao suportado", "Cliente usando extensao indisponivel"],
        "actions": ["Atualizar ou ajustar cliente SMTP", "Desabilitar extensoes nao suportadas", "Validar capacidades EHLO"],
        "side": "remetente",
    },
    "503": {
        "category": "authentication",
        "severity": "medium",
        "title": "Sequencia SMTP incorreta",
        "technical": "O codigo 503 costuma indicar comandos fora de ordem, inclusive envio sem autenticacao previa.",
        "simple": "O envio foi feito em uma ordem que o servidor nao aceitou.",
        "causes": ["Autenticacao nao iniciada", "TLS exigido antes do login", "Cliente SMTP desatualizado"],
        "actions": ["Ativar autenticacao SMTP", "Usar STARTTLS/SSL correto", "Revisar porta e metodo de seguranca"],
        "side": "remetente",
    },
    "504": {
        "category": "authentication",
        "severity": "medium",
        "title": "Parametro de autenticacao nao suportado",
        "technical": "O codigo 504 indica metodo ou parametro de autenticacao nao suportado pelo servidor.",
        "simple": "O metodo de login usado nao e aceito pelo servidor.",
        "causes": ["Metodo AUTH incorreto", "Cliente sem suporte ao metodo exigido", "Porta SMTP inadequada"],
        "actions": ["Trocar metodo de autenticacao", "Confirmar porta SMTP correta", "Atualizar cliente de e-mail"],
        "side": "remetente",
    },
    "535": {
        "category": "authentication",
        "severity": "high",
        "title": "Falha de autenticacao SMTP",
        "technical": "O codigo 535 indica credenciais rejeitadas pelo servidor SMTP.",
        "simple": "Usuario, senha ou metodo de login nao foram aceitos.",
        "causes": ["Senha incorreta", "Conta bloqueada", "Autenticacao obrigatoria ou 2FA sem senha de app"],
        "actions": ["Redefinir senha", "Validar usuario completo", "Conferir bloqueios e politica de login"],
        "side": "remetente",
    },
    "550": {
        "category": "permanent_failure",
        "severity": "high",
        "title": "Mensagem recusada permanentemente",
        "technical": "O codigo 550 indica rejeicao permanente por endereco, politica, reputacao ou autenticacao.",
        "simple": "O servidor recusou a mensagem e nao deve aceitar nova tentativa igual.",
        "causes": ["Destinatario inexistente", "SPF/DKIM/DMARC falhando", "Remetente bloqueado", "Politica antispam"],
        "actions": ["Validar endereco destinatario", "Conferir SPF, DKIM e DMARC", "Analisar reputacao e conteudo da mensagem"],
        "side": "remetente",
    },
    "551": {
        "category": "permanent_failure",
        "severity": "medium",
        "title": "Destinatario nao local",
        "technical": "O codigo 551 indica que o servidor nao aceita mensagens para esse destinatario.",
        "simple": "O servidor informado nao e responsavel por essa conta.",
        "causes": ["MX incorreto", "Conta migrada", "Endereco destinatario errado"],
        "actions": ["Validar MX do dominio", "Confirmar endereco correto", "Revisar roteamento de e-mail"],
        "side": "destinatario",
    },
    "552": {
        "category": "mailbox_full",
        "severity": "medium",
        "title": "Limite de armazenamento ou tamanho excedido",
        "technical": "O codigo 552 indica cota excedida, caixa cheia ou mensagem grande demais.",
        "simple": "A mensagem nao coube na caixa ou excedeu limite permitido.",
        "causes": ["Caixa cheia", "Anexo grande", "Limite de tamanho do servidor"],
        "actions": ["Liberar espaco", "Reduzir anexos", "Enviar arquivos por link"],
        "side": "destinatario",
    },
    "553": {
        "category": "permanent_failure",
        "severity": "medium",
        "title": "Endereco ou remetente invalido",
        "technical": "O codigo 553 indica endereco de remetente/destinatario invalido ou nao permitido.",
        "simple": "Um endereco usado no envio nao foi aceito pelo servidor.",
        "causes": ["Formato invalido", "Dominio inexistente", "Remetente nao permitido"],
        "actions": ["Conferir enderecos", "Validar dominio do remetente", "Ajustar conta autenticada"],
        "side": "remetente",
    },
    "554": {
        "category": "security_policy",
        "severity": "high",
        "title": "Mensagem rejeitada por politica",
        "technical": "O codigo 554 costuma indicar rejeicao por politica antispam, autenticacao, DMARC ou reputacao.",
        "simple": "O servidor destino bloqueou a mensagem por uma regra de seguranca.",
        "causes": ["DMARC reject", "IP em blacklist", "Conteudo suspeito", "Rate limit ou reputacao baixa"],
        "actions": ["Validar SPF, DKIM e DMARC", "Checar blacklist do IP", "Revisar conteudo e anexos"],
        "side": "remetente",
    },
}


KEYWORD_OVERRIDES = [
    (r"spf.*(fail|failed)|spf check failed", "security_policy", "Falha na autenticacao SPF", "Validar o registro SPF e incluir o servico responsavel pelo envio."),
    (r"dkim.*(fail|failed|invalid)", "security_policy", "Falha na autenticacao DKIM", "Conferir assinatura DKIM e seletor usado pelo servico de envio."),
    (r"dmarc.*(reject|quarantine|policy|fail)", "security_policy", "Mensagem recusada por politica DMARC", "Validar alinhamento SPF/DKIM e politica DMARC do dominio remetente."),
    (r"mailbox full|quota exceeded|over quota|exceeded storage", "mailbox_full", "Caixa postal cheia", "Liberar espaco na caixa destinataria ou aumentar a cota."),
    (r"auth|authentication|535|login failed|invalid credentials", "authentication", "Falha de autenticacao", "Revisar usuario, senha, porta e metodo de seguranca SMTP."),
    (r"relay access denied|unable to relay|relay denied", "security_policy", "Relay nao autorizado", "Autenticar no SMTP correto ou autorizar o remetente para relay."),
    (r"timed out|timeout|connection timed out", "temporary_failure", "Timeout de conexao", "Verificar conectividade, firewall, DNS e disponibilidade do servidor."),
    (r"blacklist|blocked list|blocklist|spamhaus|spamcop", "external_block", "Bloqueio externo ou blacklist", "Checar reputacao do IP/dominio e solicitar delisting quando aplicavel."),
    (r"rate limit|too many messages|throttl", "send_limit", "Limite de envio atingido", "Reduzir volume, aguardar janela de envio ou validar limites do provedor."),
    (r"too many recipients", "send_limit", "Muitos destinatarios", "Dividir o envio em lotes menores e revisar limites por mensagem."),
    (r"message size|size exceeded|too large", "mailbox_full", "Mensagem excede tamanho permitido", "Reduzir anexos ou enviar arquivos por link."),
    (r"attachment.*blocked|blocked attachment|file type", "security_policy", "Anexo bloqueado", "Remover ou compactar o anexo e validar tipos permitidos."),
    (r"nxdomain|domain not found|no such domain", "dns", "Dominio nao encontrado no DNS", "Validar grafia do dominio e registros DNS publicados."),
    (r"no mx|mx.*not found|mail exchanger", "dns", "MX nao encontrado", "Publicar registros MX validos para o dominio."),
]


def _extract_code(text: str) -> str:
    match = re.search(r"\b([245]\d{2})\b", text or "")
    return match.group(1) if match else ""


def _client_response(title: str, action: str) -> str:
    return (
        "Prezado, boa tarde!\n\n"
        f"Identificamos que a falha esta relacionada a: {title.lower()}. "
        f"Como proximo passo, recomendamos {action[0].lower() + action[1:] if action else 'validar os detalhes tecnicos do envio'}.\n\n"
        "Permanecemos a disposicao."
    )


def analyze_smtp_error(raw_error: str) -> dict:
    text = (raw_error or "").strip()[:20000]
    if not text:
        raise ValueError("Informe um erro SMTP para analise.")

    code = _extract_code(text)
    base = SMTP_CODES.get(code, {
        "category": "unknown",
        "severity": "medium",
        "title": "Erro SMTP nao mapeado",
        "technical": "O codigo informado nao esta na base inicial de interpretacao.",
        "simple": "Nao foi possivel identificar automaticamente o significado exato do erro.",
        "causes": ["Resposta SMTP pouco especifica", "Mensagem customizada do provedor"],
        "actions": ["Analisar o texto completo do erro", "Verificar logs no servidor de origem e destino"],
        "side": "indefinido",
    }).copy()

    lower = text.lower()
    badges = {base["category"]}
    evidence = []
    for pattern, category, title, action in KEYWORD_OVERRIDES:
        if re.search(pattern, lower):
            badges.add(category)
            base["category"] = category
            base["title"] = title
            if action not in base["actions"]:
                base["actions"].insert(0, action)
            evidence.append(pattern.split("|")[0].replace(".*", " "))

    if code.startswith("4"):
        badges.add("temporary_failure")
        base["severity"] = "medium"
    elif code.startswith("5"):
        badges.add("permanent_failure")

    return {
        "code": code or "nao_identificado",
        "category": base["category"],
        "badges": sorted(badges),
        "severity": base["severity"],
        "title": base["title"],
        "technical_explanation": base["technical"],
        "simple_explanation": base["simple"],
        "likely_causes": base["causes"],
        "recommended_actions": base["actions"],
        "responsible_side": base["side"],
        "evidence": evidence or [text[:220]],
        "client_response": _client_response(base["title"], base["actions"][0] if base["actions"] else ""),
    }

