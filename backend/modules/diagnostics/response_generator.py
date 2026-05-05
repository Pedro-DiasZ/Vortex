PROBLEM_TEMPLATES = {
    "SPF": {
        "issue": "falha na validacao SPF do dominio remetente",
        "explain": "O SPF confirma quais servidores estao autorizados a enviar mensagens em nome do dominio.",
        "action": "validar o registro SPF do dominio e incluir o servico responsavel pelo envio, caso ele ainda nao esteja autorizado",
    },
    "DKIM": {
        "issue": "falha na assinatura DKIM",
        "explain": "O DKIM assina a mensagem para permitir que o provedor destinatario valide sua autenticidade.",
        "action": "conferir o seletor DKIM, a chave publicada no DNS e o servico que realizou o envio",
    },
    "DMARC": {
        "issue": "rejeicao por politica DMARC",
        "explain": "O DMARC aplica regras quando SPF e DKIM nao passam ou nao ficam alinhados ao dominio do remetente.",
        "action": "validar SPF, DKIM e alinhamento DMARC antes de realizar novos envios",
    },
    "Blacklist": {
        "issue": "bloqueio por reputacao ou blacklist",
        "explain": "Provedores podem recusar mensagens quando o IP ou dominio de envio aparece em listas de bloqueio.",
        "action": "verificar a reputacao do IP/dominio e solicitar delisting quando aplicavel",
    },
    "Quarentena": {
        "issue": "mensagem direcionada para quarentena",
        "explain": "Filtros de seguranca podem reter mensagens suspeitas para revisao antes da entrega.",
        "action": "revisar o motivo da quarentena e ajustar conteudo, autenticacao ou regras de seguranca",
    },
    "Outlook": {
        "issue": "falha relacionada ao Outlook ou perfil local",
        "explain": "Problemas locais no perfil, cache ou configuracao podem impedir envio e recebimento.",
        "action": "validar configuracoes da conta, recriar o perfil se necessario e testar via webmail",
    },
    "DNS": {
        "issue": "inconsistencia de DNS",
        "explain": "Registros DNS incorretos podem afetar site, e-mail, autenticacao e roteamento.",
        "action": "conferir registros DNS publicados e aguardar propagacao quando houver alteracoes recentes",
    },
    "SSL": {
        "issue": "problema no certificado SSL",
        "explain": "O certificado SSL protege a conexao e precisa estar valido, correto e dentro da validade.",
        "action": "renovar ou reinstalar o certificado SSL e validar a cadeia de certificacao",
    },
    "Limite de envio": {
        "issue": "limite de envio atingido",
        "explain": "Servicos de e-mail aplicam limites para preservar reputacao e estabilidade.",
        "action": "reduzir o volume, aguardar a janela de liberacao ou revisar o limite contratado",
    },
    "Anexo bloqueado": {
        "issue": "anexo bloqueado por politica de seguranca",
        "explain": "Certos tipos ou tamanhos de anexos podem ser bloqueados por filtros antispam.",
        "action": "remover o anexo, compactar o arquivo ou enviar por link seguro",
    },
    "Lentidao": {
        "issue": "lentidao no servico",
        "explain": "Lentidao pode ocorrer por instabilidade, volume de dados, DNS ou conectividade.",
        "action": "validar conectividade, status do servico e horarios em que a lentidao ocorre",
    },
    "Erro de senha": {
        "issue": "falha de autenticacao por senha",
        "explain": "O servidor recusou as credenciais usadas para acessar ou enviar pela conta.",
        "action": "redefinir a senha e atualizar a configuracao nos dispositivos conectados",
    },
    "Caixa cheia": {
        "issue": "caixa postal cheia",
        "explain": "Quando a cota e atingida, novas mensagens podem ser recusadas.",
        "action": "liberar espaco, excluir mensagens antigas ou aumentar a cota da caixa",
    },
    "Migracao": {
        "issue": "ajuste relacionado a migracao",
        "explain": "Durante migracoes, DNS, senhas, rotas e sincronizacao podem exigir validacoes adicionais.",
        "action": "validar registros DNS, contas migradas e sincronizacao antes de concluir a virada",
    },
    "Outro": {
        "issue": "comportamento tecnico identificado",
        "explain": "A analise indica necessidade de verificacao pontual do ambiente.",
        "action": "validar os logs, reproduzir o cenario e confirmar os dados tecnicos envolvidos",
    },
}


def _sentence(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    return value if value.endswith((".", "!", "?")) else f"{value}."


def generate_response(data: dict) -> dict:
    problem = data.get("problem_type") or data.get("tipo") or "Outro"
    tone = data.get("tone") or "Tecnico"
    template = PROBLEM_TEMPLATES.get(problem, PROBLEM_TEMPLATES["Outro"])
    customer = (data.get("customer_name") or "").strip()
    domain = (data.get("domain") or "").strip()
    account = (data.get("email_account") or "").strip()
    error = (data.get("error_found") or "").strip()
    action_done = (data.get("action_done") or "").strip()
    next_step = (data.get("next_step") or template["action"]).strip()

    greeting = f"Prezado(a) {customer}, boa tarde!" if customer else "Prezado(a), boa tarde!"
    context = []
    if domain:
        context.append(f"Dominio analisado: {domain}.")
    if account:
        context.append(f"Conta envolvida: {account}.")
    if error:
        context.append(f"Erro identificado: {error}.")
    if action_done:
        context.append(f"Acao realizada: {_sentence(action_done)}")

    detail = (
        f"Identificamos {template['issue']}. {template['explain']} "
        f"Nesse caso, recomendamos {next_step}."
    )

    if tone == "Curto":
        body = f"{greeting}\n\nIdentificamos {template['issue']}. Recomendamos {next_step}.\n\nPermanecemos a disposicao."
    elif tone == "Leigo" or tone == "Suporte humanizado":
        body = (
            f"{greeting}\n\n"
            f"Verificamos o caso e encontramos um ponto que pode estar causando o problema: {template['issue']}. "
            "Esse tipo de validacao ajuda os provedores a confirmar se a mensagem ou o servico esta correto e seguro.\n\n"
            f"Para seguir, recomendamos {next_step}.\n\n"
            "Permanecemos a disposicao para auxiliar no que for necessario."
        )
    elif tone == "Assertivo":
        body = (
            f"{greeting}\n\n"
            f"A causa identificada e {template['issue']}. "
            f"O proximo passo recomendado e {next_step}.\n\n"
            "Apos esse ajuste, recomendamos realizar novo teste para confirmar a normalizacao."
        )
    else:
        body = f"{greeting}\n\n{detail}\n\nPermanecemos a disposicao."

    if tone == "Detalhado" and context:
        body = body.replace("\n\nPermanecemos", "\n\n" + "\n".join(context) + "\n\nPermanecemos")

    if tone == "Tecnico" and context:
        body = body.replace("\n\nPermanecemos", "\n\n" + "\n".join(context[:3]) + "\n\nPermanecemos")

    return {
        "problem_type": problem,
        "tone": tone,
        "response": body,
        "variants": {
            "short": f"{greeting}\n\nIdentificamos {template['issue']}. Recomendamos {next_step}.\n\nPermanecemos a disposicao.",
            "technical": f"{greeting}\n\nDiagnostico tecnico: {template['issue']}. {template['explain']} Acao recomendada: {next_step}.\n\nPermanecemos a disposicao.",
            "simple": f"{greeting}\n\nEncontramos um ajuste necessario: {template['issue']}. Para resolver, recomendamos {next_step}.\n\nPermanecemos a disposicao.",
        },
    }

