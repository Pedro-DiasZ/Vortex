import json
import os


DETAIL_HINTS = {
    "Direto e curto": "seja objetivo, sem rodeios e com foco no resultado final",
    "Médio": "inclua contexto suficiente, passos claros e explicacoes breves",
    "Bem detalhado": "explique decisoes, requisitos, restricoes e criterios de validacao",
    "Extremamente detalhado": "trate o pedido com profundidade, cobrindo contexto, riscos, alternativas, validacao e acabamento",
}

DELIVERY_HINTS = {
    "Código": "priorize implementacao funcional, organizada e aderente ao stack informado",
    "Texto profissional": "priorize clareza, tom profissional e estrutura pronta para uso",
    "E-mail/resposta para cliente": "priorize comunicacao objetiva, cordial e adequada para cliente",
    "Ideias criativas": "gere alternativas variadas, aplicaveis e com justificativa curta",
    "Roteiro": "organize em cenas, etapas ou blocos narrativos claros",
    "Análise técnica": "investigue causas, evidencias, impacto, riscos e proximos passos",
    "Plano de ação": "organize em etapas, prioridades, responsaveis e criterios de conclusao",
    "Design/UI": "priorize UX, hierarquia visual, responsividade e consistencia visual",
    "Prompt para imagem": "descreva composicao, estilo, assunto, iluminacao, cores e restricoes visuais",
    "Prompt para vídeo": "descreva cenas, camera, movimento, ritmo, duracao e estilo visual",
    "Automação": "priorize fluxo, entradas, saidas, excecoes e seguranca operacional",
    "Outro": "organize o pedido de forma clara e acionavel",
}


def _clean(value: str, limit: int = 4000) -> str:
    return (value or "").strip()[:limit]


def _bool(value, default=True) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return str(value).strip().lower() in {"sim", "true", "1", "yes", "s"}


def _line(label: str, value: str) -> str:
    value = _clean(value)
    return f"- {label}: {value}" if value else ""


def _persona(data: dict) -> str:
    if not _bool(data.get("include_persona"), True):
        return ""

    tone = _clean(data.get("tone")) or "Profissional"
    output_type = _clean(data.get("output_type")) or "resultado solicitado"
    audience = _clean(data.get("target_audience"))
    model = _clean(data.get("ai_model"))

    model_hint = f" O prompt sera usado em {model}." if model else ""
    audience_hint = f" Considere que o publico-alvo e: {audience}." if audience else ""

    return (
        f"Voce e uma IA com perfil {tone}, especialista em transformar pedidos em entregas de alta qualidade "
        f"para o tipo de resultado: {output_type}.{audience_hint}{model_hint}"
    )


def build_local_prompt(data: dict) -> str:
    objective = _clean(data.get("objective"))
    context = _clean(data.get("context"))
    output_type = _clean(data.get("output_type"))
    detail_level = _clean(data.get("detail_level")) or "Médio"
    tone = _clean(data.get("tone")) or "Profissional"
    output_format = _clean(data.get("output_format")) or "Estrutura com seções"
    avoid = _clean(data.get("avoid"))
    extra_info = _clean(data.get("extra_info"))
    language = _clean(data.get("language")) or "Português"
    expected_size = _clean(data.get("expected_size")) or "Média"
    ask_questions = _clean(data.get("ask_questions")) or "Sim, se faltar informação importante"
    keywords = _clean(data.get("required_keywords"))

    sections = []
    persona = _persona(data)
    if persona:
        sections.append(("Persona da IA", persona))

    sections.append(("Contexto", context))
    sections.append(("Objetivo", objective))
    sections.append((
        "Tarefa principal",
        (
            f"Entregue um resultado do tipo {output_type or 'solicitado'}, "
            f"com nivel de detalhe: {detail_level}. "
            f"{DELIVERY_HINTS.get(output_type, DELIVERY_HINTS['Outro'])}."
        ),
    ))

    requirements = [
        _line("Idioma da resposta", language),
        _line("Tamanho esperado", expected_size),
        _line("Tom/persona de resposta", tone),
        _line("Formato de saida", output_format),
        _line("Nivel de detalhe", DETAIL_HINTS.get(detail_level, detail_level)),
        _line("Palavras-chave obrigatorias", keywords),
        _line("Informacoes adicionais", extra_info),
    ]

    if _bool(data.get("include_technical_context"), True):
        requirements.append("- Preserve e use o contexto tecnico informado. Nao invente tecnologias, restricoes ou fatos ausentes.")
    if _bool(data.get("include_examples"), True):
        requirements.append("- Inclua exemplos quando eles ajudarem a tornar a resposta mais aplicavel.")
    if ask_questions:
        requirements.append(f"- Perguntas antes de responder: {ask_questions}.")

    sections.append(("Requisitos obrigatorios", "\n".join(item for item in requirements if item)))

    if avoid:
        sections.append(("Restricoes e cuidados", avoid))

    sections.append((
        "Estilo e formato da resposta",
        (
            f"Responda em {language}, com tom {tone}. "
            f"Use o formato: {output_format}. "
            "Organize a resposta com hierarquia clara, titulos objetivos e conteudo pronto para uso."
        ),
    ))

    if _bool(data.get("include_quality_criteria"), True):
        sections.append((
            "Criterios de qualidade",
            "\n".join([
                "- A resposta deve ser especifica, util e diretamente aplicavel.",
                "- Evite texto generico, ambiguo ou decorativo.",
                "- Explique premissas importantes quando houver incerteza.",
                "- Respeite as restricoes informadas.",
                "- Entregue um resultado completo o bastante para reduzir retrabalho.",
            ]),
        ))

    sections.append((
        "Instrucoes finais",
        (
            "Antes de responder, revise se o resultado atende ao objetivo, ao contexto, ao formato solicitado "
            "e aos criterios de qualidade. Se faltar uma informacao essencial, siga a regra definida para perguntas."
        ),
    ))

    return "\n\n".join(f"## {title}\n{body}" for title, body in sections if _clean(body))


def _tips(data: dict, provider: str) -> list[str]:
    tips = [
        "Cole este prompt diretamente na IA escolhida.",
        "Se quiser uma resposta mais precisa, adicione exemplos reais, limites e arquivos relevantes.",
    ]
    if provider == "local_template":
        tips.append("Este prompt foi gerado por template local; revise detalhes especificos antes de usar.")
    if _clean(data.get("output_type")) in {"Código", "Automação"}:
        tips.append("Para tarefas de codigo, informe stack, versoes, arquivos envolvidos e comportamento esperado.")
    return tips


def _try_gemini_refine(data: dict, local_prompt: str) -> str | None:
    if not os.environ.get("GEMINI_API_KEY"):
        return None

    system_prompt = (
        "Voce e um especialista em prompt engineering. Refine prompts em Markdown, mantendo clareza, contexto, "
        "restricoes e criterios de qualidade. Responda apenas JSON valido com a chave optimized_prompt."
    )
    user_content = json.dumps(
        {
            "input_fields": data,
            "local_prompt": local_prompt,
            "task": "Refine o prompt final, sem reduzir informacoes importantes.",
        },
        ensure_ascii=False,
    )

    try:
        from backend.ai.service import ask_gemini_json

        result = ask_gemini_json(system_prompt, user_content, max_tokens=4096)
        refined = _clean(result.get("optimized_prompt"), 20000)
        return refined or None
    except Exception:
        return None


def generate_prompt(data: dict) -> dict:
    objective = _clean(data.get("objective"), 2000)
    context = _clean(data.get("context"), 4000)
    output_type = _clean(data.get("output_type"), 120)

    if not objective or not context or not output_type:
        raise ValueError("Informe pelo menos o objetivo, contexto e tipo de entrega esperada.")

    normalized = {
        "objective": objective,
        "context": context,
        "output_type": output_type,
        "detail_level": _clean(data.get("detail_level"), 120) or "Médio",
        "tone": _clean(data.get("tone"), 120) or "Profissional",
        "output_format": _clean(data.get("output_format"), 120) or "Estrutura com seções",
        "avoid": _clean(data.get("avoid"), 4000),
        "extra_info": _clean(data.get("extra_info"), 4000),
        "target_audience": _clean(data.get("target_audience"), 120),
        "ai_model": _clean(data.get("ai_model"), 120),
        "language": _clean(data.get("language"), 80) or "Português",
        "expected_size": _clean(data.get("expected_size"), 120) or "Média",
        "ask_questions": _clean(data.get("ask_questions"), 160) or "Sim, se faltar informação importante",
        "include_examples": _bool(data.get("include_examples"), True),
        "include_quality_criteria": _bool(data.get("include_quality_criteria"), True),
        "include_persona": _bool(data.get("include_persona"), True),
        "include_technical_context": _bool(data.get("include_technical_context"), True),
        "required_keywords": _clean(data.get("required_keywords"), 1000),
    }

    local_prompt = build_local_prompt(normalized)
    refined = _try_gemini_refine(normalized, local_prompt)
    provider = "gemini" if refined else "local_template"
    optimized_prompt = refined or local_prompt

    return {
        "title": "Prompt otimizado",
        "summary": "Prompt criado com foco em clareza, contexto e resultado esperado.",
        "optimized_prompt": optimized_prompt,
        "provider": provider,
        "badges": [normalized["output_type"], normalized["detail_level"], normalized["tone"]],
        "tips": _tips(normalized, provider),
        "variants": {
            "short": build_local_prompt({**normalized, "detail_level": "Direto e curto", "expected_size": "Curta"}),
            "detailed": build_local_prompt({**normalized, "detail_level": "Extremamente detalhado", "expected_size": "Completa/profunda"}),
            "english": build_local_prompt({**normalized, "language": "Inglês"}),
        },
    }

