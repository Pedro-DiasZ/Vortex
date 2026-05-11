from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from urllib.parse import urlparse


def limit_text(value: str, max_size: int = 100_000) -> str:
    value = value or ""
    if len(value) > max_size:
        return value[:max_size]
    return value


def normalize_email_health_domain(value: str) -> str:
    value = (value or "").strip()

    if not value:
        return ""

    parsed = urlparse(value if "://" in value else f"//{value}")
    domain = (parsed.hostname or value).strip().rstrip(".")

    if "." not in domain:
        return ""

    try:
        from backend.security import assert_domain

        return assert_domain(domain)
    except Exception:
        return ""

app = FastAPI(
    title="VortexAPI",
    openapi_url="/api/openapi.json",
    docs_url="/api/docs"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"]
)

@app.get("/api")
def root():
    return {"message": "API Online - Sistema de Diagnóstico de Infraestrutura"}


@app.get("/api/spf") 
def spf(domain: str):
    from backend.modules.email.spf import check_spf

    return check_spf(domain)

@app.get("/api/dmarc")
def dmarc(domain: str):
    from backend.modules.email.dmarc import check_dmarc

    return check_dmarc(domain)

@app.get("/api/dkim")
def dkim(domain: str, selector: str = "default"):
    from backend.modules.email.dkim import check_dkim

    return check_dkim(domain, selector)

@app.get("/api/blacklists")
def blacklists(domain: str):
    from backend.modules.email.blks import check_blacklists

    return check_blacklists(domain)

@app.get("/api/smtp")
def smtp(host: str, port: int = 587):
    from backend.modules.email.smtp_checker import check_smtp

    return check_smtp(host, port)

@app.post("/api/analyze-header")
def header_analyzer(raw_header: dict):
    from backend.modules.email.email_header_analyzer import analyze_header

    return analyze_header(limit_text(raw_header.get("content", "")))

@app.post("/api/ai/header")
def ai_header_analyzer(data: dict):
    try:
        from backend.ai.auth import validate_ai_token

        validate_ai_token(data)

        raw_header = data.get("content", "")

        if not raw_header or not raw_header.strip():
            return {
                "error": True,
                "message": "Nenhum header foi enviado para análise."
            }

        raw_header = raw_header[:80000]

        from backend.ai.prompts import AI_HEADER_SYSTEM_PROMPT
        from backend.ai.service import ask_gemini_json

        result = ask_gemini_json(
            system_prompt=AI_HEADER_SYSTEM_PROMPT,
            user_content=f"Analise o seguinte header de e-mail:\n\n{raw_header}",
            max_tokens=4096
        )

        return {
            "error": False,
            "data": result
        }

    except HTTPException as e:
        return {
            "error": True,
            "message": e.detail
        }

    except Exception as e:
        return {
            "error": True,
            "message": f"Erro ao analisar header com IA: {str(e)}"
        }

@app.post("/api/ai/logs")
def ai_logs_analyzer(data: dict):
    try:
        from backend.ai.auth import validate_ai_token

        validate_ai_token(data)

        raw_logs = data.get("content", "")

        if not raw_logs or not raw_logs.strip():
            return {
                "error": True,
                "message": "Nenhum log foi enviado para análise."
            }

        raw_logs = raw_logs[:80000]

        from backend.ai.prompts import AI_LOGS_SYSTEM_PROMPT
        from backend.ai.service import ask_gemini_json

        result = ask_gemini_json(
            system_prompt=AI_LOGS_SYSTEM_PROMPT,
            user_content=f"Analise os seguintes logs técnicos:\n\n{raw_logs}",
            max_tokens=4096
        )

        return {
            "error": False,
            "data": result
        }

    except HTTPException as e:
        return {
            "error": True,
            "message": e.detail
        }

    except Exception as e:
        return {
            "error": True,
            "message": f"Erro ao analisar logs com IA: {str(e)}"
        }

@app.post("/api/ai/email-health")
def ai_email_health_analyzer(data: dict):
    try:
        import json

        from backend.ai.auth import validate_ai_token

        validate_ai_token(data)

        raw_domain = data.get("domain") or data.get("content") or ""

        if not raw_domain or not raw_domain.strip():
            return {
                "error": True,
                "message": "Nenhum domínio foi enviado para análise."
            }

        clean_domain = normalize_email_health_domain(raw_domain)

        if not clean_domain:
            return {
                "error": True,
                "message": "Informe um domínio válido para análise."
            }

        from backend.ai.email_health_collector import collect_email_health_data
        from backend.ai.prompts import AI_EMAIL_HEALTH_SYSTEM_PROMPT
        from backend.ai.service import ask_gemini_json

        collected_data = collect_email_health_data(clean_domain)

        result = ask_gemini_json(
            system_prompt=AI_EMAIL_HEALTH_SYSTEM_PROMPT,
            user_content=(
                "Analise os dados técnicos reais de DNS/e-mail abaixo. "
                "Use apenas esses dados. Não invente registros ausentes. "
                "Se algum check estiver indisponível ou inconclusivo, informe como não validado.\n\n"
                + json.dumps(collected_data, ensure_ascii=False, indent=2)
            ),
            max_tokens=4096
        )

        return {
            "error": False,
            "data": result,
            "raw": collected_data
        }

    except HTTPException as e:
        return {
            "error": True,
            "message": e.detail
        }

    except Exception as e:
        return {
            "error": True,
            "message": f"Erro ao analisar saúde de e-mail com IA: {str(e)}"
        }

@app.post("/api/ai/reputation")
def ai_reputation_analyzer(data: dict):
    try:
        from backend.ai.auth import validate_ai_token

        validate_ai_token(data)

        raw_data = data.get("content", "")

        if not raw_data or not raw_data.strip():
            return {
                "error": True,
                "message": "Nenhum dado de reputação foi enviado para análise."
            }

        raw_data = raw_data[:80000]

        from backend.ai.prompts import AI_REPUTATION_SYSTEM_PROMPT
        from backend.ai.service import ask_gemini_json

        result = ask_gemini_json(
            system_prompt=AI_REPUTATION_SYSTEM_PROMPT,
            user_content=f"Analise os seguintes dados de reputação:\n\n{raw_data}",
            max_tokens=4096
        )

        return {
            "error": False,
            "data": result
        }

    except HTTPException as e:
        return {
            "error": True,
            "message": e.detail
        }

    except Exception as e:
        return {
            "error": True,
            "message": f"Erro ao analisar reputação com IA: {str(e)}"
        }

@app.post("/api/ai/diagram")
def ai_diagram_generator(data: dict):
    try:
        from backend.ai.auth import validate_ai_token
        from backend.security import limit_text

        validate_ai_token(data)

        prompt = limit_text(data.get("prompt", ""), 4000).strip()
        language = (data.get("language") or "mermaid").strip().lower()
        diagram_type = (data.get("diagram_type") or "flowchart").strip().lower()

        if not prompt:
            return {
                "success": False,
                "error": True,
                "message": "Informe um prompt para gerar o diagrama."
            }

        if language not in {"mermaid", "plantuml"}:
            return {
                "success": False,
                "error": True,
                "message": "Linguagem de diagrama invalida."
            }

        allowed_types = {"flowchart", "sequence", "class", "state", "usecase", "component", "er", "mindmap"}
        if diagram_type not in allowed_types:
            return {
                "success": False,
                "error": True,
                "message": "Tipo de diagrama invalido."
            }

        from backend.ai.diagram_service import generate_diagram_code

        code = generate_diagram_code(prompt, language, diagram_type)

        return {
            "success": True,
            "language": language,
            "code": code
        }

    except HTTPException as e:
        return {
            "success": False,
            "error": True,
            "message": e.detail
        }

    except Exception as e:
        return {
            "success": False,
            "error": True,
            "message": f"Erro ao gerar diagrama com IA: {str(e)}"
        }


@app.get("/api/whois")
def whois(domain: str):
    from backend.modules.dns.whois import get_whois_info

    return get_whois_info(domain)

@app.get("/api/dns")
def dns(domain: str, record_type: str = "A"):
    from backend.modules.dns.lookup import dns_lookup

    return dns_lookup(domain, record_type)

@app.get("/api/dns-propagation")
def dns_propagation(domain: str, record_type: str = "A"):
    from backend.modules.dns.propagation import check_propagation

    return check_propagation(domain, record_type)


@app.get("/api/geo")
def geo(ip: str):
    from backend.modules.infra.geo import geolocate_ip

    return geolocate_ip(ip)

@app.get("/api/ping")
def ping(host: str):
    from backend.modules.infra.ping import ping_host

    return ping_host(host)

@app.get("/api/ip-info")
def ip_info(ip: str):
    from backend.modules.infra.ip_info import get_ip_info

    return get_ip_info(ip)

@app.get("/api/uptime")
def uptime(url: str):
    from backend.modules.infra.uptime import check_uptime

    return check_uptime(url)

@app.get("/api/port-checker")
def port_checker(host: str, port: int):
    from backend.modules.infra.port_checker import check_port

    return check_port(host, port)


@app.get("/api/ssl")
def ssl(domain: str):
    from backend.modules.ssl.http_headers import get_http_headers
    from backend.modules.ssl.ssl_checker import check_ssl

    ssl_info = check_ssl(domain)
    headers = get_http_headers(domain)
    return {"ssl_info": ssl_info, "http_headers": headers}


@app.get("/api/ct-logs")
def ct_logs(domain: str):
    from backend.modules.ssl.ct_logs import get_ct_logs

    return get_ct_logs(domain)

@app.get("/api/utils/cidr")
def cidr(cidr: str):
    from backend.modules.utils.cidr import is_valid_cidr

    return {"is_valid": is_valid_cidr(cidr)}

@app.get("/api/utils/base64/encode")
def b64_encode(text: str):
    from backend.modules.utils.base64_tool import base64_encode

    text = limit_text(text)
    return {"encoded": base64_encode(text)}

@app.get("/api/utils/base64/decode")
def b64_decode(text: str):
    from backend.modules.utils.base64_tool import base64_decode

    text = limit_text(text)
    return {"decoded": base64_decode(text)}

@app.get("/api/utils/password/strong")
def strong_password(length: int = 16):
    from backend.modules.utils.password_generator import generate_strong_password

    length = max(8, min(length, 128))
    return {"password": generate_strong_password(length)}

@app.get("/api/utils/ttl/humanize")
def ttl_humanize(seconds: int):
    from backend.modules.utils.ttl_converter import ttl_seconds_to_human

    return {"humanized": ttl_seconds_to_human(seconds)}

@app.get("/api/dns_reverse")
def dns_reverse(ip: str):
    from backend.modules.dns.dns_reverse import dns_reverse_resolver
    return dns_reverse_resolver(ip)

@app.post("/api/email_log_analysis") 
def email_log_analysis(data: dict):
    from backend.modules.email.log_analyzer import analyze_log

    return analyze_log(limit_text(data.get("content", "")))

@app.post("/api/security/hibp/password")
def check_hibp_password(data: dict):
    from backend.modules.ssl.hibp import check_password

    return check_password(limit_text(data.get("password", ""), 256))


@app.get("/api/http-status")
def http_status(url: str):
    from backend.modules.infra.http_status import check_http_status

    return check_http_status(url)


@app.post("/api/diagnose")
def vortex_diagnose(data: dict):
    try:
        from backend.modules.diagnostics.diagnose import diagnose

        data["smtp_error"] = limit_text(data.get("smtp_error") or data.get("log") or data.get("content") or "", 20_000)
        return diagnose(data)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/smtp/analyze")
def smtp_error_analyzer(data: dict):
    try:
        from backend.modules.diagnostics.smtp_analyzer import analyze_smtp_error

        return analyze_smtp_error(limit_text(data.get("error") or data.get("content") or "", 20_000))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/response/generate")
def response_generator(data: dict):
    from backend.modules.diagnostics.response_generator import generate_response

    return generate_response({
        "problem_type": limit_text(data.get("problem_type", ""), 80),
        "tone": limit_text(data.get("tone", ""), 80),
        "customer_name": limit_text(data.get("customer_name", ""), 120),
        "domain": limit_text(data.get("domain", ""), 255),
        "email_account": limit_text(data.get("email_account", ""), 255),
        "error_found": limit_text(data.get("error_found", ""), 2000),
        "action_done": limit_text(data.get("action_done", ""), 2000),
        "next_step": limit_text(data.get("next_step", ""), 2000),
    })


@app.post("/api/domain/health")
def domain_health(data: dict):
    try:
        from backend.security import assert_domain
        from backend.modules.diagnostics.domain_health import check_domain_health

        domain = assert_domain(data.get("domain", ""))
        selector = limit_text(data.get("selector", ""), 80).strip()
        return check_domain_health(domain, selector)
    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/markdown/render")
def markdown_render(data: dict):
    from backend.modules.diagnostics.markdown_renderer import render_markdown

    return render_markdown(limit_text(data.get("markdown") or data.get("content") or "", 100_000))


@app.post("/api/prompt/generate")
def prompt_generate(data: dict):
    try:
        from backend.modules.diagnostics.prompt_generator import generate_prompt

        return generate_prompt(data)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/migration/review-summary")
def migration_review_summary(data: dict):
    from backend.modules.diagnostics.migration_review import summarize_migration_review

    return summarize_migration_review(data)
