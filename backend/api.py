from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse


from backend.security import (
    RateLimitMiddleware,
    SecurityHeadersMiddleware,
    assert_domain,
    assert_port,
    assert_public_host,
    assert_public_ip,
    assert_public_url,
    limit_text,
)
from backend.modules.email.spf import check_spf
from backend.modules.email.dmarc import check_dmarc
from backend.modules.email.dkim import check_dkim
from backend.modules.email.blks import check_blacklists
from backend.modules.email.smtp_checker import check_smtp
from backend.modules.email.email_header_analyzer import analyze_header
from backend.modules.email.log_analyzer import analyze_log

from backend.modules.dns.whois import get_whois_info
from backend.modules.dns.lookup import dns_lookup
from backend.modules.dns.propagation import check_propagation

from backend.modules.infra.geo import geolocate_ip
from backend.modules.infra.ping import ping_host
from backend.modules.infra.ip_info import get_ip_info
from backend.modules.infra.uptime import check_uptime
from backend.modules.infra.port_checker import check_port
from backend.modules.infra.http_status import check_http_status

from backend.modules.ssl.http_headers import get_http_headers
from backend.modules.ssl.ssl_checker import check_ssl
from backend.modules.ssl.hibp import check_password

from backend.modules.utils.base64_tool import base64_decode, base64_encode
from backend.modules.utils.cidr import is_valid_cidr
from backend.modules.utils.password_generator import generate_strong_password
from backend.modules.utils.ttl_converter import ttl_seconds_to_human

app = FastAPI(
    title="VortexAPI",
    openapi_url=None,
    docs_url=None,
    redoc_url=None
)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    if isinstance(exc, HTTPException):
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
    return JSONResponse(
        status_code=500,
        content={
            "found": False,
            "status": "Erro interno ao processar a requisicao",
            "error": str(exc),
        },
    )


app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[],
    allow_methods=["GET", "POST"],
    allow_headers=["content-type"]
)

@app.get("/api")
def root():
    return {"message": "API Online - Sistema de Diagnóstico de Infraestrutura"}


@app.get("/api/spf") 
def spf(domain: str):
    domain = assert_domain(domain)
    return check_spf(domain)

@app.get("/api/dmarc")
def dmarc(domain: str):
    domain = assert_domain(domain)
    return check_dmarc(domain)

@app.get("/api/dkim")
def dkim(domain: str, selector: str = "default"):
    domain = assert_domain(domain)
    selector = assert_domain(selector)
    return check_dkim(domain, selector)

@app.get("/api/blacklists")
def blacklists(domain: str):
    domain = assert_domain(domain)
    return check_blacklists(domain)

@app.get("/api/smtp")
def smtp(host: str, port: int = 587):
    host = assert_public_host(host)
    port = assert_port(port)
    return check_smtp(host, port)

@app.post("/api/analyze-header")
def header_analyzer(raw_header: dict):
    return analyze_header(limit_text(raw_header.get("content", "")))


@app.get("/api/whois")
def whois(domain: str):
    domain = assert_domain(domain)
    return get_whois_info(domain)

@app.get("/api/dns")
def dns(domain: str, record_type: str = "A"):
    domain = assert_domain(domain)
    return dns_lookup(domain, record_type)

@app.get("/api/dns-propagation")
def dns_propagation(domain: str, record_type: str = "A"):
    domain = assert_domain(domain)
    return check_propagation(domain, record_type)


@app.get("/api/geo")
def geo(ip: str):
    ip = assert_public_ip(ip)
    return geolocate_ip(ip)

@app.get("/api/ping")
def ping(host: str):
    host = assert_public_host(host)
    return ping_host(host)

@app.get("/api/ip-info")
def ip_info(ip: str):
    ip = assert_public_ip(ip)
    return get_ip_info(ip)

@app.get("/api/uptime")
def uptime(url: str):
    url = assert_public_url(url)
    return check_uptime(url)

@app.get("/api/port-checker")
def port_checker(host: str, port: int):
    host = assert_public_host(host)
    port = assert_port(port)
    return check_port(host, port)


@app.get("/api/ssl")
def ssl(domain: str):
    domain = assert_public_host(domain)
    ssl_info = check_ssl(domain)
    headers = get_http_headers(domain)
    return {"ssl_info": ssl_info, "http_headers": headers}

@app.get("/api/utils/cidr")
def cidr(cidr: str):
    return {"is_valid": is_valid_cidr(cidr)}

@app.get("/api/utils/base64/encode")
def b64_encode(text: str):
    text = limit_text(text)
    return {"encoded": base64_encode(text)}

@app.get("/api/utils/base64/decode")
def b64_decode(text: str):
    text = limit_text(text)
    return {"decoded": base64_decode(text)}

@app.get("/api/utils/password/strong")
def strong_password(length: int = 16):
    length = max(8, min(length, 128))
    return {"password": generate_strong_password(length)}

@app.get("/api/utils/ttl/humanize")
def ttl_humanize(seconds: int):
    return {"humanized": ttl_seconds_to_human(seconds)}

@app.get("/api/dns_reverse")
def dns_reverse(ip: str):
    ip = assert_public_ip(ip)
    from backend.modules.dns.dns_reverse import dns_reverse_resolver
    return dns_reverse_resolver(ip)

@app.post("/api/email_log_analysis") 
def email_log_analysis(data: dict):
    return analyze_log(limit_text(data.get("content", "")))

@app.post("/api/security/hibp/password")
def check_hibp_password(data: dict):
    return check_password(limit_text(data.get("password", ""), max_size=256))


@app.get("/api/http-status")
def http_status(url: str):
    url = assert_public_url(url)
    return check_http_status(url)
