from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware


from backend.modules.email.spf import check_spf
from backend.modules.email.dmarc import check_dmarc
from backend.modules.email.dkim import check_dkim
from backend.modules.email.blks import check_blacklists
from backend.modules.email.smtp_checker import check_smtp
from backend.modules.email.email_header_analyzer import analyze_header

from backend.modules.dns.whois import get_whois_info
from backend.modules.dns.lookup import dns_lookup
from backend.modules.dns.propagation import check_propagation

from backend.modules.infra.geo import geolocate_ip
from backend.modules.infra.ping import ping_host
from backend.modules.infra.ip_info import get_ip_info
from backend.modules.infra.uptime import check_uptime
from backend.modules.infra.port_checker import check_port

from backend.modules.ssl.http_headers import get_http_headers
from backend.modules.ssl.ssl_checker import check_ssl

from backend.modules.utils.base64_tool import base64_decode, base64_encode
from backend.modules.utils.cidr import is_valid_cidr
from backend.modules.utils.password_generator import generate_strong_password
from backend.modules.utils.ttl_converter import ttl_seconds_to_human

app = FastAPI(
    title="VortexAPI",
    openapi_url="/api/openapi.json",
    docs_url="/api/docs"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)

@app.get("/api")
def root():
    return {"message": "API Online - Sistema de Diagnóstico de Infraestrutura"}


@app.get("/api/spf") 
def spf(domain: str):
    return check_spf(domain)

@app.get("/api/dmarc")
def dmarc(domain: str):
    return check_dmarc(domain)

@app.get("/api/dkim")
def dkim(domain: str, selector: str = "default"):
    return check_dkim(domain, selector)

@app.get("/api/blacklists")
def blacklists(domain: str):
    return check_blacklists(domain)

@app.get("/api/smtp")
def smtp(host: str, port: int = 587):
    return check_smtp(host, port)

@app.post("/api/analyze-header")
def header_analyzer(raw_header: dict):
    return analyze_header(raw_header.get("content", ""))


@app.get("/api/whois")
def whois(domain: str):
    return get_whois_info(domain)

@app.get("/api/dns")
def dns(domain: str, record_type: str = "A"):
    return dns_lookup(domain, record_type)

@app.get("/api/dns-propagation")
def dns_propagation(domain: str, record_type: str = "A"):
    return check_propagation(domain, record_type)


@app.get("/api/geo")
def geo(ip: str):
    return geolocate_ip(ip)

@app.get("/api/ping")
def ping(host: str):
    return ping_host(host)

@app.get("/api/ip-info")
def ip_info(ip: str):
    return get_ip_info(ip)

@app.get("/api/uptime")
def uptime(url: str):
    return check_uptime(url)

@app.get("/api/port-checker")
def port_checker(host: str, port: int):
    return check_port(host, port)


@app.get("/api/ssl")
def ssl(domain: str):
    ssl_info = check_ssl(domain)
    headers = get_http_headers(domain)
    return {"ssl_info": ssl_info, "http_headers": headers}

@app.get("/api/utils/cidr")
def cidr(cidr: str):
    return {"is_valid": is_valid_cidr(cidr)}

@app.get("/api/utils/base64/encode")
def b64_encode(text: str):
    return {"encoded": base64_encode(text)}

@app.get("/api/utils/base64/decode")
def b64_decode(text: str):
    return {"decoded": base64_decode(text)}

@app.get("/api/utils/password/strong")
def strong_password(length: int = 16):
    return {"password": generate_strong_password(length)}

@app.get("/api/utils/ttl/humanize")
def ttl_humanize(seconds: int):
    return {"humanized": ttl_seconds_to_human(seconds)}

@app.get("/api/dns_reverse")
def dns_reverse(ip: str):
    from backend.modules.dns.dns_reverse import dns_reverse_resolver
    return dns_reverse_resolver(ip)

@app.get("/email_log_analysis")
def email_log_analysis(raw_log: str):
    from modules.email.log_analyzer import analyze_log
    return analyze_log(raw_log)
