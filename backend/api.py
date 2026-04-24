from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# --- IMPORTAÇÕES DOS MÓDULOS ---
from modules.email.spf import check_spf
from modules.email.dmarc import check_dmarc
from modules.email.dkim import check_dkim
from modules.email.blks import check_blacklists
from modules.email.smtp_checker import check_smtp
from modules.email.email_header_analyzer import analyze_header

from modules.dns.whois import get_whois_info
from modules.dns.lookup import dns_lookup
from modules.dns.propagation import check_propagation

from modules.infra.geo import geolocate_ip
from modules.infra.ping import ping_host
from modules.infra.ip_info import get_ip_info
from modules.infra.uptime import check_uptime
from modules.infra.port_checker import check_port

from modules.ssl.http_headers import get_http_headers
from modules.ssl.ssl_checker import check_ssl

from modules.utils.base64_tool import base64_decode, base64_encode
from modules.utils.cidr import is_valid_cidr
from modules.utils.password_generator import generate_strong_password
from modules.utils.ttl_converter import ttl_seconds_to_human

app = FastAPI(title="Email Health Monitor API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)

@app.get("/")
def root():
    return {"message": "API Online - Sistema de Diagnóstico de Infraestrutura"}

# --- SEÇÃO: EMAIL ---
@app.get("/spf")
def spf(domain: str):
    return check_spf(domain)

@app.get("/dmarc")
def dmarc(domain: str):
    return check_dmarc(domain)

@app.get("/dkim")
def dkim(domain: str, selector: str = "default"):
    return check_dkim(domain, selector)

@app.get("/blacklists")
def blacklists(domain: str):
    return check_blacklists(domain)

@app.get("/smtp")
def smtp(host: str, port: int = 587):
    return check_smtp(host, port)

@app.post("/analyze-header")
def header_analyzer(raw_header: dict):
    # Recebe via POST pois headers podem ser muito longos para URL
    return analyze_header(raw_header.get("content", ""))

# --- SEÇÃO: DNS ---
@app.get("/whois")
def whois(domain: str):
    return get_whois_info(domain)

@app.get("/dns")
def dns(domain: str, record_type: str = "A"):
    return dns_lookup(domain, record_type)

@app.get("/dns-propagation")
def dns_propagation(domain: str, record_type: str = "A"):
    return check_propagation(domain, record_type)

# --- SEÇÃO: INFRA ---
@app.get("/geo")
def geo(ip: str):
    return geolocate_ip(ip)

@app.get("/ping")
def ping(host: str):
    return ping_host(host)

@app.get("/ip-info")
def ip_info(ip: str):
    return get_ip_info(ip)

@app.get("/uptime")
def uptime(url: str):
    return check_uptime(url)

@app.get("/port-checker")
def port_checker(host: str, port: int):
    return check_port(host, port)

# --- SEÇÃO: SSL ---
@app.get("/ssl")
def ssl(domain: str):
    ssl_info = check_ssl(domain)
    headers = get_http_headers(domain)
    return {"ssl_info": ssl_info, "http_headers": headers}

# --- SEÇÃO: UTILS ---
@app.get("/utils/cidr")
def cidr(cidr: str):
    return {"is_valid": is_valid_cidr(cidr)}

@app.get("/utils/base64/encode")
def b64_encode(text: str):
    return {"encoded": base64_encode(text)}

@app.get("/utils/base64/decode")
def b64_decode(text: str):
    return {"decoded": base64_decode(text)}

@app.get("/utils/password/strong")
def strong_password(length: int = 16):
    return {"password": generate_strong_password(length)}

@app.get("/utils/ttl/humanize")
def ttl_humanize(seconds: int):
    return {"humanized": ttl_seconds_to_human(seconds)}


@app.get("/dns_reverse")
def dns_reverse(ip: str):
    from modules.dns.dns_reverse import dns_reverse_resolver
    return dns_reverse_resolver(ip)