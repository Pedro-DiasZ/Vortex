import socket
from datetime import datetime

import dns.resolver


def _resolve(domain: str, record_type: str):
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 4
    return resolver.resolve(domain, record_type)


def _check(name, status, evidence, recommendation, weight=10):
    return {
        "name": name,
        "status": status,
        "evidence": evidence,
        "recommendation": recommendation,
        "weight": weight,
    }


def _status_from_score(score: int) -> str:
    if score < 45:
        return "critical"
    if score < 70:
        return "attention"
    if score < 90:
        return "good"
    return "excellent"


def _txt_values(records):
    values = []
    for record in records:
        values.append("".join(part.decode("utf-8", "ignore") for part in record.strings))
    return values


def check_domain_health(domain: str, selector: str = "") -> dict:
    domain = (domain or "").strip().rstrip(".").lower()
    if not domain or "." not in domain:
        raise ValueError("Informe um dominio valido.")

    checks = []

    resolved_ips = []
    try:
        addresses = socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
        ips = sorted({item[4][0] for item in addresses})
        resolved_ips = [ip for ip in ips if "." in ip]
        checks.append(_check("DNS resolve", "ok", f"{len(ips)} endereco(s) encontrado(s): {', '.join(ips[:4])}", "Nenhuma acao necessaria.", 12))
    except Exception:
        checks.append(_check("DNS resolve", "critical", "Dominio nao resolveu para A/AAAA.", "Validar zona DNS e registros A/AAAA.", 12))

    for record_type, label, weight in [("NS", "NS", 8), ("MX", "MX", 14)]:
        try:
            records = list(_resolve(domain, record_type))
            checks.append(_check(label, "ok", f"{len(records)} registro(s) {label} encontrado(s).", "Nenhuma acao necessaria.", weight))
        except dns.resolver.NXDOMAIN:
            checks.append(_check(label, "critical", "Dominio inexistente no DNS.", "Corrigir dominio ou zona autoritativa.", weight))
        except Exception:
            checks.append(_check(label, "critical" if label == "MX" else "warning", f"Nenhum registro {label} encontrado.", f"Publicar registros {label} validos.", weight))

    try:
        txts = _txt_values(_resolve(domain, "TXT"))
        spf_records = [txt for txt in txts if txt.lower().startswith("v=spf1")]
        if spf_records:
            spf = spf_records[0]
            status = "warning" if "+all" in spf else "ok"
            rec = "Trocar +all por politica mais restritiva." if "+all" in spf else "Nenhuma acao necessaria."
            checks.append(_check("SPF", status, spf, rec, 12))
        else:
            checks.append(_check("SPF", "warning", "Registro SPF nao encontrado.", "Publicar SPF autorizando os servicos de envio.", 12))
    except Exception:
        checks.append(_check("SPF", "warning", "Nao foi possivel consultar TXT/SPF.", "Validar DNS TXT do dominio.", 12))

    try:
        dmarc = _txt_values(_resolve(f"_dmarc.{domain}", "TXT"))
        record = next((txt for txt in dmarc if txt.lower().startswith("v=dmarc1")), "")
        if record:
            status = "warning" if "p=none" in record.lower() else "ok"
            rec = "Avaliar evolucao para quarantine/reject apos validar alinhamento." if status == "warning" else "Nenhuma acao necessaria."
            checks.append(_check("DMARC", status, record, rec, 12))
        else:
            checks.append(_check("DMARC", "warning", "Registro DMARC nao encontrado.", "Publicar politica DMARC inicial.", 12))
    except Exception:
        checks.append(_check("DMARC", "warning", "Registro DMARC nao encontrado.", "Publicar _dmarc com politica adequada.", 12))

    if selector:
        try:
            dkim = _txt_values(_resolve(f"{selector}._domainkey.{domain}", "TXT"))
            record = next((txt for txt in dkim if txt.lower().startswith("v=dkim1")), "")
            checks.append(_check("DKIM", "ok" if record else "warning", record or "Selector sem chave DKIM.", "Conferir selector DKIM usado pelo servico de envio.", 8))
        except Exception:
            checks.append(_check("DKIM", "warning", f"Selector {selector} nao encontrado.", "Validar selector informado e publicar chave DKIM.", 8))

    try:
        from backend.modules.ssl.ssl_checker import check_ssl

        ssl_info = check_ssl(domain)
        if ssl_info.get("valid"):
            days = int(ssl_info.get("days_remaining", 0))
            status = "warning" if days <= 30 else "ok"
            checks.append(_check("SSL", status, f"Certificado valido, expira em {days} dia(s).", "Renovar certificado em breve." if status == "warning" else "Nenhuma acao necessaria.", 12))
        else:
            checks.append(_check("SSL", "critical", ssl_info.get("error") or "Certificado SSL invalido.", "Renovar ou reinstalar certificado SSL.", 12))
    except Exception as exc:
        checks.append(_check("SSL", "warning", f"Nao foi possivel validar SSL: {exc}", "Verificar porta 443 e certificado.", 12))

    try:
        from backend.modules.infra.http_status import check_http_status

        http = check_http_status(f"https://{domain}")
        if http.get("found") and int(http.get("status_code", 0)) < 500:
            checks.append(_check("HTTP/HTTPS", "ok", f"Site respondeu HTTP {http.get('status_code')} em {http.get('response_time_ms')} ms.", "Nenhuma acao necessaria.", 8))
        else:
            checks.append(_check("HTTP/HTTPS", "warning", http.get("status") or "Site nao respondeu corretamente.", "Validar hospedagem, DNS e aplicacao web.", 8))
    except Exception as exc:
        checks.append(_check("HTTP/HTTPS", "warning", f"Falha ao consultar site: {exc}", "Validar disponibilidade do site.", 8))

    try:
        answers = _resolve(domain, "A")
        ttl = getattr(answers.rrset, "ttl", 0)
        status = "warning" if ttl >= 86400 else "ok"
        checks.append(_check("TTL", status, f"TTL observado: {ttl} segundos.", "Reduzir TTL antes de migracoes." if status == "warning" else "TTL adequado para operacao normal.", 6))
    except Exception:
        checks.append(_check("TTL", "warning", "Nao foi possivel medir TTL de A.", "Validar registros A/CNAME principais.", 6))

    if resolved_ips:
        try:
            from backend.modules.email.blks import check_blacklists

            reputation = check_blacklists(resolved_ips[0])
            listed = reputation.get("listed_on") or []
            status = "critical" if listed else "ok"
            evidence = f"IP {resolved_ips[0]} listado em: {', '.join(listed[:4])}" if listed else f"IP {resolved_ips[0]} nao listado nas principais DNSBLs consultadas."
            recommendation = "Investigar reputacao e solicitar delisting." if listed else "Nenhuma acao necessaria."
            checks.append(_check("Blacklist", status, evidence, recommendation, 10))
        except Exception as exc:
            checks.append(_check("Blacklist", "warning", f"Nao foi possivel validar blacklist: {exc}", "Executar checagem de reputacao manualmente.", 10))
    else:
        checks.append(_check("Blacklist", "warning", "Nenhum IPv4 A disponivel para consulta.", "Validar reputacao quando houver IP publico associado.", 10))

    max_score = sum(item["weight"] for item in checks)
    earned = 0
    for item in checks:
        if item["status"] == "ok":
            earned += item["weight"]
        elif item["status"] == "warning":
            earned += item["weight"] * 0.45
    score = round((earned / max_score) * 100) if max_score else 0

    for item in checks:
        item.pop("weight", None)

    return {
        "domain": domain,
        "score": score,
        "status": _status_from_score(score),
        "checked_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "checks": checks,
    }
