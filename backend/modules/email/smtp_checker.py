import socket
import smtplib

import dns.exception
import dns.resolver

from backend.security import assert_domain, assert_port


SMTP_TIMEOUT = 10


def _decode_smtp_message(message) -> str:
    if isinstance(message, bytes):
        return message.decode("utf-8", errors="ignore").strip()
    return str(message or "").strip()


def _base_result(host: str, port: int) -> dict:
    return {
        "host": host,
        "port": port,
        "online": False,
        "status": "Offline or Connection Error",
        "found": False,
    }


def _resolve_mx(domain: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=SMTP_TIMEOUT)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    except dns.exception.DNSException:
        return []

    records = sorted(
        ((int(answer.preference), str(answer.exchange).rstrip(".")) for answer in answers),
        key=lambda item: item[0],
    )
    return [exchange for _, exchange in records]


def _check_target(display_host: str, target_host: str, target_port: int, mx_records: list[str]) -> dict:
    result = _base_result(display_host, target_port)
    result["resolved_host"] = target_host
    result["mx_records"] = mx_records
    result["starttls"] = False

    server = None
    try:
        server = smtplib.SMTP(timeout=SMTP_TIMEOUT)
        banner_code, banner_message = server.connect(target_host, target_port)
        banner = _decode_smtp_message(banner_message) or f"Response code: {banner_code}"
        if banner_code != 220:
            result.update({
                "banner": banner,
                "status": f"Response code: {banner_code}",
                "error": banner,
            })
            return result

        code, message = server.ehlo()
        starttls_supported = server.has_extn("starttls")

        if code != 250:
            result.update({
                "banner": banner,
                "status": f"Response code: {code}: {_decode_smtp_message(message)}",
                "error": _decode_smtp_message(message),
            })
            return result

        return {
            "host": display_host,
            "port": target_port,
            "online": True,
            "banner": banner,
            "status": "Ready",
            "found": True,
            "resolved_host": target_host,
            "mx_records": mx_records,
            "starttls": starttls_supported,
        }
    except socket.timeout:
        result["error"] = f"Timeout connecting to {target_host}:{target_port}"
        return result
    except ConnectionRefusedError:
        result["error"] = f"Connection refused by {target_host}:{target_port}"
        return result
    except (socket.gaierror, TimeoutError, OSError, smtplib.SMTPException) as e:
        result["error"] = str(e)
        return result
    finally:
        if server is not None:
            try:
                server.quit()
            except (OSError, smtplib.SMTPException):
                server.close()


def check_smtp(host: str, port: int) -> dict:
    try:
        normalized_host = assert_domain(host)
        requested_port = assert_port(int(port or 25))
    except Exception as e:
        return {
            "host": host,
            "port": port,
            "online": False,
            "status": "Invalid SMTP target",
            "error": getattr(e, "detail", str(e)),
            "found": False,
        }

    mx_records = _resolve_mx(normalized_host)
    if mx_records:
        return _check_target(normalized_host, mx_records[0], 25, mx_records)

    result = _check_target(normalized_host, normalized_host, requested_port, [])
    if not result.get("online") and not result.get("error"):
        result["error"] = "No MX records found and direct SMTP connection failed."
    return result
