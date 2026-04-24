import smtplib
import socket

def check_smtp(host: str, port: int) -> dict:
    smtp_class = smtplib.SMTP_SSL if port == 465 else smtplib.SMTP
    try:
        with smtp_class(host, port, timeout=10) as server:
            banner = server.welcome.decode('utf-8', errors='ignore') if server.welcome else "No banner received"
            code, message = server.ehlo()
            return {
                "host": host,
                "port": port,
                "online": True,
                "banner": banner.strip(),
                "status": "Ready" if code == 250 else f"Response code: {code}",
                "found": True
            }
    except (smtplib.SMTPException, socket.error, Exception) as e:
        return {
            "host": host,
            "port": port,
            "online": False,
            "status": "Offline or Connection Error",
            "error": str(e),
            "found": False
        }