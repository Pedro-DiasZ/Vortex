from fastapi import HTTPException

from backend.network import safe_socket_connect

def check_port(host: str, port: int) -> dict:
    sock = None
    try:
        sock = safe_socket_connect(host, port, timeout=3)

        return {
            "host": host,
            "port": port,
            "open": True,
            "socket_result": 0,
            "found": True,
            "status": f"Port {port} is open"
        }
    except TimeoutError:
        return {
            "host": host,
            "port": port,
            "open": False,
            "found": True,
            "status": f"Port {port} is closed"
        }
    except OSError:
        return {
            "host": host,
            "port": port,
            "open": False,
            "found": True,
            "status": f"Port {port} is closed"
        }
    except HTTPException:
        raise
    except Exception:
        return {
            "host": host,
            "port": port,
            "open": False,
            "error": "Falha ao verificar a porta"
        }
    finally:
        if sock:
            sock.close()
