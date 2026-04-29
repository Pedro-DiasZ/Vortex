import socket

def check_port(host: str, port: int) -> dict:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(5)
            result = sock.connect_ex((host, port))
            is_open = (result == 0)
            
            return {
                "host": host,
                "port": port,
                "open": is_open,
                "socket_result": result,
                "found": True,
                "status": f"Port {port} is {'open' if is_open else 'closed'}"
            }
    except Exception as e:
        return {
            "host": host,
            "port": port,
            "open": False,
            "error": str(e)
        }