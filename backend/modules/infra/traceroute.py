import httpx

def run_traceroute(host: str) -> dict:
    try:
        response = httpx.get(
            f"https://api.hackertarget.com/traceroute/?q={host}",
            timeout=30,
        )
        return {
            "host": host,
            "found": True,
            "status": "OK",
            "raw": response.text,
        }
    except Exception as e:
        return {"host": host, "found": False, "status": str(e)}
