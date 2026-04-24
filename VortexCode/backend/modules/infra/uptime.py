import requests

def check_uptime(url):
    if not url.startswith("http"):
        url = f"https://{url}"
    try:
        response = requests.get(url, timeout=10)
        return {
            "url": url,
            "status_code": response.status_code,
            "response_time_ms": round(response.elapsed.total_seconds() * 1000, 2),
            "status": "Up" if response.status_code == 200 else "Down",
            "found": True,
            "online": True
        }
    except requests.exceptions.RequestException as e:
        return {"url": url, "status": "Down", "error": str(e)}
    except Exception as e:
        return {"url": url, "status": "Down", "error": str(e)}