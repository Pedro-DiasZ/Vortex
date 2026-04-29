import requests 

def get_http_headers(domain):
    security_headers = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy"
    ]

    try:
        url = f"https://{domain}"
        response = requests.get(url, timeout=10, allow_redirects=False)
        headers_recebidos = response.headers

        found_list= []
        missing_list = []

        for h in security_headers:
            if h in headers_recebidos:
                found_list.append(h)
            else:
                missing_list.append(h)

        return {
            "domain": domain,
            "status_code": response.status_code,
            "headers_found": found_list, 
            "headers_missing": missing_list,
            "all_headers": dict(headers_recebidos),
            "found": True
        }
    except requests.exceptions.RequestException as e:
        return {"error": str(e), "status": "Failed to retrieve HTTP headers", "found": False}
    except Exception as e:
        return {"error": str(e), "status": "Failed to retrieve HTTP headers", "found": False}
