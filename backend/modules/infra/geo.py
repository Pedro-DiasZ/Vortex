import requests

def geolocate_ip(ip):
    try:
        url = f"http://ip-api.com/json/{ip}" 
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "fail":
                return {"found": False, "status": data.get("message", "IP inválido")}
            return {
                "ip": data.get("query"),
                "city": data.get("city"),
                "region": data.get("regionName"),
                "country": data.get("country"),
                "lat": data.get("lat"),
                "lon": data.get("lon"),
                "isp": data.get("isp"),
                "org": data.get("org"),
                "timezone": data.get("timezone"),
                "status": "Success",
                "found": True
            }
        else:
            return {"found": False, "status": f"Erro HTTP: {response.status_code}"}
            
    except Exception as e:
        return {"found": False, "status": f"Erro de conexão: {str(e)}"}