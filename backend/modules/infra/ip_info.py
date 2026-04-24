import requests

def get_ip_info(ip: str) -> dict:
    try:
        url = f"https://ipinfo.io/{ip}/json"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            full_org = data.get("org", "")
            asn = full_org.split(' ', 1)[0] if full_org else "N/A"
            org_name = full_org.split(' ', 1)[1] if ' ' in full_org else full_org
            
            return {
                "ip": data.get("ip"),
                "asn": asn,
                "org": org_name,
                "hostname": data.get("hostname"),
                "city": data.get("city"),
                "country": data.get("country"),
                "found": True,
                "status": "Success"
            }
        else:
            return {
                "ip": ip,
                "found": False, 
                "status": f"HTTP Error: {response.status_code}"
            }
            
    except Exception as e:
        return {
            "ip": ip,
            "found": False, 
            "status": f"Connection Error: {str(e)}"
        }