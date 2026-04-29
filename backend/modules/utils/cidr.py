import ipaddress

def is_valid_cidr(cidr):
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return {
            "cidr": str(network),
            "network_address": str(network.network_address),
            "broadcast_address": str(network.broadcast_address),
            "netmask": str(network.netmask),
            "total_hosts": network.num_addresses - 2 if network.num_addresses > 2 else network.num_addresses,
            "total_addresses": network.num_addresses,
            "num_addresses": network.num_addresses,
            "found": True,
            "status": "CIDR Calculated"
        }
    except ValueError as e:
        return {"error": str(e), "status": "Invalid CIDR format", "found": False}