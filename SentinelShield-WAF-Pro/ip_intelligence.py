import ipaddress
import socket

def inspect_ip(ip):
    try:
        obj=ipaddress.ip_address(ip)
        if obj.is_loopback:
            kind="Loopback"
        elif obj.is_private:
            kind="Private"
        elif obj.is_link_local:
            kind="Link-local"
        elif obj.is_reserved:
            kind="Reserved"
        else:
            kind="Public"
        try:
            hostname=socket.gethostbyaddr(ip)[0]
        except Exception:
            hostname="Unavailable"
        return {"ip":ip,"type":kind,"hostname":hostname,"country":"Local/Unknown"}
    except ValueError:
        return {"ip":ip,"type":"Invalid","hostname":"Unavailable","country":"Unknown"}
