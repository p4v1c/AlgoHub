import socket

def resolve_hostname_to_ip(hostname):
    """
    Tente de résoudre un nom d'hôte ou un FQDN en adresse IP.
    """
    try:
        ip_address = socket.gethostbyname(hostname)
        print(f" ✅ Résolution DNS: {hostname} -> {ip_address}")
        return ip_address
    except socket.gaierror:
        print(f" ❌ Échec de la résolution DNS pour {hostname}. Vérifiez le nom d'hôte ou la configuration DNS.")
        return None
