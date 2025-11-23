import re

def validate_subnets(subnets):
    """
    Vérifie si la liste de sous-réseaux est au format CIDR IPv4 valide (ex: 192.168.1.0/24).
    """
    valid_subnets = []
    errors = []
    CIDR_REGEX = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})$")
    
    for subnet in subnets:
        subnet = subnet.strip()
        if not subnet:
            continue
        
        if not CIDR_REGEX.match(subnet):
            errors.append(f"❌ Format CIDR invalide ou caractères non autorisés dans '{subnet}'. Format attendu: X.X.X.X/Y")
            continue
        
        ip_part, mask_part = subnet.split('/')
        
        try:
            mask = int(mask_part)
        except ValueError:
            errors.append(f"❌ Le masque CIDR '{mask_part}' n'est pas un nombre valide dans '{subnet}'.")
            continue
        
        if not (1 <= mask <= 30):
            errors.append(f"❌ Masque CIDR '{mask}' invalide. Doit être entre /1 et /30.")
            continue
        
        ip_octets = ip_part.split('.')
        valid_octet = True
        
        for octet in ip_octets:
            try:
                if not (0 <= int(octet) <= 255):
                    valid_octet = False
                    break
            except ValueError:
                valid_octet = False
                break
        
        if not valid_octet:
            errors.append(f"❌ Adresse IP invalide (octet hors de la plage 0-255) dans '{ip_part}'.")
            continue
        
        valid_subnets.append(subnet)
    
    return valid_subnets, errors
