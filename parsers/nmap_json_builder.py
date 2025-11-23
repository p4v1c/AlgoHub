import json
from libnmap.parser import NmapParser


class NmapJsonBuilder:
    """Construit un JSON structuré à partir d'un fichier XML Nmap."""
    
    @staticmethod
    def build_json(xml_file, json_file):
        """
        Parse le fichier XML Nmap et génère un fichier JSON structuré,
        en ne gardant que les ports en état 'open'.
        """
        try:
            nmap_report = NmapParser.parse_fromfile(xml_file)
        except FileNotFoundError:
            print(f" ⚠️ Fichier XML {xml_file} non trouvé.")
            return
        except Exception as e:
            print(f" ⚠️ Erreur lors du parsing de {xml_file}: {e}")
            return
        
        hosts_data = []
        
        for host in nmap_report.hosts:
            if not host.is_up():
                continue
            
            host_info = {
                "ip": host.address,
                "hostname": host.hostnames[0] if host.hostnames else None,
                "status": host.status,
                "ports": []
            }
            
            for service in host.services:
                # Ne garder que les ports ouverts
                if service.state != "open":
                    continue
                
                port_info = {
                    "port": service.port,
                    "protocol": service.protocol,
                    "state": service.state,  # sera toujours "open" ici
                    "service": service.service,
                    "product": getattr(service, 'service_dict', {}).get('product', ''),
                    "version": getattr(service, 'service_dict', {}).get('version', ''),
                    "extrainfo": getattr(service, 'service_dict', {}).get('extrainfo', ''),
                    "banner": service.banner
                }
                host_info["ports"].append(port_info)
            
            # Si aucun port ouvert, tu peux choisir de garder ou de skipper l’hôte
            if host_info["ports"]:
                hosts_data.append(host_info)
        
        try:
            with open(json_file, 'w') as f:
                json.dump(hosts_data, f, indent=4)
            print(f" ✅ Fichier JSON généré (ports open uniquement) : {json_file}")
        except Exception as e:
            print(f" ❌ Erreur lors de l'écriture du fichier JSON {json_file}: {e}")
