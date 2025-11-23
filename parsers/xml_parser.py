import xml.etree.ElementTree as ET

class XmlParser:
    """Parse les fichiers XML Nmap."""
    
    @staticmethod
    def parse_nmap_xml(xml_file):
        """
        Parse le fichier XML Nmap et retourne une liste de dictionnaires.
        Chaque dict contient: ip, hostname, ports (liste de dicts avec port, protocol, service, product, version).
        """
        hosts_data = []
        
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            for host in root.findall('host'):
                # Récupérer l'adresse IP
                address = host.find('address')
                if address is None:
                    continue
                
                ip = address.get('addr')
                
                # Récupérer le hostname (optionnel)
                hostname = None
                hostnames_elem = host.find('hostnames')
                if hostnames_elem is not None:
                    hostname_elem = hostnames_elem.find('hostname')
                    if hostname_elem is not None:
                        hostname = hostname_elem.get('name')
                
                # Récupérer les ports
                ports_list = []
                ports_elem = host.find('ports')
                if ports_elem is not None:
                    for port in ports_elem.findall('port'):
                        portid = port.get('portid')
                        protocol = port.get('protocol')
                        
                        state = port.find('state')
                        if state is None or state.get('state') != 'open':
                            continue
                        
                        service = port.find('service')
                        service_name = service.get('name') if service is not None else ''
                        product = service.get('product') if service is not None else ''
                        version = service.get('version') if service is not None else ''
                        
                        ports_list.append({
                            'port': portid,
                            'protocol': protocol,
                            'service': service_name,
                            'product': product,
                            'version': version
                        })
                
                if ports_list:
                    hosts_data.append({
                        'ip': ip,
                        'hostname': hostname,
                        'ports': ports_list
                    })
        
        except FileNotFoundError:
            print(f" ⚠️ Fichier XML {xml_file} non trouvé.")
        except ET.ParseError as e:
            print(f" ⚠️ Erreur de parsing XML dans {xml_file}: {e}")
        except Exception as e:
            print(f" ⚠️ Erreur inattendue lors du parsing de {xml_file}: {e}")
        
        return hosts_data
