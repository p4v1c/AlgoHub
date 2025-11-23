from pathlib import Path
from workflows.base_workflow import BaseWorkflow
from scanners.nmap_scanner import NmapScanner
from scanners.gowitness_scanner import GoWitnessScanner
from parsers.ldap_parser import LdapParser
from utils.state_manager import mark_as_scanned, is_scanned
from utils.validators import validate_subnets
from scanners.nxc_scanner import NxcScanner
from config import OUTPUT_BASE_DIR, RELAY_TARGETS_GLOBAL
from concurrent.futures import ThreadPoolExecutor, as_completed

class BlackBoxWorkflow(BaseWorkflow):
    """Workflow Black Box : scan sans credentials."""
    
    def __init__(self):
        super().__init__(OUTPUT_BASE_DIR)
    
    def run(self):
        print("\n" + "="*60)
        print("🔍 WORKFLOW BLACK BOX - Scan sans credentials")
        print("="*60)
        
        print("\n📌 Entrez les sous-réseaux à scanner (format CIDR, ex: 192.168.1.0/24)")
        print("   Séparez par des virgules ou espaces. Tapez 'q' pour annuler.")
        user_input = input("Sous-réseaux : ").strip()
        if user_input.lower() == 'q':
            print("❌ Scan annulé.")
            return
        subnets_raw = [s.strip() for s in user_input.replace(',', ' ').split()]
        valid_subnets, errors = validate_subnets(subnets_raw)
        if errors:
            print("\n⚠️ Erreurs de validation :")
            for error in errors:
                print(f"  {error}")
        if not valid_subnets:
            print("❌ Aucun sous-réseau valide fourni.")
            return

        # Demander les DC (optionnel, pour ldap/ldaps)
        print("\n📌 Entrez l'adresse IP ou le hostname des DC (optionnel).")
        print("   Vous pouvez en mettre plusieurs, séparées par des virgules ou des espaces.")
        print("   Laissez vide si vous ne voulez pas en ajouter.")
        dc_input = input("DC (IP/FQDN) : ").strip()
        dc_hosts = []
        if dc_input:
            dc_raw = [s.strip() for s in dc_input.replace(',', ' ').split()]
            dc_hosts = [h for h in dc_raw if h]
        if dc_hosts:
            print(f"✅ DC configurés : {', '.join(dc_hosts)}")
        else:
            print("ℹ️ Aucun DC supplémentaire configuré.")

        # Filtrer les sous-réseaux déjà scannés
        new_subnets = [s for s in valid_subnets if not is_scanned("BlackBox", s)]
        already_scanned = [s for s in valid_subnets if is_scanned("BlackBox", s)]
        if already_scanned:
            print(f"\n⚠️ Sous-réseaux déjà scannés (ignorés) : {', '.join(already_scanned)}")
        if not new_subnets:
            print("✅ Tous les sous-réseaux ont déjà été scannés.")
            return
        print(f"\n✅ {len(new_subnets)} sous-réseau(x) à scanner en parallèle : {', '.join(new_subnets)}")
        
        # Lancement parallèle des scans
        with ThreadPoolExecutor(max_workers=min(5, len(new_subnets))) as executor:
            futures = {}
            for subnet in new_subnets:
                future = executor.submit(self._scan_single_subnet, subnet, dc_hosts)
                futures[future] = subnet
            
            for future in as_completed(futures):
                subnet = futures[future]
                try:
                    future.result()
                    print(f"✅ Scan terminé pour {subnet}")
                except Exception as e:
                    print(f"❌ Erreur lors du scan de {subnet} : {e}")

        print(f"\n{'='*60}")
        print("✅ Workflow Black Box terminé !")
        print(f"{'='*60}")

    def _scan_single_subnet(self, subnet, dc_hosts):
        """Lance tous les scans pour un seul sous-réseau."""
        print(f"\n{'='*60}")
        print(f"🎯 Scan du sous-réseau : {subnet}")
        print(f"{'='*60}")
        
        nmap_scanner = NmapScanner(self.output_dir)
        gowitness_scanner = GoWitnessScanner(self.output_dir)
        nxc_scanner = NxcScanner(self.output_dir)
        
        nmap_result = nmap_scanner.scan_subnet(subnet)
        if nmap_result and nmap_result["xml"] and nmap_result["xml"].exists():
            gowitness_scanner.scan_from_nmap_xml(str(nmap_result["xml"]))
        nxc_scanner.scan_smb_signing(subnet)
        smb_signing_file = self.output_dir / "nxc_smb_signing.txt"
        LdapParser.extract_relay_targets(
            str(smb_signing_file),
            str(RELAY_TARGETS_GLOBAL),
            dc_hosts=dc_hosts
        )
        mark_as_scanned("BlackBox", subnet)
