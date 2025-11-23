from pathlib import Path
from workflows.base_workflow import BaseWorkflow
from scanners.nmap_scanner import NmapScanner
from scanners.gowitness_scanner import GoWitnessScanner
from scanners.certipy_scanner import CertipyScanner
from scanners.ldeep_scanner import LdeepScanner
from scanners.bloodhound_scanner import BloodHoundScanner
from utils.paths import resolve_hostname_to_ip
from config import OUTPUT_BASE_DIR
from scanners.manspider_scanner import ManSpiderScanner
from utils.state_manager import is_graybox_scanned, mark_graybox_scanned
from concurrent.futures import ThreadPoolExecutor, as_completed

class GrayBoxWorkflow(BaseWorkflow):
    """Workflow Gray Box : scan avec credentials utilisateur standard."""
    
    def __init__(self):
        super().__init__(OUTPUT_BASE_DIR)
    
    def run(self):
        print("\n" + "="*60)
        print("🔐 WORKFLOW GRAY BOX - Scan avec credentials")
        print("="*60)
        print("\n📌 Entrez les informations d'authentification :")
        
        # Possibilité de scanner plusieurs DC en parallèle
        dc_input = input("Contrôleur(s) de domaine (IP ou FQDN, séparés par espace/virgule) : ").strip()
        dc_hosts = [d.strip() for d in dc_input.replace(',', ' ').split() if d.strip()]
        
        domain = input("Domaine (ex: CORP.LOCAL) : ").strip()
        username = input("Nom d'utilisateur : ").strip()
        password = input("Mot de passe : ").strip()
        
        if not all([dc_hosts, domain, username, password]):
            print("❌ Tous les champs sont requis.")
            return

        # Filtrer les DC déjà scannés
        new_dcs = [dc for dc in dc_hosts if not is_graybox_scanned(dc)]
        already_scanned = [dc for dc in dc_hosts if is_graybox_scanned(dc)]
        if already_scanned:
            print(f"\n⚠️ DC(s) déjà scannés (ignorés) : {', '.join(already_scanned)}")
        if not new_dcs:
            print("✅ Tous les DCs ont déjà été scannés.")
            return
        
        print(f"\n✅ {len(new_dcs)} DC(s) à scanner en parallèle : {', '.join(new_dcs)}")

        # Lancement parallèle des scans (un DC = un thread)
        with ThreadPoolExecutor(max_workers=min(3, len(new_dcs))) as executor:
            futures = {}
            for dc_host in new_dcs:
                future = executor.submit(self._scan_single_dc, dc_host, domain, username, password)
                futures[future] = dc_host
            
            for future in as_completed(futures):
                dc_host = futures[future]
                try:
                    future.result()
                    print(f"✅ Scan terminé pour {dc_host}")
                except Exception as e:
                    print(f"❌ Erreur lors du scan de {dc_host} : {e}")

        print(f"\n{'='*60}")
        print("✅ Workflow Gray Box terminé !")
        print(f"{'='*60}")

    def _scan_single_dc(self, dc_host, domain, username, password):
        """Lance tous les scans pour un seul DC EN PARALLÈLE."""
        if dc_host.replace('.', '').replace(':', '').isdigit():
            dc_ip = dc_host
        else:
            dc_ip = resolve_hostname_to_ip(dc_host)
        if not dc_ip:
            print(f"❌ Impossible de résoudre l'adresse du DC : {dc_host}")
            return
        
        print(f"\n{'='*60}")
        print(f"🎯 Scan du DC : {dc_host}")
        print(f"{'='*60}")
        
        # Lancement parallèle des 4 scanners
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {
                executor.submit(self._run_ldeep_scan, dc_host, dc_ip, domain, username, password): "Ldeep",
                executor.submit(self._run_certipy_scan, dc_host, dc_ip, domain, username, password): "Certipy",
                executor.submit(self._run_bloodhound_scan, dc_host, dc_ip, domain, username, password): "BloodHound"
            }
            
            for future in as_completed(futures):
                scanner_name = futures[future]
                try:
                    future.result()
                    print(f"  ✅ {scanner_name} terminé pour {dc_host}")
                except Exception as e:
                    print(f"  ❌ Erreur {scanner_name} sur {dc_host} : {e}")
        
        mark_graybox_scanned(dc_host)

    def _run_ldeep_scan(self, dc_host, dc_ip, domain, username, password):
        """Scan Ldeep."""
        ldeep_scanner = LdeepScanner(self.output_dir / "ldeep", dc_host)
        ldeep_scanner.dump_specific(dc_ip, domain, username, password)

    def _run_certipy_scan(self, dc_host, dc_ip, domain, username, password):
        """Scan Certipy."""
        certipy_scanner = CertipyScanner(self.output_dir / "certipy", dc_host)
        certipy_scanner.find_vulnerabilities(dc_ip, domain, username, password)

    def _run_bloodhound_scan(self, dc_host, dc_ip, domain, username, password):
        """Scan BloodHound."""
        bh_scanner = BloodHoundScanner(self.output_dir / "bloodhound", dc_host)
        bh_scanner.collect_all(dc_ip, domain, username, password)
