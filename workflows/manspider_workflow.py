from simple_term_menu import TerminalMenu
from pathlib import Path
from scanners.manspider_scanner import ManSpiderScanner
from utils.state_manager import is_scanned, mark_as_scanned
from concurrent.futures import ThreadPoolExecutor, as_completed

class ManSpiderWorkflow:
    """Workflow ManSpider avec choix options et réseaux multiples (parallélisation)."""

    def __init__(self, base_output_dir):
        self.base_output_dir = Path(base_output_dir)
        self.base_output_dir.mkdir(parents=True, exist_ok=True)
    
    def run(self):
        print("="*60)
        print("🕷️ WORKFLOW MANSPIDER")
        print("="*60)
        options = [
            "🗂 Scan standard (extensions classiques, chemins)",
            "🔑 Recherche de credentials (filenames et contenu)"
        ]
        terminal_menu = TerminalMenu(
            options,
            title="Choisissez le type de scan ManSpider (utilisez ↑/↓ puis [Entrée]) :\n",
            menu_cursor="➤ ",
            menu_highlight_style=("bg_cyan", "fg_black"),
            cycle_cursor=True,
            clear_screen=True
        )
        mode_index = terminal_menu.show()
        mode = "standard" if mode_index == 0 else "creds"
        
        cidr_input = input("Subnets / CIDRs (ex: 10.3.10.0/24 10.3.50.0/28): ").strip()
        # ✅ Supporte espaces ET virgules
        cidr_list = [s.strip() for s in cidr_input.replace(',', ' ').split()]
        if not cidr_list:
            print("❌ Aucun sous-réseau précisé !")
            return
        
        domain = input("Domaine : ").strip()
        username = input("Nom d'utilisateur : ").strip()
        password = input("Mot de passe : ").strip()

        # Filtrer les sous-réseaux déjà scannés
        key = "standard_scanned" if mode == "standard" else "creds_scanned"
        new_cidrs = [cidr for cidr in cidr_list if not is_scanned("ManSpider", cidr, key=key)]
        already_scanned = [cidr for cidr in cidr_list if is_scanned("ManSpider", cidr, key=key)]
        if already_scanned:
            print(f"⚠️ Sous-réseaux déjà scannés (ignorés) : {', '.join(already_scanned)}")
        if not new_cidrs:
            print("✅ Tous les sous-réseaux ont déjà été scannés.")
            return

        print(f"\n✅ {len(new_cidrs)} sous-réseau(x) à scanner en parallèle : {', '.join(new_cidrs)}")

        # Lancement parallèle des scans
        with ThreadPoolExecutor(max_workers=min(5, len(new_cidrs))) as executor:
            futures = {}
            for cidr in new_cidrs:
                future = executor.submit(self._scan_single_cidr, cidr, domain, username, password, mode, key)
                futures[future] = cidr
            
            for future in as_completed(futures):
                cidr = futures[future]
                try:
                    future.result()
                    print(f"✅ Scan terminé pour {cidr}")
                except Exception as e:
                    print(f"❌ Erreur lors du scan de {cidr} : {e}")

        print("\n✅ Tous les scans ManSpider sont terminés.")

    def _scan_single_cidr(self, cidr, domain, username, password, mode, key):
        """Lance un scan ManSpider sur un seul sous-réseau."""
        print(f"\n{'-'*60}\n🕷️ Scan SMB sur {cidr} ({mode})")
        manscan = ManSpiderScanner(self.base_output_dir, cidr)
        if mode == "standard":
            manscan.scan_files(domain, username, password, network_cidr=cidr, output_json="enum_file.json")
        else:
            manscan.scan_creds(domain, username, password, network_cidr=cidr, output_json="grepcreds.json")
        mark_as_scanned("ManSpider", cidr, key=key)
