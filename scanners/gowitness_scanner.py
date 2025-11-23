from pathlib import Path
from utils.command_runner import run_cmd
from config import (
    GOWITNESS_OUTPUT_GLOBAL,
    GOWITNESS_DB_FILE_PATH,
)


class GoWitnessScanner:
    """Gère les scans GoWitness à partir d'un XML Nmap, screenshots globaux."""
    
    def __init__(self, base_output_dir):
        # base_output_dir = racine des scans (ex: scan/), pas strictement nécessaire ici
        self.base_output_dir = Path(base_output_dir)
        GOWITNESS_OUTPUT_GLOBAL.mkdir(parents=True, exist_ok=True)
    
    def scan_from_nmap_xml(self, xml_file: str):
        """
        Lance GoWitness directement sur un fichier XML Nmap.
        Les screenshots vont dans scan/screenshots_global
        et la même DB est réutilisée pour tous les scans.
        
        Exemple de commande résultante :
        gowitness scan nmap -f scan/10_189_15_239_24/full_scan.xml \
            -s scan/screenshots_global --write-db --open-only
        """
        xml_path = Path(xml_file)
        if not xml_path.exists():
            print(f" ⚠️ Fichier XML {xml_path} introuvable.")
            return
        
        print(f"\n📸 Lancement de GoWitness sur le XML Nmap : {xml_path}")
        print(f"📁 Dossier screenshots global : {GOWITNESS_OUTPUT_GLOBAL}")
        
        cmd = [
            "gowitness", "scan", "nmap",
            "-f", str(xml_path),
            "-s", str(GOWITNESS_OUTPUT_GLOBAL),
            "--write-db",
            "--open-only",
        ]
        
        run_cmd(cmd)
        print(f" ✅ Scan GoWitness terminé. Screenshots dans {GOWITNESS_OUTPUT_GLOBAL}")
        print(f" ✅ Base Gowitness : {GOWITNESS_DB_FILE_PATH}")
