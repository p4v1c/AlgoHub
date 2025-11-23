from pathlib import Path
from utils.command_runner import run_cmd
from parsers.nmap_json_builder import NmapJsonBuilder
from config import ALL_PORTS_NMAP, NMAP_OPTIONS, OUTPUT_BASE_DIR


class NmapScanner:
    """Gère les scans Nmap (un dossier par sous-réseau + modes liste d'hôtes)."""
    
    def __init__(self, base_output_dir=None):
        self.base_output_dir = Path(base_output_dir or OUTPUT_BASE_DIR)
        self.base_output_dir.mkdir(parents=True, exist_ok=True)
    
    def _subnet_folder(self, subnet: str) -> Path:
        safe_name = subnet.replace("/", "_").replace(".", "_")
        folder = self.base_output_dir / safe_name
        folder.mkdir(parents=True, exist_ok=True)
        return folder
    
    def scan_subnet(self, subnet: str):
        subdir = self._subnet_folder(subnet)
        xml_file = subdir / "full_scan.xml"
        json_file = subdir / "full_scan.json"
        
        cmd = [
            "nmap", subnet,
            "-p", ALL_PORTS_NMAP,
            "-sV", "-sC"
        ] + NMAP_OPTIONS.split() + [
            "-oX", str(xml_file)
        ]
        
        print(f"\n📡 Lancement du scan Nmap sur {subnet}...")
        print(f"📁 Dossier de sortie : {subdir}")
        run_cmd(cmd)
        
        if xml_file.exists():
            print(f" ✅ Scan Nmap terminé. Résultats XML : {xml_file}")
            NmapJsonBuilder.build_json(str(xml_file), str(json_file))
            print(f" ✅ JSON généré : {json_file}")
        else:
            print(f" ❌ Fichier XML Nmap non généré pour {subnet}.")
        
        return {
            "folder": subdir,
            "xml": xml_file if xml_file.exists() else None,
            "json": json_file if json_file.exists() else None,
        }
