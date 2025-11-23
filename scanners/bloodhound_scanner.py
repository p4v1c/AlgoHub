from pathlib import Path
import os
from utils.command_runner import run_cmd


class BloodHoundScanner:
    """Lance la collecte BloodHound CE + ShareHound pour un DC donné."""
    
    def __init__(self, base_output_dir, dc_host):
        self.dc_host = dc_host
        safe_dc = str(dc_host).replace(":", "_").replace("/", "_").replace("\\", "_")
        self.output_dir = Path(base_output_dir) / safe_dc
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # /workspace/hub/rules, calculé dynamiquement
        project_root = Path(__file__).resolve().parent.parent
        self.rules_dir = project_root / "rules"
    
    def collect_all(self, dc_ip, domain, username, password):
        print(f"\n📂 Dossier BloodHound/ShareHound : {self.output_dir}")
        print(f"[DEBUG] Dossier des règles ShareQL : {self.rules_dir}")
        
        # 1. BloodHound CE
        print(f"\n📂 Lancement de BloodHound CE (collector) sur {dc_ip}...")
        
        cmd_bh = [
            "bloodhound-ce.py",
            "--zip",
            "-c", "All",
            "-d", domain,
            "-u", username,
            "-p", password,
            "-dc", self.dc_host,
            "-ns", dc_ip,
        ]
        print(f"[DEBUG] Commande BloodHound CE : {' '.join(cmd_bh)}")
        print(f"[DEBUG] CWD BloodHound CE       : {self.output_dir}")
        run_cmd(cmd_bh, cwd=str(self.output_dir))
        
        print("[DEBUG] Contenu du dossier après BloodHound CE :")
        for f in self.output_dir.iterdir():
            print(f"  - {f.name}")
        
        # Renommer le zip le plus récent en <dc_host>_bloodhound.zip
        zip_files = sorted(
            self.output_dir.glob("*.zip"),
            key=lambda p: p.stat().st_mtime,
            reverse=True
        )
        
        if zip_files:
            latest_zip = zip_files[0]
            target_zip = self.output_dir / f"{self.dc_host}_bloodhound.zip"
            if latest_zip != target_zip:
                latest_zip.rename(target_zip)
            print(f"✅ Zip BloodHound renommé en {target_zip}")
        else:
            print("⚠️ Aucun zip BloodHound trouvé à renommer (aucun *.zip dans le dossier).")
        
        # 2. ShareHound
        # print(f"\n📂 Lancement de ShareHound sur {dc_ip}...")
        
        # cmd_sharehound = [
        #     "sharehound",
        #     "-au", username,
        #     "-ap", password,
        #     "--ad", domain,
        #     "-ai", dc_ip,
        #     "--subnets",
        #     "--include-common-shares",
        #     "--depth", "5",
        #     "-rf", str(self.rules_dir / "max_depth_2.shareql"),
        #     "-rf", str(self.rules_dir / "skip_common_shares.shareql"),
        #     "-rf", str(self.rules_dir / "focus_sensitive_ext.shareql"),
        #     "-rf", str(self.rules_dir / "private_dirs.shareql"),
            
        # ]
        # print(f"[DEBUG] Commande ShareHound : {' '.join(cmd_sharehound)}")
        # print(f"[DEBUG] CWD ShareHound     : {self.output_dir}")
        # run_cmd(cmd_sharehound, cwd=str(self.output_dir))
        
        # print("[DEBUG] Contenu du dossier après ShareHound :")
        # for f in self.output_dir.iterdir():
        #     print(f"  - {f.name}")
        
        # # Si ShareHound sort opengraph.json dans le CWD, on le renomme
        # default_sharehound_file = self.output_dir / "opengraph.json"
        # if default_sharehound_file.exists():
        #     new_name = f"{self.dc_host}_sharehound.json"
        #     new_path = default_sharehound_file.with_name(new_name)
        #     default_sharehound_file.rename(new_path)
        #     print(f"✅ Fichier ShareHound (opengraph.json) renommé en {new_path.name}")
        # else:
        #     print("⚠️ Aucun fichier ShareHound (opengraph.json) trouvé dans {self.output_dir}")
        
        print(f"\n✅ BloodHound + ShareHound terminés, résultats dans {self.output_dir}")
