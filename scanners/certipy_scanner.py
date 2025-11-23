from pathlib import Path
from utils.command_runner import run_cmd


class CertipyScanner:
    """Gère les scans Certipy (find vuln) avec un dossier par DC."""
    
    def __init__(self, base_output_dir, dc_host):
        """
        base_output_dir : dossier racine (ex: scan/certipy)
        dc_host : IP ou hostname du DC (utilisé pour nommer le sous-dossier et pour -ns)
        """
        self.dc_host = dc_host  # ← IMPORTANT : on stocke dc_host sur l'instance

        safe_dc = str(dc_host).replace(":", "_").replace("/", "_").replace("\\", "_")
        self.output_dir = Path(base_output_dir) / safe_dc
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def find_vulnerabilities(self, dc_ip, domain, username, password):
        """
        Lance Certipy 'find' en mode vuln (-vuln) avec sortie JSON dans le dossier du DC.
        -dc-ip : IP résolue du DC
        -ns    : nom du DC (dc_host), ou IP si l'utilisateur a donné une IP
        """
        print(f"\n📂 Lancement de Certipy (find vuln) sur {dc_ip}...")
        
        user_upn = f"{username}@{domain}"
        output_prefix = self.output_dir / f"{domain.replace('.', '_')}"
        
        cmd = [
            "certipy", "find",
            "-u", user_upn,
            "-p", password,
            "-vuln",
            "-dc-ip", dc_ip,
            "-json",
            "-output", str(output_prefix),
            "-ns", dc_ip,   # ← ici on utilise bien self.dc_host
        ]
        
        run_cmd(cmd)
        
        print(f"\n✅ Certipy terminé, résultats dans {self.output_dir}")
