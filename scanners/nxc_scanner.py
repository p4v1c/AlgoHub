from pathlib import Path
from utils.command_runner import run_cmd

class NxcScanner:
    """Gère les scans NetExec (nxc)."""
    
    def __init__(self, output_dir):
        self.output_dir = Path(output_dir)
    
    
    def scan_smb_signing(self, subnet):
        """Scan SMB signing."""
        output_file = self.output_dir / "nxc_smb_signing.txt"
        cmd = [
            "nxc", "smb", subnet,
            "--gen-relay-list", str(output_file)
        ]
        
        print(f"\n🔍 Scan SMB signing sur {subnet}...")
        run_cmd(cmd)
        print(f" ✅ Résultats dans {output_file}")
    
