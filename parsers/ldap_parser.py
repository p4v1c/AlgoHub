import re
from pathlib import Path


class LdapParser:
    
    @staticmethod
    def extract_relay_targets(smb_signing_file, output_file, dc_hosts=None):
        """
        Génère scan/relay.txt même si nxc_smb_signing.txt n'existe pas.
        - Si nxc_smb_signing.txt existe : extrait les IP avec signing:False.
        - Ajoute en plus les DC (ldap:// et ldaps://) si fournis.
        - Toujours dédupliqué.
        """
        dc_hosts = dc_hosts or []
        smb_signing_path = Path(smb_signing_file)
        output_path = Path(output_file)

        ips = []

        # 1. Si le fichier NetExec existe, on tente d'en extraire des IP
        ips = []

        if smb_signing_path.exists():
            try:
                with smb_signing_path.open('r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        # On ajoute chaque ligne si elle ressemble à une IP
                        if re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', line):
                            ips.append(line)
            except Exception as e:
                print(f" ⚠️ Erreur lors de la lecture de {smb_signing_path}: {e}")


        urls = set()

        # 2. IP sans SMB signing -> schémas relay "classiques"
        for ip in ips:
            urls.add(f"smb://{ip}")
            urls.add(f"winrm://{ip}")
            urls.add(f"http://{ip}")
            urls.add(f"https://{ip}")
            urls.add(f"mssql://{ip}")

        # 3. DC -> ldap / ldaps uniquement (même si le fichier NetExec n'existe pas)
        for dc in dc_hosts:
            host = dc.strip()
            if not host:
                continue
            urls.add(f"ldap://{host}")
            urls.add(f"ldaps://{host}")

        # 4. Même si on n'a rien, on crée quand même le fichier (éventuellement vide)
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with output_path.open('w', encoding='utf-8') as f:
                for url in sorted(urls):
                    f.write(f"{url}\n")
            print(f" ✅ relay.txt généré dans {output_path} avec {len(urls)} entrée(s).")
        except Exception as e:
            print(f" ❌ Erreur lors de l'écriture dans {output_path}: {e}")
            return []

        return list(urls)
