import json
from pathlib import Path
from utils.command_runner import run_cmd

class LdeepScanner:
    """Gère les scans Ldeep (LDAP) ciblés (trusts, pkis, users, delegations, computers) et export JSON + usernames.txt."""
    
    def __init__(self, base_output_dir, dc_host):
        safe_dc = str(dc_host).replace(":", "_").replace("/", "_").replace("\\", "_")
        self.output_dir = Path(base_output_dir) / safe_dc
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def dump_specific(self, dc_ip, domain, username, password):
        print(f"\n📂 Lancement de ldeep (dump spécifique) sur {dc_ip}...")
        
        # 1. Trusts (JSON)
        print("\n🔗 Récupération des trusts...")
        trusts_file = self.output_dir / "trusts.json"
        cmd_trusts = [
            "ldeep", "--outfile", str(trusts_file),
            "ldap",
            "-s", f"ldap://{dc_ip}",
            "-d", domain,
            "-u", username,
            "-p", password,
            "trusts",
            "-v"
        ]
        run_cmd(cmd_trusts)

        # 2. PKIs (JSON)
        print("\n🔐 Récupération des PKIs...")
        pkis_file = self.output_dir / "pkis.json"
        cmd_pkis = [
            "ldeep", "--outfile", str(pkis_file),
            "ldap",
            "-s", f"ldap://{dc_ip}",
            "-d", domain,
            "-u", username,
            "-p", password,
            "pkis",
            "-v"
        ]
        run_cmd(cmd_pkis)

        # 3. Delegations (JSON)
        print("\n🔐 Récupération des delegations...")
        delegations_file = self.output_dir / "delegations.json"
        cmd_delegations = [
            "ldeep", "--outfile", str(delegations_file),
            "ldap",
            "-s", f"ldap://{dc_ip}",
            "-d", domain,
            "-u", username,
            "-p", password,
            "delegations",
            "-v"
        ]
        run_cmd(cmd_delegations)

        # 4. Users (JSON)
        print("\n🔐 Récupération des utilisateurs activés...")
        users_file = self.output_dir / "users.json"
        cmd_users = [
            "ldeep", "--outfile", str(users_file),
            "ldap",
            "-s", f"ldap://{dc_ip}",
            "-d", domain,
            "-u", username,
            "-p", password,
            "users",
            "enabled",
            "-v"
        ]
        run_cmd(cmd_users)

        # 5. Computers & IP Resolution (JSON) - NOUVELLE ÉTAPE
        print("\n💻 Récupération des ordinateurs et résolution IP...")
        machines_ip_file = self.output_dir / "machines-ip.json"
        cmd_computers = [
            "ldeep", "--outfile", str(machines_ip_file),
            "ldap",
            "-s", f"ldap://{dc_ip}",
            "-d", domain,
            "-u", username,
            "-p", password,
            "computers",
            "--resolve",
            "-v"
        ]
        run_cmd(cmd_computers)
        
        print(f"\n✅ Dump LDAP spécifique terminé dans {self.output_dir}")
        
        # Parse et exporte en JSON agrégé
        # On passe le nouveau fichier machines_ip_file au parser
        results = self._parse_results(trusts_file, pkis_file, users_file, delegations_file, machines_ip_file)
        self._export_json(results)

        # Export usernames.txt à partir de users.json
        self._export_usernames_from_users_json(users_file)

        return results

    def _parse_results(self, trusts_file, pkis_file, users_file, delegations_file, machines_ip_file):
        results = {
            "trusts": [],
            "pkis": [],
            "users": [],
            "delegations": [],
            "computers_resolve": [], # Nouvelle clé pour les résultats
        }

        # Parse trusts.json
        if trusts_file.exists():
            try:
                with trusts_file.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                results["trusts"] = data if isinstance(data, list) else [data]
            except Exception as e:
                print(f" ⚠️ Erreur lors de la lecture de {trusts_file}: {e}")

        # Parse pkis.json
        if pkis_file.exists():
            try:
                with pkis_file.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                results["pkis"] = data if isinstance(data, list) else [data]
            except Exception as e:
                print(f" ⚠️ Erreur lors de la lecture de {pkis_file}: {e}")

        # Parse users.json
        if users_file.exists():
            try:
                with users_file.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                results["users"] = data if isinstance(data, list) else [data]
            except Exception as e:
                print(f" ⚠️ Erreur lors de la lecture de {users_file}: {e}")

        # Parse delegations.json
        if delegations_file.exists():
            try:
                with delegations_file.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                results["delegations"] = data if isinstance(data, list) else [data]
            except Exception as e:
                print(f" ⚠️ Erreur lors de la lecture de {delegations_file}: {e}")

        # Parse machines-ip.json (NOUVEAU)
        if machines_ip_file.exists():
            try:
                with machines_ip_file.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                results["computers_resolve"] = data if isinstance(data, list) else [data]
            except Exception as e:
                print(f" ⚠️ Erreur lors de la lecture de {machines_ip_file}: {e}")

        return results

    def _export_json(self, results):
        json_file = self.output_dir / "ldap_results.json"
        json_data = {
            "metadata": {
                "scanner": "ldeep",
                "export_type": "structured_ldap_dump"
            },
            "data": {
                "trusts": {
                    "count": len(results["trusts"]),
                    "items": results["trusts"],
                },
                "pkis": {
                    "count": len(results["pkis"]),
                    "items": results["pkis"],
                },
                "users": {
                    "count": len(results["users"]),
                    "items": results["users"],
                },
                "delegations": {
                    "count": len(results["delegations"]),
                    "items": results["delegations"],
                },
                "computers_resolve": {
                    "count": len(results["computers_resolve"]),
                    "items": results["computers_resolve"],
                },
            },
        }
        try:
            with json_file.open("w", encoding="utf-8") as f:
                json.dump(json_data, f, indent=4, ensure_ascii=False)
            print(f"\n✅ Résultats JSON agrégés dans {json_file}")
        except Exception as e:
            print(f" ❌ Erreur lors de l'export JSON : {e}")

    def _export_usernames_from_users_json(self, users_file, output_name="usernames.txt", include_machines=False):
        """Extrait sAMAccountName des users.json et écrit un fichier texte un user par ligne."""
        if not users_file.exists():
            print(f"⚠️ Fichier users.json introuvable, pas d'export usernames.")
            return
        
        try:
            with users_file.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            print(f" ⚠️ Erreur lors de la lecture de {users_file} pour usernames: {e}")
            return

        if not isinstance(data, list):
            data = [data]

        usernames = []
        for entry in data:
            sam = entry.get("sAMAccountName")
            if not sam:
                continue
            # Ignore comptes machine/trusts si demandé
            if not include_machines and sam.endswith("$"):
                continue
            usernames.append(sam)

        if not usernames:
            print("⚠️ Aucun sAMAccountName trouvé dans users.json.")
            return

        out_file = self.output_dir / output_name
        try:
            with out_file.open("w", encoding="utf-8") as f:
                for u in sorted(set(usernames)):
                    f.write(u + "\n")
            print(f"✅ {len(set(usernames))} utilisateurs exportés dans {out_file}")
        except Exception as e:
            print(f" ❌ Erreur lors de l'écriture de {out_file}: {e}")