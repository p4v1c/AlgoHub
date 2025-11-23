import os
import json
import subprocess
import re
from pathlib import Path

class ManSpiderScanner:
    """Gère les scans ManSpider (recherche classique ou credentials dans les shares)."""

    def __init__(self, base_output_dir, network_cidr):
        self.network_cidr = network_cidr
        safe_cidr = str(network_cidr).replace(":", "").replace("/", "_").replace("\\", "_")
        self.output_dir = Path(base_output_dir) / safe_cidr
        self.output_dir.mkdir(parents=True, exist_ok=True)

    # ------ API Scan standard ------
    def scan_files(self, domain, username, password, network_cidr=None, output_json="enum_file.json"):
        cidr = network_cidr or self.network_cidr
        exts = [
            "pfx", "p12", "pkcs12",
            "pem", "key", "crt", "cer",
            "csr", "jks", "keystore",
            "keys", "der",
            "json", "xml", "ini",
            "ps1", "bat", "dll",
            "dmp", "vbs",
            "txt", "log", "config", "conf",
            "kdbx"
        ]
        cmd = [
            "/opt/tools/MANSPIDER/venv/bin/python3",
            "/opt/tools/MANSPIDER/man_spider/manspider.py",
            cidr,
            "-e", *exts,
            "-d", domain,
            "-u", username,
            "-p", password,
            "-n",
            "-t", "20",
            "-s", "100M"
        ]
        print(f"\n🕷️ Scan standard sur le réseau {cidr}...")
        self._run_and_process(cmd, output_json=output_json)

    # ------ API Scan creds ------
    def scan_creds(self, domain, username, password, network_cidr=None, output_json="grepcreds.json"):
        cidr = network_cidr or self.network_cidr
        exts = [
            "docx", "xlsx", "pdf", "txt", "log", "ini", "xml",
            "pem", "kdbx", "pfx", "cred", "key", "conf", "config",
            "json", "bat", "ps1", "psd1", "psm1", "vbs"
        ]
        
        # PATTERNS EXHAUSTIFS pour maximiser la détection
        patterns = [
            # Basiques password
            "password", "Password", "PASSWORD",
            "passwd", "Passwd", "PASSWD",
            "passw", "Passw", "PASSW",
            "pass", "Pass", "PASS",
            "pwd", "Pwd", "PWD",
            "pswd", "pword",
            
            # Français
            "motdepasse", "mot_de_passe", "mot-de-passe",
            "mdp", "passe",
            
            # Avec underscores/tirets
            "password:", "password=", "password =",
            "passwd:", "passwd=", "passwd =",
            "pass:", "pass=", "pass =",
            "pwd:", "pwd=", "pwd =",
            
            # Contextes spécifiques
            "userpassword", "user_password", "user-password",
            "adminpassword", "admin_password", "admin-password",
            "rootpassword", "root_password", "root-password",
            "dbpassword", "db_password", "database_password",
            "sqlpassword", "sql_password",
            "apipassword", "api_password",
            "servicepassword", "service_password", "svc_password",
            
            # Credentials génériques
            "credential", "credentials", "Credential", "Credentials",
            "cred", "creds", "Cred", "Creds",
            
            # Authentication
            "auth", "Auth", "authentication", "Authentication",
            "login", "Login", "logon", "Logon",
            "username", "user", "Username", "User",
            
            # Secrets & keys
            "secret", "Secret", "SECRET",
            "secrets", "Secrets",
            "key", "Key", "KEY",
            "keys", "Keys", "KEYS",
            "privatekey", "private_key", "private-key",
            "apikey", "api_key", "api-key",
            "token", "Token", "TOKEN",
            "access_token", "accesstoken",
            "bearer", "Bearer",
            
            # Comptes privilégiés
            "admin", "Admin", "ADMIN",
            "administrator", "Administrator",
            "root", "Root", "ROOT",
            "sudo", "sa", "sysadmin",
            "domainadmin", "domain_admin",
            
            # Services
            "ldap", "LDAP", "ldap_password",
            "ad", "AD", "ad_password",
            "smtp", "SMTP", "smtp_password",
            "ftp", "FTP", "ftp_password",
            "ssh", "SSH", "ssh_password",
            "rdp", "RDP", "rdp_password",
            "vpn", "VPN", "vpn_password",
            "sql", "SQL", "mysql", "postgres", "oracle",
            
            # Database
            "database", "Database", "db", "DB",
            "connectionstring", "connection_string",
            "dsn", "DSN",
            
            # Configuration
            "config", "Config", "configuration",
            "settings", "Settings",
            
            # Backup & old
            "backup", "Backup", "bak",
            "old", "Old", "copy",
            
            # Certificats
            "certificate", "cert", "Cert",
            "pfx", "PFX", "p12", "P12",
            
            # Hash & encryption
            "hash", "Hash", "HASH",
            "ntlm", "NTLM", "lm", "LM",
            "encrypted", "cipher",
            
            # Variables d'environnement
            "PASSWORD", "PASSWD", "PWD",
            "API_KEY", "API_PASSWORD",
            "DB_PASSWORD", "DATABASE_PASSWORD",
            "ADMIN_PASSWORD", "ROOT_PASSWORD",
            "SECRET", "SECRET_KEY",
            
            # Métier
            "account", "Account", "compte",
            "identifiant", "utilisateur"
        ]
        
        cmd = [
            "/opt/tools/MANSPIDER/venv/bin/python3",
            "/opt/tools/MANSPIDER/man_spider/manspider.py",
            cidr,
            "-e", *exts,
            "-c", *patterns,
            "-d", domain,
            "-u", username,
            "-p", password,
            "-n",
            "-t", "100",
            "-s", "10M"
        ]
        print(f"\n🕷️ Scan credentials sur le réseau {cidr}...")
        print(f"→ {len(patterns)} patterns de recherche utilisés")
        self._run_and_process(cmd, output_json=output_json)

    # ------ Implémentation commune ----------
    def _run_and_process(self, cmd, output_json="manspider_results.json"):
        print(f"→ Commande : {' '.join(cmd)}")
        result = subprocess.run(
            cmd,
            cwd=str(self.output_dir),
            text=True,
            capture_output=True,
        )
        raw_log_path = self.output_dir / "manspider_raw_output.txt"
        raw_content = (result.stdout or "") + "\n" + (result.stderr or "")
        raw_log_path.write_text(raw_content, encoding="utf-8")
        if result.returncode != 0:
            print(f"⚠️ ManSpider a retourné {result.returncode}. Voir {raw_log_path}")
        findings = self._parse_manspider_output(raw_content)
        json_path = self.output_dir / output_json
        json_path.write_text(json.dumps(findings, indent=2), encoding="utf-8")
        print(f"✅ Scan terminé, résultats JSON dans {json_path}")

    def _strip_ansi(self, s: str) -> str:
        ansi_re = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
        return ansi_re.sub("", s)

    def _parse_manspider_output(self, output_text):
        hosts = {}
        logged_in = set()
        current_file_matches = {}
        
        debug_lines_path = self.output_dir / "manspider_parse_debug.txt"
        dbg = debug_lines_path.open("w", encoding="utf-8")
        dbg.write("=== DEBUG PARSE MANSPIDER ===\n")
        
        lines = (output_text or "").splitlines()
        
        for idx, raw_line in enumerate(lines, start=1):
            clean_line = self._strip_ansi(raw_line)
            dbg.write(f"\n[LINE {idx}] RAW   : {raw_line!r}\n")
            dbg.write(f"[LINE {idx}] CLEAN : {clean_line!r}\n")
            
            line = clean_line.strip()
            if not line.startswith("[+]"):
                dbg.write(f"[LINE {idx}] SKIP: ne commence pas par '[+]'\n")
                continue
            if len(line) < 4:
                dbg.write(f"[LINE {idx}] SKIP: ligne trop courte après '[+]'\n")
                continue
            
            content = line[4:].strip()
            dbg.write(f"[LINE {idx}] CONTENT: {content!r}\n")
            
            # 1. Détection login
            if 'Successful login as "' in content and ": " in content:
                try:
                    ip_part, _ = content.split(": ", 1)
                    ip = ip_part.strip()
                    logged_in.add(ip)
                    hosts.setdefault(ip, {"ip": ip, "files": []})
                    dbg.write(f"[LINE {idx}] LOGIN DETECTED pour IP {ip}\n")
                except ValueError as e:
                    dbg.write(f"[LINE {idx}] ERROR login split: {e}\n")
                continue
            
            # 2. Format GREP : "10.3.10.11\NETLOGON\script.ps1: matched "keyword" N times"
            if "matched" in content and ": matched " in content:
                try:
                    full_path, match_info = content.split(": matched ", 1)
                    
                    # Extraire keyword et count
                    keyword_match = re.search(r'"([^"]+)"\s+(\d+)\s+times?', match_info)
                    if keyword_match:
                        keyword = keyword_match.group(1)
                        match_count = keyword_match.group(2)
                    else:
                        keyword = "unknown"
                        match_count = match_info.split()[0] if match_info else "unknown"
                    
                    # Séparer IP du chemin
                    parts = full_path.replace("\\\\", "\\").split("\\", 1)
                    if len(parts) == 2:
                        ip = parts[0].strip()
                        file_path = parts[1].strip()
                    else:
                        ip = parts[0].strip()
                        file_path = full_path.strip()
                    
                    dbg.write(f"[LINE {idx}] GREP FORMAT - IP: {ip!r}, FILE: {file_path!r}, KEYWORD: {keyword!r}, MATCHES: {match_count}\n")
                    
                    if ip in logged_in:
                        hosts.setdefault(ip, {"ip": ip, "files": []})
                        
                        # Créer ou récupérer l'entrée du fichier
                        file_key = f"{ip}\\{file_path}"
                        if file_key not in current_file_matches:
                            current_file_matches[file_key] = {
                                "path": file_path,
                                "matches": [],
                                "code_snippets": []
                            }
                        
                        current_file_matches[file_key]["matches"].append({
                            "keyword": keyword,
                            "count": match_count
                        })
                    else:
                        dbg.write(f"[LINE {idx}] SKIP: IP {ip} pas encore loggée\n")
                except Exception as e:
                    dbg.write(f"[LINE {idx}] ERROR grep format: {e}\n")
                continue
            
            # 3. Extraits de code (lignes qui suivent un match)
            if not ":" in content or (content.startswith("$") or content.startswith("#") or content.startswith("//") or "=" in content):
                # C'est probablement un extrait de code
                if current_file_matches:
                    last_file_key = list(current_file_matches.keys())[-1]
                    # Limiter les snippets à 10 lignes max par fichier
                    if len(current_file_matches[last_file_key]["code_snippets"]) < 10:
                        current_file_matches[last_file_key]["code_snippets"].append(content)
                        dbg.write(f"[LINE {idx}] CODE SNIPPET ajouté\n")
                continue
            
            # 4. Format classique : "IP: SHARE\file.ext (SIZE)"
            if ": " in content:
                try:
                    ip_part, rest = content.split(": ", 1)
                    ip = ip_part.strip()
                    rest = rest.strip()
                    
                    if ip in logged_in and "(" in rest and rest.endswith(")"):
                        dbg.write(f"[LINE {idx}] CLASSIC FORMAT\n")
                        try:
                            path_part, size_part = rest.rsplit(" (", 1)
                            size = size_part[:-1].strip()
                            file_path = path_part.strip()
                            
                            hosts.setdefault(ip, {"ip": ip, "files": []})
                            hosts[ip]["files"].append({
                                "path": file_path,
                                "size": size
                            })
                            dbg.write(f"[LINE {idx}] FILE PATH: {file_path!r}, SIZE: {size!r}\n")
                        except ValueError as e:
                            dbg.write(f"[LINE {idx}] ERROR rsplit: {e}\n")
                    else:
                        dbg.write(f"[LINE {idx}] SKIP: format non reconnu ou IP pas loggée\n")
                except ValueError as e:
                    dbg.write(f"[LINE {idx}] ERROR split general: {e}\n")
        
        # Ajouter les fichiers avec matches aux hosts
        for file_key, file_data in current_file_matches.items():
            ip = file_key.split("\\", 1)[0]
            if ip in hosts:
                hosts[ip]["files"].append(file_data)
        
        dbg.write("\n=== ETAT FINAL ===\n")
        dbg.write(f"logged_in = {logged_in!r}\n")
        dbg.write(f"hosts keys = {list(hosts.keys())!r}\n")
        dbg.write(f"Total files with matches: {len(current_file_matches)}\n")
        dbg.close()
        
        print(f"[DEBUG] Fin _parse_manspider_output, IP trouvées: {list(hosts.keys())}")
        print(f"[DEBUG] Fichiers avec credentials trouvés: {len(current_file_matches)}")
        print(f"[DEBUG] Fichier de debug: {debug_lines_path}")
        return list(hosts.values())
