import subprocess
import argparse
import sys
import re
import shutil
import shlex  # Pour afficher les commandes proprement
import json   # Ajout pour l'export JSON
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- CONFIGURATION DES DROITS INTÉRESSANTS ---
INTERESTING_MASKS = [
    "FullControl",
    "GenericAll",
    "GenericWrite",
    "WriteDacl",
    "WriteOwner",
    "WriteProperty",
    "ExtendedRight",
    "Self",
    "ControlAccess"
]

# Regex
RE_ACE_BLOCK = re.compile(r"ACE\[\d+\] info(.*?)(?=ACE\[\d+\] info|Total ACEs|\Z)", re.DOTALL)
RE_ACCESS_MASK = re.compile(r"Access mask\s*:\s*(.*)", re.IGNORECASE)
RE_TRUSTEE = re.compile(r"Trustee \(SID\)\s*:\s*(.*)", re.IGNORECASE)

# --- EXCEPTION PERSONNALISÉE POUR ARRÊT D'URGENCE ---
class AuthenticationError(Exception):
    """Levée quand une erreur d'authentification est détectée"""
    pass

def check_tools():
    if not shutil.which("ldapsearch"):
        print("[!] Erreur: 'ldapsearch' n'est pas trouvé dans le PATH.")
        sys.exit(1)
    try:
        subprocess.run(["dacledit.py", "--help"], capture_output=True)
    except FileNotFoundError:
        print("[!] Erreur: 'dacledit.py' n'est pas trouvé. Assurez-vous qu'il est dans le PATH.")
        sys.exit(1)

def get_all_dns(dc_ip, user_upn, password, base_dn, verbose=False):
    """
    Utilise ldapsearch avec le format user@domain (UPN)
    """
    print(f"[*] Récupération des objets via ldapsearch...")

    cmd = [
        "ldapsearch", "-x", "-H", f"ldap://{dc_ip}",
        "-D", user_upn,
        "-w", password,
        "-b", base_dn,
        "(objectClass=*)", "distinguishedName"
    ]

    if verbose:
        debug_cmd = cmd.copy()
        debug_cmd[7] = "*****"
        print(f"[DEBUG] Commande LDAP exécutée :\n   {shlex.join(debug_cmd)}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Erreur critique ldapsearch (Code {e.returncode})")
        err_msg = e.stderr

        # Gestion des erreurs d'authentification Step 1
        if "data 52e" in err_msg or "Invalid credentials" in err_msg:
            print("\n[!!!] AUTH FAILED (LDAP): Identifiants invalides.")
            print("      Le script s'arrête immédiatement.")
            sys.exit(1)
        elif "data 775" in err_msg:
            print("\n[!!!] COMPTE VERROUILLÉ (Account Locked - data 775) [!!!]")
            sys.exit(1)
        elif "data 525" in err_msg:
            print("\n[!] UTILISATEUR INTROUVABLE (User not found - data 525).")
            sys.exit(1)
        else:
            print(f"Détails bruts: {err_msg}")
            sys.exit(1)

    dns = []
    for line in result.stdout.splitlines():
        if line.startswith("distinguishedName: "):
            dn = line.split(": ")[1].strip()
            dns.append(dn)

    print(f"[+] {len(dns)} objets trouvés dans l'AD.")
    return dns

def parse_dacledit_output(output, target_dn, filter_trustees=None, verbose=False):
    findings = []
    ace_blocks = RE_ACE_BLOCK.findall(output)

    for block in ace_blocks:
        mask_match = RE_ACCESS_MASK.search(block)
        trustee_match = RE_TRUSTEE.search(block)

        if mask_match and trustee_match:
            raw_mask = mask_match.group(1).strip()
            access_mask_str = raw_mask.split('(')[0].strip()
            raw_trustee = trustee_match.group(1).strip()
            trustee = raw_trustee.split('(')[0].strip()

            if filter_trustees:
                match_found = False
                for f in filter_trustees:
                    if f.lower() in trustee.lower():
                        match_found = True
                        break
                if not match_found:
                    continue

            is_interesting = any(interest.lower() in access_mask_str.lower() for interest in INTERESTING_MASKS)

            if "Principal Self" in trustee and "Read" in access_mask_str and "Write" not in access_mask_str:
                 continue

            if is_interesting:
                findings.append({
                    "dn": target_dn,
                    "trustee": trustee,
                    "rights": access_mask_str
                })
    return findings

def check_single_dn(dn, impacket_creds_string, filter_trustees=None, verbose=False):
    """
    Utilise dacledit. Si auth fail, lève une exception pour arrêter le main thread.
    """
    cmd = ["dacledit.py", impacket_creds_string, "-target-dn", dn, "-action", "read"]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        # Vérification critique des erreurs AVANT tout traitement
        if result.returncode != 0:
            err_msg = result.stderr.strip()
            
            # Détection des erreurs d'authentification fatales
            if "invalidCredentials" in err_msg or "data 52e" in err_msg or "Login failure" in err_msg:
                # On lève une exception spéciale qui sera attrapée par le main pour tout stopper
                raise AuthenticationError("Invalid Credentials detected")
            
            if "data 775" in err_msg:
                raise AuthenticationError("Account Locked detected")

            if verbose:
                safe_creds = impacket_creds_string.split(':')[0] + ":*****"
                safe_cmd = f"dacledit.py {safe_creds} -target-dn \"{dn}\" -action read"
                print(f"\n[DEBUG] Échec commande: {safe_cmd}")
                print(f"        Erreur: {err_msg}")
            return []

        return parse_dacledit_output(result.stdout, dn, filter_trustees, verbose)

    except AuthenticationError:
        # On relance l'exception pour qu'elle remonte au thread principal
        raise
    except subprocess.TimeoutExpired:
        if verbose: print(f"\n[DEBUG] Timeout sur {dn}")
        return []
    except Exception:
        return []

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-H", "--host", required=True, help="IP du DC (ex: 10.3.10.11)")
    parser.add_argument("-d", "--domain", required=True, help="Domaine FQDN (ex: north.sevenkingdoms.local)")
    parser.add_argument("-u", "--username", required=True, help="Utilisateur SIMPLE (ex: arya.stark)")
    parser.add_argument("-p", "--password", required=True, help="Mot de passe")
    parser.add_argument("-b", "--base-dn", required=True, help="Base DN (ex: DC=north,DC=sevenkingdoms,DC=local)")
    parser.add_argument("-t", "--threads", type=int, default=10)
    parser.add_argument("-v", "--verbose", action="store_true", help="Mode debug (affiche les commandes)")
    parser.add_argument("-f", "--filter", action="append", help="Filtrer par Trustee (ex: -f 'Domain Admins'). Logique OR.")
    parser.add_argument("--json", help="Fichier de sortie pour les résultats au format JSON (ex: output.json)")

    args = parser.parse_args()

    check_tools()

    # Credentials Construction
    ldap_user_upn = f"{args.username}@{args.domain}"
    impacket_creds = f"{args.domain}/{args.username}:{args.password}"

    print(f"[*] Configuration:")
    print(f"    DC IP (LDAP)   : {args.host}")
    print(f"    Auth ldapsearch: {ldap_user_upn}")
    print(f"    Auth dacledit  : {impacket_creds.split(':')[0]}:*****")
    print("-" * 50)

    # Step 1: LDAP Search (Déjà sécurisé par sys.exit)
    all_dns = get_all_dns(args.host, ldap_user_upn, args.password, args.base_dn, args.verbose)

    print(f"[*] Scan ACL en cours avec {args.threads} threads...")

    results = []

    # Step 2: DACL Edit (Sécurisé via Exception et shutdown)
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_dn = {
            executor.submit(check_single_dn, dn, impacket_creds, args.filter, args.verbose): dn
            for dn in all_dns
        }

        completed = 0
        try:
            for future in as_completed(future_to_dn):
                completed += 1
                if completed % 10 == 0:
                    sys.stdout.write(f"\r[*] Progression : {completed}/{len(all_dns)}")
                    sys.stdout.flush()

                try:
                    data = future.result()
                    if data:
                        for vul in data:
                            print(f"\n[+] INTERESSANT: {vul['dn']}")
                            print(f"    Trustee : {vul['trustee']}")
                            print(f"    Rights  : {vul['rights']}")
                            results.append(vul)
                except AuthenticationError as e:
                    # C'est ICI qu'on catch l'erreur fatale venant d'un thread
                    print("\n\n" + "!" * 60)
                    print(f"[!!!] ERREUR CRITIQUE PENDANT LE SCAN DACL : {str(e)}")
                    print("[!!!] Identifiants invalides ou compte verrouillé détecté par dacledit.")
                    print("[!!!] Arrêt immédiat de tous les threads.")
                    print("!" * 60)
                    
                    # On tue le pool de threads pour ne pas continuer
                    executor.shutdown(wait=False, cancel_futures=True)
                    sys.exit(1)
                except Exception:
                    pass
        except KeyboardInterrupt:
            print("\n[!] Interruption utilisateur (Ctrl+C). Arrêt...")
            executor.shutdown(wait=False)
            sys.exit(0)

    print(f"\n\n[*] Analyse terminée. {len(results)} ACLs intéressantes trouvées.")

    if args.json:
        try:
            with open(args.json, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=4, ensure_ascii=False)
            print(f"[+] Résultats exportés avec succès dans : {args.json}")
        except IOError as e:
            print(f"[!] Erreur lors de l'écriture du fichier JSON : {e}")

if __name__ == "__main__":
    main()