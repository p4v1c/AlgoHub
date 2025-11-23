import argparse
import sys
import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from ldap3 import Server, Connection, ALL, SASL, KERBEROS, NTLM
from impacket.dcerpc.v5 import transport, rrp
from impacket.dcerpc.v5.dtypes import NULL

# Configuration des logs
logging.basicConfig(format='%(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

class SessionHunter:
    def __init__(self, args):
        self.args = args
        self.username = args.username
        self.password = args.password
        self.domain = args.domain
        self.dc_ip = args.dc_ip
        self.hashes = args.hashes
        self.lmhash = ''
        self.nthash = ''

        if self.hashes:
            self.lmhash, self.nthash = self.hashes.split(':')

        # Cache pour SID -> User et détection AdminCount
        self.sid_map = {}
        self.admin_users = set()
        self.computers = []

    def get_ldap_connection(self):
        """Établit la connexion LDAP pour récupérer infos users et computers"""
        server = Server(self.dc_ip, get_info=ALL)

        # Authentification
        if self.hashes:
            conn = Connection(server, user=f'{self.domain}\\{self.username}', password=self.lmhash + ':' + self.nthash, authentication=NTLM)
        else:
            conn = Connection(server, user=f'{self.domain}\\{self.username}', password=self.password, authentication=NTLM)

        if not conn.bind():
            logger.error(f"[!] Erreur bind LDAP: {conn.result}")
            sys.exit(1)
        return conn

    def enumerate_ldap(self):
        """Récupère Computers et mappage SID Utilisateurs"""
        conn = self.get_ldap_connection()
        search_base = self.get_search_base(conn)

        logger.info(f"[*] Énumération LDAP sur {self.domain}...")

        # 1. Récupérer les utilisateurs pour mapper SID -> Nom et vérifier adminCount
        # On prend tout pour avoir la résolution de nom, c'est rapide en Python
        conn.search(search_base, '(objectClass=user)', attributes=['sAMAccountName', 'objectSid', 'adminCount'])

        for entry in conn.entries:
            try:
                sid = str(entry.objectSid)
                name = str(entry.sAMAccountName)
                self.sid_map[sid] = name

                if str(entry.adminCount) == '1':
                    self.admin_users.add(name)
            except:
                continue

        logger.info(f"[+] {len(self.sid_map)} utilisateurs mis en cache pour résolution SID.")
        logger.info(f"[+] {len(self.admin_users)} utilisateurs identifiés comme High Value (adminCount=1).")

        # 2. Récupérer les ordinateurs cibles
        ldap_filter = '(objectClass=computer)'
        if self.args.servers_only:
            ldap_filter = '(&(objectClass=computer)(operatingSystem=*Server*))'
        elif self.args.workstations_only:
            ldap_filter = '(&(objectClass=computer)(!(operatingSystem=*Server*)))'

        conn.search(search_base, ldap_filter, attributes=['dNSHostName'])

        for entry in conn.entries:
            if entry.dNSHostName:
                self.computers.append(str(entry.dNSHostName))

        logger.info(f"[+] {len(self.computers)} ordinateurs cibles trouvés via LDAP.")
        conn.unbind()

    def get_search_base(self, conn):
        if self.args.base_dn:
            return self.args.base_dn
        return conn.server.info.other['defaultNamingContext'][0]

    def check_registry_sessions(self, target):
        """
        Connect to Remote Registry (HKEY_USERS) to find active sessions.
        Equivalent to the PowerShell script's main non-admin method.
        """
        active_sessions = []

        # Format string connexion Impacket
        # ncacn_np:target[\pipe\winreg]
        stringBinding = r'ncacn_np:%s[\pipe\winreg]' % target

        rpctransport = transport.DCERPCTransportFactory(stringBinding)

        if hasattr(rpctransport, 'set_credentials'):
            rpctransport.set_credentials(self.username, self.password, self.domain, self.lmhash, self.nthash)

        try:
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(rrp.MSRPC_UUID_RRP)

            # Open HKEY_USERS
            ans = rrp.OpenUsers(dce)
            hKey = ans['phKey']

            # Enumerate SubKeys (SIDs)
            index = 0
            while True:
                try:
                    ans = rrp.BaseRegEnumKey(dce, hKey, index)
                    sid_str = ans['lpNameOut'][:-1] # Remove null byte
                    index += 1

                    # Filtrer les SIDs génériques (Local Service, Network Service, etc.)
                    # Les SIDs utilisateurs commencent généralement par S-1-5-21-
                    if "S-1-5-21" in sid_str and "_Classes" not in sid_str:
                        username = self.sid_map.get(sid_str, sid_str) # Résolution via cache LDAP
                        is_admin_count = username in self.admin_users

                        active_sessions.append({
                            'user': username,
                            'sid': sid_str,
                            'is_high_value': is_admin_count
                        })
                except rrp.DCERPCSessionError:
                    # Fin de l'énumération
                    break

            rrp.BaseRegCloseKey(dce, hKey)
            dce.disconnect()

        except Exception as e:
            # logger.debug(f"[-] Erreur sur {target}: {e}")
            return None

        return active_sessions

    def worker(self, target):
        # Scan de port rapide pour éviter d'attendre sur le RPC
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, 445))
            sock.close()
            if result != 0:
                return None
        except:
            return None

        return self.check_registry_sessions(target)

    def run(self):
        self.enumerate_ldap()

        logger.info(f"[*] Démarrage de la chasse aux sessions ({self.args.threads} threads)...")
        print(f"{'HOST':<30} {'USER':<25} {'HIGH VALUE':<10}")
        print("-" * 65)

        with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            future_to_target = {executor.submit(self.worker, target): target for target in self.computers}

            for future in as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    sessions = future.result()
                    if sessions:
                        for session in sessions:
                            # Logique de filtrage --hunt
                            if self.args.hunt and self.args.hunt.lower() not in session['user'].lower():
                                continue

                            # Logique de filtrage --match (seulement high value)
                            if self.args.match and not session['is_high_value']:
                                continue

                            hv_str = "[!]" if session['is_high_value'] else ""

                            # Coloration simple si possible
                            if session['is_high_value']:
                                print(f"\033[91m{target:<30} {session['user']:<25} {hv_str:<10}\033[0m")
                            else:
                                print(f"{target:<30} {session['user']:<25} {hv_str:<10}")

                except Exception as exc:
                    pass

def main():
    parser = argparse.ArgumentParser(description="Python alternative to Invoke-SessionHunter using Impacket & LDAP")

    parser.add_argument("-u", "--username", required=True, help="Username")
    parser.add_argument("-p", "--password", required=False, help="Password")
    parser.add_argument("-H", "--hashes", required=False, help="LM:NT hash")
    parser.add_argument("-d", "--domain", required=True, help="Domain FQDN (ex: contoso.local)")
    parser.add_argument("-dc-ip", required=True, help="Domain Controller IP")

    parser.add_argument("-b", "--base-dn", help="LDAP Base DN (optional, auto-detected otherwise)")

    # Filtres de cibles
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--servers-only", action="store_true", help="Only scan servers")
    group.add_argument("--workstations-only", action="store_true", help="Only scan workstations")

    # Filtres de résultats
    parser.add_argument("--hunt", help="Show sessions only for this specific user")
    parser.add_argument("--match", action="store_true", help="Show only High Value targets (adminCount=1)")

    parser.add_argument("-t", "--threads", type=int, default=20, help="Threads (default 20)")

    args = parser.parse_args()

    if not args.password and not args.hashes:
        print("[!] Password or Hashes required")
        sys.exit(1)

    hunter = SessionHunter(args)
    hunter.run()

if __name__ == "__main__":
    main()