import sys
import os
from pathlib import Path
from flask import Flask, render_template, jsonify
import json

# --- CONFIGURATION DES CHEMINS ---
CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = CURRENT_DIR.parent
sys.path.append(str(PROJECT_ROOT))

try:
    from config import WEBSERVER_PORT
except ImportError:
    print("⚠️ Impossible d'importer config.py. Utilisation du port 5000 par défaut.")
    WEBSERVER_PORT = 5000

TEMPLATE_DIR = CURRENT_DIR / 'templates'
SCAN_DATA_DIR = PROJECT_ROOT / 'scan'

app = Flask(__name__, template_folder=str(TEMPLATE_DIR))

# --- FONCTIONS UTILITAIRES ---
def read_json_file(filepath):
    if not os.path.exists(filepath): return None
    try:
        with open(filepath, 'r', encoding='utf-8') as f: return json.load(f)
    except: return None

def is_data_empty(data):
    if data is None: return True
    if isinstance(data, dict) and not data: return True 
    if isinstance(data, list) and not data: return True 
    return False

def is_valid_manspider_output(data):
    if isinstance(data, list) and len(data) > 0: return True
    return False

# --- ROUTES API (Données) ---
def get_nmap_data():
    results = []
    if not SCAN_DATA_DIR.exists(): return results
    for item in os.listdir(SCAN_DATA_DIR):
        dir_path = SCAN_DATA_DIR / item
        if dir_path.is_dir() and item.startswith("10_"):
            json_path = dir_path / "full_scan.json"
            data = read_json_file(json_path)
            if is_data_empty(data): continue
            
            hosts_list = []
            if isinstance(data, list): hosts_list = data
            elif isinstance(data, dict) and 'hosts' in data: hosts_list = data['hosts']
            else: continue
            
            formatted_title = item.replace("_", ".").replace(".24", "/24")
            results.append({"id": item, "title": f"Subnet: {formatted_title}", "hosts": hosts_list})
    return results

def get_ad_data():
    """
    Retourne une LISTE d'objets, un par DC trouvé dans scan/ldeep.
    Structure: [ { "dc_name": "DC01", "domain": "CORP.LOCAL", "certipy": {...}, "ldeep": [...] }, ... ]
    """
    ad_results = []
    
    # On se base sur le dossier 'ldeep' qui contient un dossier par DC
    ldeep_root = SCAN_DATA_DIR / 'ldeep'
    certipy_root = SCAN_DATA_DIR / 'certipy'
    
    if ldeep_root.exists():
        for dc_folder in os.listdir(ldeep_root):
            dc_path = ldeep_root / dc_folder
            if not dc_path.is_dir(): continue
            
            # Objet pour ce DC
            dc_obj = {
                "dc_name": dc_folder, # ex: 10.0.0.1 ou DC01.CORP
                "domain": "Unknown",
                "certipy": None,
                "ldeep": []
            }
            
            # 1. Charger les données LDEEP
            for f in ["users.json", "trusts.json", "delegations.json", "pkis.json", "ldap_results.json", "machines-ip.json"]:
                f_path = dc_path / f
                data = read_json_file(f_path)
                if not is_data_empty(data):
                    dc_obj["ldeep"].append({"file": f, "data": data})
                    
                    # Tentative de deviner le domaine via le DN du premier user ou trust
                    if dc_obj["domain"] == "Unknown":
                        if f == "users.json" and isinstance(data, list) and len(data) > 0 and "distinguishedName" in data[0]:
                            match = data[0]["distinguishedName"]
                            # Logique simple extraction DC=...
                            import re
                            dcs = re.findall(r'DC=([^,]+)', match)
                            if dcs: dc_obj["domain"] = ".".join(dcs)

            # 2. Chercher les données CERTIPY correspondantes
            # On cherche un dossier dans certipy/ qui a le même nom (ou IP)
            if certipy_root.exists():
                certipy_dc_path = certipy_root / dc_folder
                if certipy_dc_path.exists() and certipy_dc_path.is_dir():
                    # Trouver le JSON certipy
                    for f in os.listdir(certipy_dc_path):
                        if f.endswith("_Certipy.json"):
                            c_data = read_json_file(certipy_dc_path / f)
                            if not is_data_empty(c_data):
                                dc_obj["certipy"] = {"title": "Certipy", "file": f, "data": c_data}
                                # Certipy a souvent le domaine clean
                                if "domain" in c_data: # ça dépend du format exact output certipy
                                    pass 
                            break
            
            ad_results.append(dc_obj)

    return ad_results

def get_manspider_data():
    results = []
    manspider_dir = SCAN_DATA_DIR / 'manspider'
    if not manspider_dir.exists(): return results
    for subnet_item in os.listdir(manspider_dir):
        subnet_path = manspider_dir / subnet_item
        if not subnet_path.is_dir(): continue
        
        subnet_result = {"subnet": subnet_item.replace("_", "."), "files": None, "creds": None}
        has_any_data = False
        
        enum_path = subnet_path / "enum_file.json"
        enum_data = read_json_file(enum_path)
        if is_valid_manspider_output(enum_data):
            subnet_result["files"] = enum_data
            has_any_data = True
            
        grep_path = subnet_path / "grepcreds.json"
        grep_data = read_json_file(grep_path)
        if is_valid_manspider_output(grep_data):
            subnet_result["creds"] = grep_data
            has_any_data = True
            
        if has_any_data: results.append(subnet_result)
    return results

# --- ROUTES WEB ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/users')
def users():
   return render_template('users.html')

@app.route('/machines')
def machines():
   return render_template('machines.html')

@app.route('/checklist')
def checklist():
    return render_template('checklist.html')

@app.route('/api/data')
def get_all_data():
    full_data_structure = {
        "nmap_subnets": get_nmap_data(),
        "ad_enumeration": get_ad_data(), # Retourne maintenant une liste
        "file_analysis": {
            "manspider": get_manspider_data()
        }
    }
    return jsonify(full_data_structure)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=WEBSERVER_PORT, use_reloader=False)