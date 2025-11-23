import json
from pathlib import Path
from config import STATE_FILE

def init_state():
    if not STATE_FILE.exists():
        with open(STATE_FILE, "w") as f:
            json.dump({
                "BlackBox": {"scanned_subnets": []},
                "GrayBox": {"scanned_dchosts": []},
                "ManSpider": {"standard_scanned": [], "creds_scanned": []}
            }, f, indent=4)
        print(f"✅ Fichier d'état initialisé : {STATE_FILE}")

def load_state():
    with open(STATE_FILE, "r") as f:
        return json.load(f)

def save_state(data):
    with open(STATE_FILE, "w") as f:
        json.dump(data, f, indent=4)

def is_scanned(workflow, item, key="scanned_subnets"):
    return item in load_state().get(workflow, {}).get(key, [])

def mark_as_scanned(workflow, item, key="scanned_subnets"):
    data = load_state()
    wf_state = data.setdefault(workflow, {})
    lst = wf_state.setdefault(key, [])
    if item not in lst:
        lst.append(item)
        save_state(data)

def is_graybox_scanned(dc_host):
    return is_scanned("GrayBox", dc_host, key="scanned_dchosts")

def mark_graybox_scanned(dc_host):
    mark_as_scanned("GrayBox", dc_host, key="scanned_dchosts")
