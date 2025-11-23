from pathlib import Path

# Racine du projet (là où se trouve config.py / app.py)
PROJECT_ROOT = Path(__file__).resolve().parent

# ======================================================
# CONFIGURATION GLOBALE
# ======================================================

STATE_FILE = PROJECT_ROOT / "state.json"

OUTPUT_BASE_DIR = PROJECT_ROOT / "scan"
RELAY_TARGETS_GLOBAL = OUTPUT_BASE_DIR / "relay.txt"
OUTPUT_BASE_DIR.mkdir(parents=True, exist_ok=True)

# Fichiers et dossiers centralisés

# Dossier global pour les screenshots
GOWITNESS_OUTPUT_GLOBAL = OUTPUT_BASE_DIR / "screenshots_global"
GOWITNESS_OUTPUT_GLOBAL.mkdir(parents=True, exist_ok=True)

# Fichier DB Gowitness (RACINE PROJET)
GOWITNESS_DB_FILE_PATH = PROJECT_ROOT / "gowitness.sqlite3"

# Chemins absolus prêts à l'emploi
GOWITNESS_DB_FILE_PATH_ABSOLUTE = str(GOWITNESS_DB_FILE_PATH)
# sqlite:///ABSOLUTE_PATH (3 / pour un chemin absolu sur le FS)
GOWITNESS_DB_URI_ABSOLUTE = f"sqlite:///{GOWITNESS_DB_FILE_PATH_ABSOLUTE}"
GOWITNESS_SCREENSHOT_PATH_ABSOLUTE = str(GOWITNESS_OUTPUT_GLOBAL)

GOWITNESS_REPORT_PORT = 7171
GOWITNESS_SERVER_LOG = OUTPUT_BASE_DIR / "gowitness_server.log"
GOWITNESS_THREADS = 10

# BloodHound & Neo4j
BLOODHOUND_UI_LOG = OUTPUT_BASE_DIR / "bloodhound_ui_log"
NEO4J_HTTP_PORT = 7474

# WebServer (Flask Dashboard)
WEBSERVER_PORT = 5000
WEBSERVER_LOG = PROJECT_ROOT / "scan" / "webserver.log" # On met le log dans scan/ pour regrouper

# Nmap
ALL_PORTS_NMAP = "80,443,8080,8443,3000,5000,88,445,139,53,135,5985,5986,3389,1433"
NMAP_OPTIONS = "-Pn --min-rate 1000 -T5"