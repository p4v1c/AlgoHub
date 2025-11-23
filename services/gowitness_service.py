import time
import subprocess
from multiprocessing import Process
from pathlib import Path
from services.base_service import BaseService          
from services.process_utils import is_service_active, stop_service
from config import (
    GOWITNESS_DB_URI_ABSOLUTE,
    GOWITNESS_REPORT_PORT,
    GOWITNESS_SERVER_LOG,
    GOWITNESS_SCREENSHOT_PATH_ABSOLUTE,
)


class GoWitnessService(BaseService):
    def __init__(self):
        super().__init__("GoWitness")
        self.process = None
    
    def is_active(self):
        return is_service_active('gowitness', keyword='report server', port=GOWITNESS_REPORT_PORT)
    
    def start(self):
        if self.is_active():
            print(" ⚠️ Le serveur GoWitness est déjà en cours d'exécution.")
            return

        if not GOWITNESS_DB_URI_ABSOLUTE or not GOWITNESS_SCREENSHOT_PATH_ABSOLUTE:
            print(" ❌ Chemins GoWitness non initialisés (DB ou screenshots).")
            print("    Vérifie que MainMenu._init_gowitness_paths() est bien appelé au démarrage.")
            return
    
        if GOWITNESS_SERVER_LOG.exists():
            GOWITNESS_SERVER_LOG.unlink()
        
        print(f" [DEBUG] Logs serveur GoWitness : {GOWITNESS_SERVER_LOG}")
        print(f" [DEBUG] DB URI : {GOWITNESS_DB_URI_ABSOLUTE}")
        print(f" [DEBUG] Screenshots : {GOWITNESS_SCREENSHOT_PATH_ABSOLUTE}")
        
        def run_server():
            cmd = [
                "gowitness", "report", "server",
                "--port", str(GOWITNESS_REPORT_PORT),
                "--db-uri", GOWITNESS_DB_URI_ABSOLUTE,
                "--screenshot-path", GOWITNESS_SCREENSHOT_PATH_ABSOLUTE,
            ]
            try:
                with open(GOWITNESS_SERVER_LOG, 'a') as f_log:
                    subprocess.Popen(cmd, stdout=f_log, stderr=f_log, close_fds=True)
            except FileNotFoundError:
                print(" ❌ Outil gowitness non trouvé.")
            except Exception as e:
                print(f" ❌ Erreur inattendue : {e}")
        
        self.process = Process(target=run_server)
        self.process.start()
        time.sleep(1)
        
        if self.is_active():
            print(" 🌐 Serveur GoWitness lancé et détecté comme ACTIF.")
        else:
            print(" ❌ Serveur lancé mais non détecté. Vérifiez les logs.")

    def stop(self):
        """Arrête le serveur GoWitness."""
        stop_service('gowitness', keyword='report server')
        print("✅ Serveur GoWitness arrêté.")