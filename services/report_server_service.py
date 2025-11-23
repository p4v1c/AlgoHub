import sys
import os
import subprocess
import time
from pathlib import Path
from services.base_service import BaseService
from config import WEBSERVER_LOG, WEBSERVER_PORT, PROJECT_ROOT

class ReportServerService(BaseService):
    """
    Service qui gère le cycle de vie du serveur Flask (Démarrage/Arrêt).
    Il lance le script server.py en arrière-plan et redirige les logs.
    """

    def __init__(self, port=5000, scan_dir=None, template_dir=None):
        super().__init__("WebServer")
        self.port = WEBSERVER_PORT
        self.script_path = PROJECT_ROOT / "WebServer" / "server.py"
        self.process = None

    def is_active(self):
        # Detection fiable : vérifie si le process est vivant
        if self.process is not None and self.process.poll() is None:
            return True
        return False

    def start(self):
        if self.is_active():
            print(f"⚠️ Le serveur Web est déjà actif sur http://127.0.0.1:{self.port}")
            return

        if not WEBSERVER_LOG.parent.exists():
            WEBSERVER_LOG.parent.mkdir(parents=True, exist_ok=True)

        print(f"🚀 Démarrage du serveur Web sur http://127.0.0.1:{self.port} ...")
        
        try:
            env = os.environ.copy()
            env["PYTHONPATH"] = str(PROJECT_ROOT)
            env["PYTHONUNBUFFERED"] = "1" 

            log_file = open(WEBSERVER_LOG, "a")

            self.process = subprocess.Popen(
                [sys.executable, str(self.script_path)],
                stdout=log_file,
                stderr=subprocess.STDOUT,
                cwd=str(PROJECT_ROOT),
                env=env,
                close_fds=False
            )
            
            time.sleep(2)
            
            if self.is_active():
                print(f"✅ Serveur démarré avec succès.")
                print(f"📄 Logs disponibles dans : {WEBSERVER_LOG}")
            else:
                print(f"❌ Échec du démarrage. Le serveur s'est arrêté immédiatement.")
                print(f"👉 Vérifiez le fichier de log : {WEBSERVER_LOG}")
                log_file.close()

        except FileNotFoundError:
            print(f"❌ Impossible de trouver le fichier : {self.script_path}")
        except Exception as e:
            print(f"❌ Erreur inattendue : {e}")

    def stop(self):
        # Arrêt direct du process si lancé par ce service
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except Exception:
                self.process.kill()
            print("✅ Serveur Web arrêté (via terminate()).")
            self.process = None
            return
        print("⚠️ Aucune instance connue du serveur Web à arrêter.")
