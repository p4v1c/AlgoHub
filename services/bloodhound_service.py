import time
import subprocess
from services.base_service import BaseService
from services.process_utils import is_service_active, stop_service
from config import BLOODHOUND_UI_LOG


class BloodHoundService(BaseService):
    def __init__(self):
        super().__init__("BloodHound")
        self.bin_path = "/opt/tools/bin/bloodhound-ce"
    
    def is_active(self):
        return (is_service_active('bloodhound') or 
                is_service_active('node', keyword='bloodhound-ce') or 
                is_service_active('electron', keyword='bloodhound-ce'))
    
    def start(self):
        if self.is_active():
            print(" ⚠️ L'interface BloodHound CE est déjà en cours d'exécution.")
            return
        
        print(" 🌐 Lancement de l'interface BloodHound CE...")
        
        try:
            with open(BLOODHOUND_UI_LOG, "a") as f_log:
                subprocess.Popen(
                    [self.bin_path],
                    stdout=f_log,
                    stderr=subprocess.STDOUT,
                    close_fds=True,
                    start_new_session=True
                )
            
            time.sleep(4)
        
        except FileNotFoundError:
            print(f" ❌ Lanceur BloodHound CE non trouvé à {self.bin_path}.")
        except Exception as e:
            print(f" ❌ Erreur inattendue lors du lancement de BloodHound UI: {e}")
    
    def stop(self):
        bloodhound_stopped = stop_service('bloodhound')
        node_stopped = stop_service('node', keyword='bloodhound-ce')
        electron_stopped = stop_service('electron', keyword='bloodhound-ce')
        
        if bloodhound_stopped or node_stopped or electron_stopped:
            print("✅ Interface BloodHound CE arrêtée.")
        else:
            print("✅ Interface BloodHound CE arrêtée (ou n'était pas actif).")
