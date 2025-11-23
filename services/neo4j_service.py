import os
import time
import subprocess
from services.base_service import BaseService
from services.process_utils import is_service_active, stop_service
from config import NEO4J_HTTP_PORT

class Neo4jService(BaseService):
    def __init__(self):
        super().__init__("Neo4j")
    
    def is_active(self):
        return is_service_active('java', keyword='neo4j', port=NEO4J_HTTP_PORT)
    
    def start(self):
        if self.is_active():
            print(f" ⚠️ Le service Neo4j est déjà en cours d'exécution sur le port {NEO4J_HTTP_PORT}.")
            return True
        
        print(" 🌐 Lancement de Neo4j avec 'neo4j start'...")
        
        try:
            env = os.environ.copy()
            env["JAVA_HOME"] = "/usr/lib/jvm/java-11-openjdk"
            
            subprocess.run(
                ["neo4j", "start"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=env
            )
            
            time.sleep(3)
            
            status_result = subprocess.run(
                ["neo4j", "status"],
                capture_output=True,
                text=True,
                check=False,
                env=env
            )
            
            if "running" in status_result.stdout.lower():
                print(f" 🌐 Service Neo4j lancé et détecté sur http://localhost:{NEO4J_HTTP_PORT}.")
                return True
            else:
                print(" ❌ Neo4j lancé mais non détecté par 'neo4j status'.")
                print(f" Sortie de 'neo4j status': {status_result.stdout.strip()}")
                return False
        
        except FileNotFoundError:
            print(" ❌ Outil neo4j non trouvé. Assurez-vous qu'il est dans le PATH.")
            return False
        except Exception as e:
            print(f" ❌ Erreur inattendue lors du lancement de Neo4j: {e}")
            return False
    
    def stop(self):
        print(" 🛑 Arrêt de Neo4j avec 'neo4j stop'...")
        
        try:
            subprocess.run(
                ["neo4j", "stop"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            time.sleep(2)
            
            if is_service_active('java', keyword='neo4j'):
                stop_service('java', keyword='neo4j')
            else:
                print("✅ Service Neo4j arrêté.")
        
        except FileNotFoundError:
            print("❌ Commande neo4j non trouvée pour l'arrêt.")
        except Exception as e:
            print(f"❌ Erreur lors de l'arrêt de Neo4j: {e}")
