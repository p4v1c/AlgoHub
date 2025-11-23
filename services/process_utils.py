import time
import psutil

def is_service_active(process_name, keyword=None, port=None):
    """Vérifie si un processus est actif par nom, mot-clé dans la commande et port."""
    for proc in psutil.process_iter(['name', 'cmdline', 'pid']):
        if proc.info['name'] == process_name:
            cmdline = ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else ''
            
            if keyword and keyword not in cmdline:
                continue
            
            if port:
                try:
                    connections = proc.net_connections()
                    if connections:
                        if any(conn.laddr.port == port for conn in connections):
                            return True
                except psutil.AccessDenied:
                    continue
            else:
                return True
    
    return False

def stop_service(process_name, keyword=None):
    """Arrête tous les processus correspondants au nom et au mot-clé."""
    pids_to_kill = []
    
    for proc in psutil.process_iter(['name', 'cmdline', 'pid']):
        if proc.info['name'] == process_name:
            cmdline = ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else ''
            if not keyword or keyword in cmdline:
                pids_to_kill.append(proc.info['pid'])
    
    if not pids_to_kill:
        return True
    
    print(f" 🛑 Arrêt des processus '{process_name}' ({len(pids_to_kill)} PID(s))...")
    
    for pid in pids_to_kill:
        try:
            process = psutil.Process(pid)
            process.terminate()
            time.sleep(0.1)
            if process.is_running():
                process.kill()
        except psutil.NoSuchProcess:
            continue
    
    print(f" ✅ Service '{process_name}' arrêté.")
    return True
