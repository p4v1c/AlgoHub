import subprocess


def run_cmd(cmd, cwd=None):
    """
    Exécute une commande de manière bloquante.
    - Masque les mots de passe à l'affichage.
    - Retourne l'objet CompletedProcess (code retour, stdout/stderr vides car redirigés).
    """
    # Masquer le mot de passe dans l'affichage
    cmd_display = []
    skip_next = False
    
    for item in cmd:
        if skip_next:
            skip_next = False
            cmd_display.append("*****")
            continue
        
        if item in ["-p", "-P", "-ap"]:
            cmd_display.append(item)
            skip_next = True
        elif len(item) > 2 and item[0] == '-' and '=' in item:
            key, value = item.split('=', 1)
            if key.lower() in ["-p", "-ap", "-password"]:
                cmd_display.append(f"{key}=*****")
            else:
                cmd_display.append(item)
        else:
            cmd_display.append(item)
    
    print("\n→ Exécution :", " ".join(cmd_display))
    
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return result
    except FileNotFoundError:
        print("❌ Commande introuvable :", cmd[0])
    except Exception as e:
        print(f"❌ Erreur lors de l'exécution : {e}")
    
    return None
