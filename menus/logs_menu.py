import os
import subprocess
from pathlib import Path
from simple_term_menu import TerminalMenu
from config import GOWITNESS_SERVER_LOG, BLOODHOUND_UI_LOG

class LogsMenu:
    """Menu pour consulter les logs des services avec navigation par flèches."""
    
    @staticmethod
    def show():
        """Affiche le menu des logs."""
        options = [
            "📄 Logs du serveur GoWitness",
            "📄 Logs de l'interface BloodHound CE",
            "🔙 Retour au menu principal"
        ]
        
        terminal_menu = TerminalMenu(
            options,
            title="📋 CONSULTATION DES LOGS\n",
            menu_cursor="➤ ",
            menu_cursor_style=("fg_cyan", "bold"),
            menu_highlight_style=("fg_cyan", "fg_gray"),
            cycle_cursor=True,
            clear_screen=True
        )
        
        while True:
            LogsMenu._clear_screen()
            choice_index = terminal_menu.show()
            
            if choice_index == 0:
                LogsMenu._show_log(GOWITNESS_SERVER_LOG, "GoWitness")
            elif choice_index == 1:
                LogsMenu._show_log(BLOODHOUND_UI_LOG, "BloodHound CE")
            elif choice_index == 2 or choice_index is None:
                break
    
    @staticmethod
    def _clear_screen():
        """Efface l'écran."""
        os.system("cls" if os.name == "nt" else "clear")
    
    @staticmethod
    def _show_log(log_file, service_name):
        """Affiche le contenu d'un fichier log."""
        LogsMenu._clear_screen()
        
        if not log_file.exists():
            print(f"\n⚠️ Aucun log disponible pour {service_name}.")
            print(f"   Fichier attendu : {log_file}")
            input("\n⏸️  Appuyez sur Entrée pour continuer...")
            return
        
        print(f"\n📄 Logs de {service_name} ({log_file}) :")
        print("="*60)
        
        try:
            subprocess.run(["less", str(log_file)], check=False)
        except FileNotFoundError:
            # Fallback si 'less' n'est pas disponible
            with open(log_file, 'r') as f:
                print(f.read())
            input("\n⏸️  Appuyez sur Entrée pour continuer...")
        except Exception as e:
            print(f"❌ Erreur lors de la lecture du fichier : {e}")
            input("\n⏸️  Appuyez sur Entrée pour continuer...")
