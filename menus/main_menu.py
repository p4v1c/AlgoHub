import sys
import os
from simple_term_menu import TerminalMenu
from services.neo4j_service import Neo4jService
from services.bloodhound_service import BloodHoundService
from services.gowitness_service import GoWitnessService
from services.report_server_service import ReportServerService  # <-- Import ajouté
from workflows.blackbox_workflow import BlackBoxWorkflow
from workflows.graybox_workflow import GrayBoxWorkflow
from workflows.manspider_workflow import ManSpiderWorkflow
from menus.logs_menu import LogsMenu
from utils.state_manager import init_state
from config import GOWITNESS_REPORT_PORT, WEBSERVER_PORT


class MainMenu:
    """Menu principal de l'application avec navigation par flèches."""
    
    def __init__(self):
        self.neo4j = Neo4jService()
        self.bloodhound = BloodHoundService()
        self.gowitness = GoWitnessService()
        self.webserver = ReportServerService() # <-- Initialisation du service
        self._init_gowitness_paths()
    
    def _init_gowitness_paths(self):
        """Initialise les chemins absolus pour GoWitness (DB + screenshots)."""
        import config as cfg
        cfg.OUTPUT_BASE_DIR.mkdir(parents=True, exist_ok=True)
        cfg.GOWITNESS_OUTPUT_GLOBAL.mkdir(parents=True, exist_ok=True)
        cfg.GOWITNESS_DB_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
        
        abs_db = cfg.GOWITNESS_DB_FILE_PATH.resolve()
        abs_shots = cfg.GOWITNESS_OUTPUT_GLOBAL.resolve()
        
        cfg.GOWITNESS_DB_FILE_PATH_ABSOLUTE = str(abs_db)
        cfg.GOWITNESS_DB_URI_ABSOLUTE = f"sqlite:///{abs_db}"
        cfg.GOWITNESS_SCREENSHOT_PATH_ABSOLUTE = str(abs_shots)

    def clear_screen(self):
        os.system("cls" if os.name == "nt" else "clear")
    
    def _banner_title(self) -> str:
        return """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ██████╗ ███████╗███╗   ██╗████████╗███████╗███████╗████████╗║
║   ██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝║
║   ██████╔╝█████╗  ██╔██╗ ██║   ██║   █████╗  ███████╗   ██║   ║
║   ██╔═══╝ ██╔══╝  ██╚██╗ ██║   ██║   ██╔══╝  ╚════██║   ██║   ║
║   ██║     ███████╗██║ ╚████║   ██║   ███████╗███████║   ██║   ║
║   ╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝   ╚═╝   ║
║                                                               ║
║                    🎯 ALGOHUB v1.0                            ║
║              Automated Security Assessment Suite              ║
║                 Developed by Victor Paquereau                 ║
╚═══════════════════════════════════════════════════════════════╝

📌 Sélectionnez une option (↑/↓ pour naviguer, Enter pour valider) :

"""
    
    def show(self):
        init_state()
        options = [
            "🔍 Workflow Black Box (sans credentials)",
            "🔐 Workflow Gray Box (avec credentials)",
            "🕷️ Workflow ManSpider SMB",
            "🖥️ Gérer les serveurs",
            "❌ Quitter"
        ]
        
        terminal_menu = TerminalMenu(
            options,
            title=self._banner_title(),          
            menu_cursor="➤ ",
            menu_cursor_style=("fg_cyan", "bold"),
            menu_highlight_style=("bg_cyan", "fg_black"),
            cycle_cursor=True,
            clear_screen=True                  
        )
        
        while True:
            choice_index = terminal_menu.show()
            if choice_index == 0: self._run_blackbox()
            elif choice_index == 1: self._run_graybox()
            elif choice_index == 2: self._run_manspider() 
            elif choice_index == 3: self._manage_servers()
            elif choice_index == 4 or choice_index is None:
                self._cleanup()
                print("\n👋 Fermeture du Pentest Hub...")
                sys.exit(0)
    
    def _run_blackbox(self):
        self.clear_screen()
        BlackBoxWorkflow().run()
        input("\n⏸️  Appuyez sur Entrée pour revenir au menu...")
    
    def _run_graybox(self):
        self.clear_screen()
        GrayBoxWorkflow().run()
        input("\n⏸️  Appuyez sur Entrée pour revenir au menu...")

    def _run_manspider(self):
        self.clear_screen()
        ManSpiderWorkflow("scan/manspider").run()
        input("\n⏸️  Appuyez sur Entrée pour revenir au menu...")
    
    # --- SOUS-MENU WEB SERVER ---
    def _manage_webserver(self):
        options = [
            "🚀 Démarrer le Dashboard Web",
            "🛑 Arrêter le Dashboard Web",
            "📊 Statut du Dashboard",
            "🔙 Retour"
        ]
        menu = TerminalMenu(
            options,
            title="🌐 GESTION DU DASHBOARD WEB (FLASK)\n",
            menu_cursor="➤ ",
            menu_cursor_style=("fg_purple", "bold"),
            menu_highlight_style=("bg_purple", "fg_black"),
            cycle_cursor=True,
            clear_screen=True
        )
        while True:
            idx = menu.show()
            if idx == 0:
                self.webserver.start()
                if self.webserver.is_active():
                    print(f"\n🌐 Dashboard accessible sur : http://127.0.0.1:{self.webserver.port}")
                input("\n⏸️  Appuyez sur Entrée...")
            elif idx == 1:
                self.webserver.stop()
                input("\n⏸️  Appuyez sur Entrée...")
            elif idx == 2:
                status = "ACTIF ✅" if self.webserver.is_active() else "INACTIF ❌"
                print(f"\n📊 Statut Dashboard : {status}")
                if self.webserver.is_active():
                    print(f"🔗 URL : http://127.0.0.1:{self.webserver.port}")
                input("\n⏸️  Appuyez sur Entrée...")
            elif idx == 3 or idx is None:
                break

    def _manage_neo4j(self):
        options = ["🚀 Démarrer Neo4j", "🛑 Arrêter Neo4j", "📊 Statut Neo4j", "🔙 Retour"]
        menu = TerminalMenu(options, title="🌐 GESTION DE NEO4J\n", menu_cursor="➤ ", menu_cursor_style=("fg_green", "bold"), menu_highlight_style=("bg_green", "fg_black"), cycle_cursor=True, clear_screen=True)
        while True:
            idx = menu.show()
            if idx == 0: self.neo4j.start(); input("\n⏸️  Entrée...")
            elif idx == 1: self.neo4j.stop(); input("\n⏸️  Entrée...")
            elif idx == 2: print(f"\n📊 Statut : {'ACTIF ✅' if self.neo4j.is_active() else 'INACTIF ❌'}"); input("\n⏸️  Entrée...")
            elif idx == 3 or idx is None: break

    def _manage_bloodhound(self):
        options = ["🚀 Démarrer BloodHound CE", "🛑 Arrêter BloodHound CE", "📊 Statut BloodHound CE", "🔙 Retour"]
        menu = TerminalMenu(options, title="🩸 GESTION DE BLOODHOUND CE\n", menu_cursor="➤ ", menu_cursor_style=("fg_red", "bold"), menu_highlight_style=("bg_red", "fg_gray"), cycle_cursor=True, clear_screen=True)
        while True:
            idx = menu.show()
            if idx == 0: self.bloodhound.start(); input("\n⏸️  Entrée...")
            elif idx == 1: self.bloodhound.stop(); input("\n⏸️  Entrée...")
            elif idx == 2: print(f"\n📊 Statut : {'ACTIF ✅' if self.bloodhound.is_active() else 'INACTIF ❌'}"); input("\n⏸️  Entrée...")
            elif idx == 3 or idx is None: break

    def _manage_gowitness(self):
        options = ["🚀 Démarrer GoWitness", "🛑 Arrêter GoWitness", "📊 Statut GoWitness", "🔙 Retour"]
        menu = TerminalMenu(options, title="📸 GESTION DE GOWITNESS\n", menu_cursor="➤ ", menu_cursor_style=("fg_yellow", "bold"), menu_highlight_style=("bg_yellow", "fg_black"), cycle_cursor=True, clear_screen=True)
        while True:
            idx = menu.show()
            if idx == 0: 
                self.gowitness.start()
                print(f"\n🌐 Serveur : http://localhost:{GOWITNESS_REPORT_PORT}")
                input("\n⏸️  Entrée...")
            elif idx == 1: self.gowitness.stop(); input("\n⏸️  Entrée...")
            elif idx == 2: print(f"\n📊 Statut : {'ACTIF ✅' if self.gowitness.is_active() else 'INACTIF ❌'}"); input("\n⏸️  Entrée...")
            elif idx == 3 or idx is None: break

    def _manage_servers(self):
        options = [
            "🌐 Neo4j",
            "🩸 BloodHound CE",
            "📸 GoWitness",
            "📊 Dashboard Web (Flask)",  # Option ajoutée
            "🔙 Retour"
        ]
        menu = TerminalMenu(options, title="🖥️ GESTION DES SERVEURS\n", menu_cursor="➤ ", menu_highlight_style=("bg_cyan", "fg_gray"), cycle_cursor=True, clear_screen=True)
        while True:
            idx = menu.show()
            if idx == 0: self._manage_neo4j()
            elif idx == 1: self._manage_bloodhound()
            elif idx == 2: self._manage_gowitness()
            elif idx == 3: self._manage_webserver() # Appel du sous-menu
            elif idx == 4 or idx is None: break
    
    def _cleanup(self):
        print("\n🧹 Nettoyage des services actifs...")
        if self.gowitness.is_active(): self.gowitness.stop()
        if self.bloodhound.is_active(): self.bloodhound.stop()
        if self.neo4j.is_active(): self.neo4j.stop()
        if self.webserver.is_active(): self.webserver.stop() # Arrêt du webserver
        print("✅ Tous les services ont été arrêtés proprement.")