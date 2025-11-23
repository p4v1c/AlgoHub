#!/usr/bin/env python3
"""
Pentest Hub - Application principale
Point d'entrée du programme refactoré en orienté objet.
"""

from menus.main_menu import MainMenu

def main():
    """Point d'entrée principal de l'application."""
    try:
        menu = MainMenu()
        menu.show()
    except KeyboardInterrupt:
        print("\n\n⚠️ Interruption par l'utilisateur (Ctrl+C).")
        print("👋 Fermeture du Pentest Hub...")
    except Exception as e:
        print(f"\n❌ Erreur critique : {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
