from pathlib import Path

class BaseWorkflow:
    """Classe de base pour tous les workflows."""
    
    def __init__(self, output_dir):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def run(self):
        """Méthode à implémenter par les workflows enfants."""
        raise NotImplementedError
