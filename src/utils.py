import re
from typing import Dict, List, Optional
from urllib.parse import urlparse

def normalize_url(url: str) -> str:
    """
    Normalise une URL en s'assurant qu'elle a un schéma.
    
    Args:
        url: URL à normaliser
        
    Returns:
        URL normalisée avec https:// par défaut
    """
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url

def extract_domain(url: str) -> str:
    """
    Extrait le nom de domaine d'une URL.
    
    Args:
        url: URL complète
        
    Returns:
        Nom de domaine
    """
    parsed = urlparse(url)
    return parsed.netloc

def is_same_domain(domain1: str, domain2: str) -> bool:
    """
    Vérifie si deux domaines sont identiques (ignore www).
    
    Args:
        domain1: Premier domaine
        domain2: Second domaine
        
    Returns:
        True si les domaines correspondent
    """
    d1 = domain1.lower().replace('www.', '')
    d2 = domain2.lower().replace('www.', '')
    return d1 == d2

class ColorFormatter:
    """Gère la coloration console pour les messages."""
    
    COLORS = {
        'CRITICAL': '\033[91m',  # Rouge
        'HIGH': '\033[93m',       # Orange/Jaune
        'MEDIUM': '\033[94m',      # Bleu
        'LOW': '\033[92m',         # Vert
        'INFO': '\033[97m',        # Blanc
        'RESET': '\033[0m'         # Reset
    }
    
    @classmethod
    def colorize(cls, text: str, level: str) -> str:
        """Ajoute de la couleur à un texte selon le niveau de risque."""
        color = cls.COLORS.get(level.upper(), cls.COLORS['INFO'])
        return f"{color}{text}{cls.COLORS['RESET']}"
