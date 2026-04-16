from typing import Dict, List, Optional
from urllib.parse import urlparse


def normalize_url(url: str) -> str:
    """
    Normalise une URL en ajoutant https:// par défaut.
    
    Args:
        url: URL à normaliser
        
    Returns:
        URL normalisée
        
    Raises:
        ValueError: Si l'URL est vide ou invalide
    """
    if not url or not isinstance(url, str):
        raise ValueError("URL cannot be empty or None")
    
    url = url.strip()
    if not url:
        raise ValueError("URL cannot be empty after stripping")
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url


def extract_domain(url: str) -> str:
    """Extrait le nom de domaine d'une URL."""
    url = normalize_url(url)
    parsed = urlparse(url)
    return parsed.netloc


def is_same_domain(domain1: str, domain2: str) -> bool:
    """Vérifie si deux domaines sont identiques (ignore le préfixe www.)."""
    d1 = domain1.lower().replace('www.', '')
    d2 = domain2.lower().replace('www.', '')
    return d1 == d2


class ColorFormatter:
    """Gère la coloration de la console de façon simple et cohérente."""

    COLORS = {
        'SUCCESS': '\033[92m',
        'ERROR': '\033[91m',
        'WARNING': '\033[93m',
        'INFO': '\033[96m',
        'BOLD': '\033[1m',
        'RESET': '\033[0m'
    }

    def __init__(self, use_color: bool = True):
        self.use_color = use_color

    def _colorize(self, text: str, color_key: str) -> str:
        if not self.use_color:
            return text
        color = self.COLORS.get(color_key.upper(), self.COLORS['RESET'])
        return f"{color}{text}{self.COLORS['RESET']}"

    def success(self, text: str) -> None:
        print(self._colorize(f"✅ {text}", 'SUCCESS'))

    def error(self, text: str) -> None:
        print(self._colorize(f"❌ {text}", 'ERROR'))

    def warning(self, text: str) -> None:
        print(self._colorize(f"⚠️ {text}", 'WARNING'))

    def info(self, text: str) -> None:
        print(self._colorize(f"ℹ️ {text}", 'INFO'))

    def bold(self, text: str) -> None:
        if self.use_color:
            print(f"{self.COLORS['BOLD']}{text}{self.COLORS['RESET']}")
        else:
            print(text)

    def print_success(self, text: str) -> None:
        self.success(text)

    def print_error(self, text: str) -> None:
        self.error(text)

    def print_warning(self, text: str) -> None:
        self.warning(text)

    def print_info(self, text: str) -> None:
        self.info(text)
