#!/usr/bin/env python3
"""
Utils - Fonctions utilitaires et ColorFormatter
Version professionnelle - Style outils de sécurité
"""

import re
from typing import Dict, List, Optional
from urllib.parse import urlparse
from datetime import datetime


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
    """
    Formateur de console style outils de sécurité professionnels.
    """
    
    # Codes ANSI
    COLORS = {
        'CRITICAL': '\033[91m',     # Rouge vif
        'HIGH': '\033[93m',         # Jaune/Orange
        'MEDIUM': '\033[94m',       # Bleu
        'LOW': '\033[92m',          # Vert
        'INFO': '\033[96m',         # Cyan
        'SUCCESS': '\033[92m',      # Vert
        'ERROR': '\033[91m',        # Rouge
        'WARNING': '\033[93m',      # Jaune
        'RESET': '\033[0m',
        'BOLD': '\033[1m',
        'DIM': '\033[2m',
        'GREEN': '\033[92m',
        'YELLOW': '\033[93m',
        'RED': '\033[91m',
        'BLUE': '\033[94m',
        'CYAN': '\033[96m'
    }
    
    # Symboles professionnels (pas d'emojis)
    SYMBOLS = {
        'success': '[+]',
        'error': '[-]',
        'warning': '[!]',
        'info': '[*]',
        'debug': '[#]',
        'question': '[?]',
        'critical': '[CRITIQUE]',
        'high': '[ELEVE]',
        'medium': '[MOYEN]',
        'low': '[FAIBLE]'
    }
    
    def __init__(self, use_color: bool = True):
        """Initialise le formateur avec option de désactivation des couleurs."""
        self.use_color = use_color
    
    def _colorize(self, text: str, color_key: str) -> str:
        """Applique une couleur si activée."""
        if not self.use_color:
            return text
        color = self.COLORS.get(color_key.upper(), self.COLORS['RESET'])
        return f"{color}{text}{self.COLORS['RESET']}"
    
    def print_banner(self, target_count: int = 1, depth: int = 0, 
                     timeout: int = 10, output_format: str = "html") -> None:
        """
        Affiche la bannière de l'outil (style professionnel)
        """
        banner = f"""
╔═══════════════════════════════════════════════════════════════════╗
║                    CookieVigil v1.0.0                          ║
║              Outil d'audit de sécurité des cookies                ║
║            Conforme OWASP | Intégration DevSecOps                 ║
╚═══════════════════════════════════════════════════════════════════╝
[*] Cible(s)    : {target_count} URL(s)
[*] Profondeur  : {depth}
[*] Timeout     : {timeout}s
[*] Format      : {output_format}
[*] Démarrage   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        """
        print(self._colorize(banner, 'BOLD'))
    
    def print_separator(self, char: str = "=", length: int = 60) -> None:
        """Affiche une ligne de séparation."""
        print(self._colorize(char * length, 'DIM'))
    
    def print_header(self, text: str, level: int = 1) -> None:
        """Affiche un en-tête de section."""
        if level == 1:
            print(self._colorize(f"\n{text}", 'BOLD'))
            self.print_separator("-", len(text) + 2)
        else:
            print(self._colorize(f"\n  {text}", 'INFO'))
    
    def result_cookie(self, name: str, risk: str, issues: List[str], 
                      is_sensitive: bool = False) -> None:
        """
        Affiche un résultat de cookie formaté professionnellement.
        """
        # Déterminer le préfixe et la couleur selon le risque
        if risk == 'CRITICAL':
            prefix = self._colorize(self.SYMBOLS['critical'], 'CRITICAL')
            color = 'CRITICAL'
        elif risk == 'HIGH':
            prefix = self._colorize(self.SYMBOLS['high'], 'HIGH')
            color = 'HIGH'
        elif risk == 'MEDIUM':
            prefix = self._colorize(self.SYMBOLS['medium'], 'MEDIUM')
            color = 'MEDIUM'
        else:
            prefix = self._colorize(self.SYMBOLS['low'], 'LOW')
            color = 'LOW'
        
        # Afficher le cookie
        sensitive_tag = self._colorize(" [SENSIBLE]", 'WARNING') if is_sensitive else ""
        print(f"{prefix} {self._colorize(name, color)}{sensitive_tag}")
        
        # Afficher les problèmes
        for i, issue in enumerate(issues):
            if i == len(issues) - 1:
                print(f"    └─ {issue}")
            else:
                print(f"    ├─ {issue}")
    
    def print_summary_table(self, stats: Dict) -> None:
        """
        Affiche un tableau de résumé style professionnel.
        """
        print("\n" + self._colorize("RESUME DE L'ANALYSE", 'BOLD'))
        self.print_separator("-", 50)
        
        print(f"  Total cookies analysés  : {stats.get('total', 0)}")
        print(f"  Cookies sécurisés       : {self._colorize(str(stats.get('secure_count', 0)), 'GREEN')}")
        print(f"  Cookies non sécurisés   : {self._colorize(str(stats.get('insecure_count', 0)), 'RED')}")
        
        sensitive = stats.get('sensitive_count', 0)
        if sensitive > 0:
            print(f"  Cookies SENSIBLES       : {self._colorize(str(sensitive), 'YELLOW')}")
        
        self.print_separator("-", 50)
        
        # Répartition par niveau de risque
        risk_counts = stats.get('risk_counts', {})
        
        critical = risk_counts.get('CRITICAL', 0)
        high = risk_counts.get('HIGH', 0)
        medium = risk_counts.get('MEDIUM', 0)
        low = risk_counts.get('LOW', 0)
        info = risk_counts.get('INFO', 0)
        
        if critical > 0:
            print(f"  {self._colorize('CRITIQUE'.ljust(10), 'CRITICAL')}: {self._colorize(str(critical), 'CRITICAL')}")
        if high > 0:
            print(f"  {self._colorize('ELEVE'.ljust(10), 'HIGH')}: {self._colorize(str(high), 'HIGH')}")
        if medium > 0:
            print(f"  {self._colorize('MOYEN'.ljust(10), 'MEDIUM')}: {self._colorize(str(medium), 'MEDIUM')}")
        if low > 0:
            print(f"  {self._colorize('FAIBLE'.ljust(10), 'LOW')}: {self._colorize(str(low), 'LOW')}")
        if info > 0:
            print(f"  {self._colorize('INFO'.ljust(10), 'INFO')}: {info}")
        
        self.print_separator("-", 50)
        
        # Score de sécurité
        score = stats.get('security_score', 100)
        if score >= 80:
            score_color = 'GREEN'
            score_label = "BON"
        elif score >= 50:
            score_color = 'YELLOW'
            score_label = "MOYEN"
        else:
            score_color = 'RED'
            score_label = "CRITIQUE"
        
        print(f"  Score de sécurité       : {self._colorize(str(score), score_color)}/100 ({score_label})")
        self.print_separator("-", 50)
    
    def print_footer(self, duration: float, report_path: str = None) -> None:
        """Affiche le pied de page avec le résumé final."""
        print("\n" + self._colorize("RESUME FINAL", 'BOLD'))
        self.print_separator("-", 50)
        
        if report_path:
            print(f"  Rapport généré   : {report_path}")
        print(f"  Durée d'exécution: {duration:.2f}s")
        
        self.print_separator("-", 50)
    
    # Méthodes de base (sans emojis)
    def success(self, text: str) -> None:
        """Affiche un message de succès."""
        print(self._colorize(f"{self.SYMBOLS['success']} {text}", 'SUCCESS'))
    
    def error(self, text: str) -> None:
        """Affiche un message d'erreur."""
        print(self._colorize(f"{self.SYMBOLS['error']} {text}", 'ERROR'))
    
    def warning(self, text: str) -> None:
        """Affiche un avertissement."""
        print(self._colorize(f"{self.SYMBOLS['warning']} {text}", 'WARNING'))
    
    def info(self, text: str) -> None:
        """Affiche une information."""
        print(self._colorize(f"{self.SYMBOLS['info']} {text}", 'INFO'))
    
    def question(self, text: str) -> None:
        """Affiche une question."""
        print(self._colorize(f"{self.SYMBOLS['question']} {text}", 'INFO'))
    
    def bold(self, text: str) -> None:
        """Affiche du texte en gras."""
        print(self._colorize(text, 'BOLD'))
    
    # Alias pour compatibilité
    def print_success(self, text: str) -> None:
        self.success(text)
    
    def print_error(self, text: str) -> None:
        self.error(text)
    
    def print_warning(self, text: str) -> None:
        self.warning(text)
    
    def print_info(self, text: str) -> None:
        self.info(text)
