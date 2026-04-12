#!/usr/bin/env python3
"""
Outil d'audit de sécurité des cookies web.
Analyse les cookies d'un site web et évalue leur configuration selon OWASP.
"""

import argparse
import sys
from typing import List
from src import CookieCollector, CookieAnalyzer, CookieReporter
from src.utils import ColorFormatter

def parse_arguments():
    """Parse les arguments de ligne de commande."""
    parser = argparse.ArgumentParser(
        description="Analyse la sécurité des cookies d'un site web",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  %(prog)s https://example.com
  %(prog)s -u https://site1.com https://site2.com -o rapport.html
  %(prog)s -f sites.txt --depth 2 --format html
        """
    )
    
    parser.add_argument(
        'urls',
        nargs='*',
        help='URLs à analyser'
    )
    
    parser.add_argument(
        '-f', '--file',
        help='Fichier contenant une liste d\'URLs (une par ligne)'
    )
    
    parser.add_argument(
        '-o', '--output',
        default='rapport_cookies',
        help='Nom de base du fichier de sortie (sans extension)'
    )
    
    parser.add_argument(
        '--format',
        choices=['json', 'html', 'csv', 'md', 'all'],
        default='html',
        help='Format du rapport (défaut: html)'
    )
    
    parser.add_argument(
        '--depth',
        type=int,
        default=0,
        help='Profondeur de crawling (0 = pas de crawling, défaut: 0)'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=10,
        help='Timeout des requêtes en secondes (défaut: 10)'
    )
    
    parser.add_argument(
        '--delay',
        type=float,
        default=1.0,
        help='Délai entre requêtes en secondes (défaut: 1.0)'
    )
    
    parser.add_argument(
        '--no-color',
        action='store_true',
        help='Désactive les couleurs dans la console'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Affiche plus de détails'
    )
    
    return parser.parse_args()

def load_urls_from_file(filename: str) -> List[str]:
    """Charge les URLs depuis un fichier."""
    try:
        with open(filename, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
        return urls
    except Exception as e:
        print(f"Erreur lecture fichier {filename}: {e}")
        return []

def main():
    """Fonction principale."""
    args = parse_arguments()
    
    # Collecte des URLs
    urls = []
    if args.urls:
        urls.extend(args.urls)
    if args.file:
        urls.extend(load_urls_from_file(args.file))
    
    if not urls:
        print("❌ Erreur: Aucune URL spécifiée")
        print("Utilisez: python audit_cookies.py <url> ou -f <fichier>")
        sys.exit(1)
    
    print(f"\n🔍 Démarrage de l'analyse pour {len(urls)} URL(s)...")
    
    # Initialisation des composants
    collector = CookieCollector(timeout=args.timeout, delay=args.delay)
    analyzer = CookieAnalyzer()
    reporter = CookieReporter()
    
    # Collecte des cookies
    all_results = []
    for url in urls:
        print(f"\n📡 Analyse de {url}...")
        result = collector.collect_from_url(url)
        
        if 'error' in result:
            print(f"   ❌ Erreur: {result['error']}")
            continue
        
        cookies = result.get('cookies', [])
        print(f"   ✅ {len(cookies)} cookie(s) trouvé(s)")
        
        # Analyse des cookies
        context = {'is_https': url.startswith('https')}
        analysis = analyzer.analyze_cookies(cookies, context)
        
        # Affichage du résumé
        if not args.no_color:
            analyzer.print_analysis_summary(analysis)
        
        all_results.append({
            'url': url,
            'result': result,
            'analysis': analysis
        })
    
    if not all_results:
        print("\n❌ Aucune analyse réalisée avec succès")
        sys.exit(1)
    
    # Génération du rapport
    print(f"\n📊 Génération du rapport...")
    
    if args.format == 'all':
        formats = ['json', 'html', 'csv', 'md']
    else:
        formats = [args.format]
    
    generated_files = []
    for fmt in formats:
        # Fusionner tous les résultats pour un rapport global
        global_analysis = {
            'results': [],
            'statistics': {
                'total': 0,
                'secure_count': 0,
                'insecure_count': 0,
                'risk_counts': {level: 0 for level in analyzer.RISK_LEVELS}
            }
        }
        
        for item in all_results:
            global_analysis['results'].extend(item['analysis']['results'])
            stats = item['analysis']['statistics']
            global_analysis['statistics']['total'] += stats['total']
            global_analysis['statistics']['secure_count'] += stats['secure_count']
            global_analysis['statistics']['insecure_count'] += stats['insecure_count']
            for level, count in stats['risk_counts'].items():
                global_analysis['statistics']['risk_counts'][level] += count
        
        filepath = reporter.generate_report(global_analysis, fmt, args.output)
        generated_files.append(filepath)
        print(f"   ✅ Rapport {fmt.upper()} généré: {filepath}")
    
    print(f"\n✨ Analyse terminée ! {len(generated_files)} rapport(s) généré(s)")
    
    # Détection de problèmes critiques pour exit code
    critical_count = global_analysis['statistics']['risk_counts'].get('CRITICAL', 0)
    if critical_count > 0:
        print(f"\n⚠️  Attention: {critical_count} cookie(s) avec risque CRITIQUE détecté(s)")
        sys.exit(1)

if __name__ == "__main__":
    main()
