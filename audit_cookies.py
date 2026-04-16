#!/usr/bin/env python3
"""
CookieSentinel - Outil d'audit automatisé de la sécurité des cookies web
Analyse les cookies selon les recommandations OWASP.
"""

import argparse
import sys
from typing import List, Set
from urllib.parse import urlparse

from src import CookieCollector, CookieAnalyzer, CookieReporter
from src.utils import ColorFormatter, normalize_url  # Import depuis utils


def is_valid_url(url: str) -> bool:
    """Valide une URL de base."""
    if not url or not isinstance(url, str):
        return False
    try:
        parsed = urlparse(url)
        return parsed.scheme in ('http', 'https', '') and bool(parsed.netloc or parsed.path)
    except Exception:
        return False


def normalize_and_validate_urls(urls: List[str], verbose: bool = False) -> List[str]:
    """Normalise, valide et dédoublonne les URLs."""
    valid_urls = []
    for u in urls:
        u = u.strip()
        if u and not u.startswith('#') and is_valid_url(u):
            valid_urls.append(normalize_url(u))  # Utilise normalize_url depuis utils
        elif u and not u.startswith('#') and verbose:
            print(f"⚠️ URL ignorée (invalide): {u}")

    # Dédoublonnage en préservant l'ordre
    seen: Set[str] = set()
    return [u for u in valid_urls if not (u in seen or seen.add(u))]


def parse_arguments():
    """Parse les arguments de ligne de commande."""
    parser = argparse.ArgumentParser(
        description="CookieSentinel - Audit automatisé de la sécurité des cookies web (OWASP)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples :
  python audit_cookies.py https://example.com
  python audit_cookies.py -f sites.txt --depth 2 --format all
  python audit_cookies.py --verbose --timeout 15 https://site1.com https://site2.com
  python audit_cookies.py --insecure https://example.com  # Désactive SSL (non recommandé)
        """
    )

    parser.add_argument('urls', nargs='*', help='URLs à analyser')
    parser.add_argument('-f', '--file', help='Fichier contenant une liste d\'URLs (une par ligne)')
    parser.add_argument('-o', '--output', default='rapport_cookies',
                        help='Nom de base du rapport (sans extension)')
    parser.add_argument('--format', choices=['json', 'html', 'csv', 'md', 'all'],
                        default='html', help='Format du rapport')
    parser.add_argument('--depth', type=int, default=0,
                        help='Profondeur de crawling (0 = désactivé)')
    parser.add_argument('--timeout', type=int, default=10,
                        help='Timeout des requêtes HTTP (secondes)')
    parser.add_argument('--delay', type=float, default=1.0,
                        help='Délai entre les requêtes')
    parser.add_argument('--no-color', action='store_true',
                        help='Désactive la coloration de la console')
    parser.add_argument('--verbose', action='store_true',
                        help='Mode verbeux')
    parser.add_argument('--insecure', action='store_true',
                        help='Désactive la vérification SSL (non recommandé - risque MITM)')

    return parser.parse_args()


def load_urls_from_file(filename: str) -> List[str]:
    """Charge les URLs depuis un fichier en ignorant les commentaires."""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except Exception as e:
        print(f"❌ Erreur lecture fichier {filename}: {e}")
        return []


def main():
    """Fonction principale."""
    args = parse_arguments()
    color = ColorFormatter(use_color=not args.no_color)

    # === Collecte et validation des URLs ===
    raw_urls: List[str] = args.urls[:]
    if args.file:
        raw_urls.extend(load_urls_from_file(args.file))

    if not raw_urls:
        color.error("Aucune URL spécifiée. Utilisez une URL ou l'option -f.")
        sys.exit(1)

    urls = normalize_and_validate_urls(raw_urls, args.verbose)

    if not urls:
        color.error("Aucune URL valide après validation.")
        sys.exit(1)

    color.bold(f"\n🔍 Démarrage de l'analyse pour {len(urls)} URL(s)...")

    if args.verbose:
        color.info(f"📋 URLs à analyser : {', '.join(urls)}")

    # === Initialisation des composants ===
    # verify_ssl = True par défaut, désactivé uniquement si --insecure
    verify_ssl = not args.insecure
    
    collector = CookieCollector(
        timeout=args.timeout,
        delay=args.delay,
        depth=args.depth,
        verbose=args.verbose,
        verify_ssl=verify_ssl
    )
    analyzer = CookieAnalyzer()
    reporter = CookieReporter()

    all_results = []

    # === Analyse de chaque URL ===
    for url in urls:
        color.info(f"\n📡 Analyse de {url}...")

        # Gestion du crawling
        if args.depth > 0:
            results = collector.collect_multiple_urls([url], max_depth=args.depth)
        else:
            results = [collector.collect_from_url(url)]

        for result in results:
            if 'error' in result:
                color.error(f"Erreur sur {result.get('url', url)} : {result['error']}")
                continue

            cookies = result.get('cookies', [])
            final_url = result.get('final_url', url)

            context = {'is_https': urlparse(final_url).scheme == 'https'}

            analysis = analyzer.analyze_cookies(cookies, context, source_url=final_url)

            color.success(f"{len(cookies)} cookie(s) trouvé(s) sur {final_url}")

            if args.verbose and analysis['statistics'].get('insecure_count', 0) > 0:
                color.info(f"{analysis['statistics']['insecure_count']} cookie(s) non conformes")

            analyzer.print_analysis_summary(analysis, color=color)

            all_results.append({
                'url': url,
                'final_url': final_url,
                'result': result,
                'analysis': analysis
            })

    if not all_results:
        color.error("Aucune analyse n'a pu être réalisée avec succès.")
        sys.exit(1)

    # === Construction du rapport global ===
    color.info("\n📊 Génération du rapport global...")

    global_analysis = {
        'results': [],
        'statistics': {
            'total': 0,
            'secure_count': 0,
            'insecure_count': 0,
            'sensitive_count': 0,
            'risk_counts': {level: 0 for level in CookieAnalyzer.RISK_LEVELS}
        }
    }

    for item in all_results:
        analysis = item['analysis']
        global_analysis['results'].extend(analysis.get('results', []))

        stats = analysis.get('statistics', {})
        global_analysis['statistics']['total'] += stats.get('total', 0)
        global_analysis['statistics']['secure_count'] += stats.get('secure_count', 0)
        global_analysis['statistics']['insecure_count'] += stats.get('insecure_count', 0)
        global_analysis['statistics']['sensitive_count'] += stats.get('sensitive_count', 0)

        for level, count in stats.get('risk_counts', {}).items():
            global_analysis['statistics']['risk_counts'][level] += count

    # === Génération des rapports ===
    formats = ['json', 'html', 'csv', 'md'] if args.format == 'all' else [args.format]

    for fmt in formats:
        filepath = reporter.generate_report(global_analysis, fmt, args.output)
        color.success(f"Rapport {fmt.upper()} généré → {filepath}")

    color.bold(f"\n✨ Analyse terminée ! {len(formats)} rapport(s) généré(s)")

    # === Codes de sortie pour CI/CD (DevSecOps) ===
    critical = global_analysis['statistics']['risk_counts'].get('CRITICAL', 0)
    high = global_analysis['statistics']['risk_counts'].get('HIGH', 0)

    if critical > 0:
        color.error(f"🔴 {critical} cookie(s) avec risque CRITIQUE détecté(s)")
        sys.exit(2)
    elif high > 0:
        color.warning(f"🟠 {high} cookie(s) avec risque HIGH détecté(s)")
        sys.exit(1)
    else:
        color.success("🟢 Aucune vulnérabilité critique ou haute détectée")
        sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n⛔ Analyse interrompue par l'utilisateur.")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Erreur inattendue : {e}")
        sys.exit(3)
