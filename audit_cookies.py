#!/usr/bin/env python3
"""
CookieVigil - Outil d'audit automatisé de la sécurité des cookies web
Analyse les cookies selon les recommandations OWASP.
"""

import argparse
import sys
import time
import re
from typing import List, Set
from urllib.parse import urlparse

from src import CookieCollector, CookieAnalyzer, CookieReporter
from src.utils import ColorFormatter, normalize_url


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
            valid_urls.append(normalize_url(u))
        elif u and not u.startswith('#') and verbose:
            print(f"[-] URL ignoree (invalide): {u}")

    seen: Set[str] = set()
    return [u for u in valid_urls if not (u in seen or seen.add(u))]


def parse_arguments():
    """Parse les arguments de ligne de commande."""
    parser = argparse.ArgumentParser(
        description="CookieVigil - Audit automatise de la securite des cookies web (OWASP)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples :
  # Analyse simple
  python audit_cookies.py https://example.com

  # Analyse avec session persistante (authentification POST)
  python audit_cookies.py https://app.com/dashboard --session --login-url https://app.com/login --login-data "user=admin&pass=123"

  # Avec fichier de sites
  python audit_cookies.py -f sites.txt --depth 2 --format all

  # Mode DevSecOps : échouer si risque HIGH ou plus
  python audit_cookies.py https://example.com --fail-on high

  # Mode DevSecOps : échouer si score inférieur à 70
  python audit_cookies.py https://example.com --fail-score-below 70
        """
    )

    parser.add_argument('urls', nargs='*', help='URLs à analyser')
    parser.add_argument('-f', '--file', help='Fichier contenant une liste d\'URLs (une par ligne)')
    parser.add_argument('-o', '--output', default='rapport_cookies',
                        help='Nom de base du rapport (sans extension)')
    parser.add_argument('--format', choices=['json', 'html', 'csv', 'md', 'all'],
                        default='html', help='Format du rapport')
    parser.add_argument('--depth', type=int, default=0,
                        help='Profondeur de crawling (0 = desactive)')
    parser.add_argument('--timeout', type=int, default=10,
                        help='Timeout des requetes HTTP (secondes)')
    parser.add_argument('--delay', type=float, default=1.0,
                        help='Delai entre les requetes')
    parser.add_argument('--no-color', action='store_true',
                        help='Desactive la coloration de la console')
    parser.add_argument('--verbose', action='store_true',
                        help='Mode verbeux')
    parser.add_argument('--insecure', action='store_true',
                        help='Desactive la verification SSL (non recommande - risque MITM)')
    parser.add_argument('--verify', action='store_true',
                        help='Active la verification croisee des cookies')
    parser.add_argument('--session', action='store_true',
                        help='Utilise une session persistante (maintient les cookies entre les requetes)')
    parser.add_argument('--login-url', help='URL de connexion pour authentification POST')
    parser.add_argument('--login-data', help='Donnees de connexion (format: "user=admin&pass=123")')
    parser.add_argument('--force-https-context', action='store_true',
                        help='Force le contexte HTTPS pour la verification des regles OWASP (demonstration)')

    # AJOUT :
    # Permet de choisir le niveau minimal de risque qui fait échouer le pipeline CI/CD.
    # Par défaut : high, ce qui conserve le comportement initial de l'outil.
    parser.add_argument('--fail-on',
                        choices=['none', 'critical', 'high', 'medium', 'low'],
                        default='high',
                        help='Niveau minimal de risque qui provoque un code de sortie non nul')

    # AJOUT :
    # Permet de faire échouer le pipeline selon le score global de sécurité.
    parser.add_argument('--fail-score-below',
                        type=int,
                        default=None,
                        help='Echoue si le score de securite est inferieur a cette valeur')

    return parser.parse_args()


def load_urls_from_file(filename: str) -> List[str]:
    """Charge les URLs depuis un fichier en ignorant les commentaires."""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except Exception as e:
        print(f"[-] Erreur lecture fichier {filename}: {e}")
        return []


def perform_login(session, login_url: str, login_data: str, verify_ssl: bool, color, verbose: bool = False) -> bool:
    """
    Effectue une authentification POST et sauvegarde les cookies avec leurs attributs complets.
    """
    import requests

    post_data = {}
    for item in login_data.split('&'):
        if '=' in item:
            key, value = item.split('=', 1)
            post_data[key] = value

    color.info(f"Authentification sur {login_url}...")
    if verbose:
        display_data = {k: '***' if 'pass' in k.lower() else v for k, v in post_data.items()}
        color.info(f"   Donnees: {display_data}")

    try:
        response = session.post(
            login_url,
            data=post_data,
            timeout=10,
            verify=verify_ssl
        )

        if response.status_code in (200, 302, 301):
            color.success(f"Authentification reussie (status {response.status_code})")

            auth_cookies = []
            cookie_strings = response.raw.headers.getlist('Set-Cookie')

            for cookie_str in cookie_strings:
                try:
                    name_value_match = re.match(r'^([^=]+)=([^;]*)', cookie_str)
                    if not name_value_match:
                        continue

                    name = name_value_match.group(1).strip()
                    value = name_value_match.group(2)

                    # CORRECTION :
                    # On vérifie que Secure et HttpOnly sont de vrais attributs.
                    secure_present = bool(re.search(r'(?:^|;)\s*secure\s*(?:;|$)', cookie_str, re.IGNORECASE))
                    httponly_present = bool(re.search(r'(?:^|;)\s*httponly\s*(?:;|$)', cookie_str, re.IGNORECASE))

                    path_match = re.search(r'Path=([^;]+)', cookie_str, re.IGNORECASE)
                    path = path_match.group(1).strip() if path_match else '/'

                    domain_match = re.search(r'Domain=([^;]+)', cookie_str, re.IGNORECASE)
                    domain = domain_match.group(1).strip() if domain_match else None

                    samesite_match = re.search(r'SameSite=([^;]+)', cookie_str, re.IGNORECASE)
                    samesite = samesite_match.group(1).strip() if samesite_match else None

                    expires_match = re.search(r'Expires=([^;]+)', cookie_str, re.IGNORECASE)
                    expires = expires_match.group(1).strip() if expires_match else None

                    maxage_match = re.search(r'Max-Age=([^;]+)', cookie_str, re.IGNORECASE)
                    max_age = maxage_match.group(1).strip() if maxage_match else None

                    auth_cookies.append({
                        'name': name,
                        'value': value[:200] + "..." if len(value) > 200 else value,
                        'raw_value_for_analysis': value,
                        'value_length': len(value),
                        'attributes': {
                            'domain': domain,
                            'path': path,
                            'expires': expires,
                            'max-age': max_age,
                            'secure': secure_present,
                            'httponly': httponly_present,
                            'samesite': samesite
                        },
                        'source': 'login_response',
                        'raw_header': cookie_str[:200] + "..." if len(cookie_str) > 200 else cookie_str
                    })

                    if verbose:
                        color.info(
                            f"   Parse: {name} -> "
                            f"secure={secure_present}, httponly={httponly_present}, samesite={samesite}"
                        )

                except Exception as e:
                    if verbose:
                        color.warning(f"Erreur parsing cookie: {e}")

            session.auth_cookies = auth_cookies

            if auth_cookies:
                color.info(f"Cookies d'authentification obtenus: {len(auth_cookies)}")
                for cookie in auth_cookies:
                    attrs = cookie['attributes']
                    attr_str = []
                    if attrs.get('secure'):
                        attr_str.append("Secure")
                    if attrs.get('httponly'):
                        attr_str.append("HttpOnly")
                    if attrs.get('samesite'):
                        attr_str.append(f"SameSite={attrs['samesite']}")
                    color.info(f"   - {cookie['name']}: {', '.join(attr_str) if attr_str else 'aucun attribut'}")
            else:
                color.warning("Aucun cookie trouve dans la reponse login")

            return True

        color.error(f"Echec authentification: status {response.status_code}")
        if verbose:
            print(f"   Reponse: {response.text[:200]}")
        return False

    except Exception as e:
        color.error(f"Erreur lors de l'authentification: {e}")
        return False


def main():
    """Fonction principale."""
    args = parse_arguments()
    color = ColorFormatter(use_color=not args.no_color)
    start_time = time.time()

    if args.fail_score_below is not None and not 0 <= args.fail_score_below <= 100:
        color.error("L'option --fail-score-below doit etre comprise entre 0 et 100")
        sys.exit(1)

    if args.session and args.login_url and not args.login_data:
        color.error("L'option --login-data est requise avec --login-url")
        sys.exit(1)

    raw_urls: List[str] = args.urls[:]
    if args.file:
        raw_urls.extend(load_urls_from_file(args.file))

    if not raw_urls:
        color.error("Aucune URL specifiee. Utilisez une URL ou l'option -f.")
        sys.exit(1)

    urls = normalize_and_validate_urls(raw_urls, args.verbose)

    if not urls:
        color.error("Aucune URL valide apres validation.")
        sys.exit(1)

    color.print_banner(
        target_count=len(urls),
        depth=args.depth,
        timeout=args.timeout,
        output_format=args.format
    )

    if args.verbose:
        color.info(f"URLs à analyser : {', '.join(urls)}")
        if args.verify:
            color.info("Mode verification croisee active")
        if args.session:
            color.info("Mode session persistante active")
        if args.force_https_context:
            color.info("Mode force HTTPS context active (demonstration)")
        color.info(f"Politique CI/CD --fail-on : {args.fail_on}")
        if args.fail_score_below is not None:
            color.info(f"Politique CI/CD --fail-score-below : {args.fail_score_below}")

    verify_ssl = not args.insecure

    session = None
    if args.session:
        import requests
        session = requests.Session()
        session.verify = verify_ssl
        session.auth_cookies = []

        if args.login_url and args.login_data:
            if not perform_login(session, args.login_url, args.login_data, verify_ssl, color, args.verbose):
                color.error("Authentification echouee, arret de l'analyse.")
                sys.exit(1)
            print()

    collector = CookieCollector(
        timeout=args.timeout,
        delay=args.delay,
        depth=args.depth,
        verbose=args.verbose,
        verify_ssl=verify_ssl
    )

    if session:
        collector.session = session

    analyzer = CookieAnalyzer()
    reporter = CookieReporter()

    all_results = []
    global_verification_status = {'verified': True, 'failed_urls': []}

    for url in urls:
        color.info(f"Analyse de {url}...")

        if args.depth > 0:
            results = collector.collect_multiple_urls([url], max_depth=args.depth)
        else:
            if args.session and session:
                result = collector.collect_from_url_with_session(url, session)
            else:
                result = collector.collect_from_url(url)
            results = [result]

        for result in results:
            if 'error' in result:
                color.error(f"Erreur sur {result.get('url', url)} : {result['error']}")
                continue

            cookies = result.get('cookies', [])
            final_url = result.get('final_url', url)

            context = {
                'is_https': urlparse(final_url).scheme == 'https',
                'force_check': args.force_https_context
            }

            verification = None
            if args.verify and not args.depth and cookies:
                color.info("Verification croisee des cookies...")
                verification = collector.verify_cookies_consistency(url, cookies)

                if verification['verified']:
                    color.success(
                        f"Verification reussie : "
                        f"{len(verification['matching_cookies'])}/{len(cookies)} cookies coherents"
                    )
                else:
                    color.warning(f"Cookies manquants: {verification['missing_cookies']}")
                    global_verification_status['verified'] = False
                    global_verification_status['failed_urls'].append(url)

                result['verification'] = verification

            analysis = analyzer.analyze_cookies(cookies, context, source_url=final_url)

            if args.verbose:
                color.success(f"{len(cookies)} cookie(s) trouve(s) sur {final_url}")

            if args.verbose and analysis['statistics'].get('insecure_count', 0) > 0:
                color.info(f"{analysis['statistics']['insecure_count']} cookie(s) non conformes")

            analyzer.print_analysis_summary(analysis, color=color)

            all_results.append({
                'url': url,
                'final_url': final_url,
                'result': result,
                'analysis': analysis,
                'verification': verification
            })

    if not all_results:
        color.error("Aucune analyse n'a pu etre realisee avec succes.")
        sys.exit(1)

    color.info("Generation du rapport global...")

    global_analysis = {
        'results': [],
        'statistics': {
            'total': 0,
            'secure_count': 0,
            'insecure_count': 0,
            'sensitive_count': 0,
            'risk_counts': {level: 0 for level in analyzer.RISK_LEVELS},
            # AJOUT :
            # Statistiques globales par catégorie de cookies.
            'category_counts': {}
        },
        'verification': global_verification_status if args.verify else None
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

        # AJOUT :
        # Agrégation des catégories renvoyées par analyzer.py.
        for category, count in stats.get('category_counts', {}).items():
            current = global_analysis['statistics']['category_counts'].get(category, 0)
            global_analysis['statistics']['category_counts'][category] = current + count

    security_score = analyzer.calculate_security_score(global_analysis['statistics'])
    global_analysis['statistics']['security_score'] = security_score

    formats = ['json', 'html', 'csv', 'md'] if args.format == 'all' else [args.format]

    generated_files = []
    for fmt in formats:
        filepath = reporter.generate_report(global_analysis, fmt, args.output)
        generated_files.append(filepath)
        color.success(f"Rapport {fmt.upper()} genere -> {filepath}")

    elapsed_time = time.time() - start_time
    color.print_footer(duration=elapsed_time, report_path=generated_files[0] if generated_files else None)

    if args.verify and not global_verification_status['verified']:
        color.warning(
            f"Verification croisee partiellement echouee pour: "
            f"{global_verification_status['failed_urls']}"
        )

    critical = global_analysis['statistics']['risk_counts'].get('CRITICAL', 0)
    high = global_analysis['statistics']['risk_counts'].get('HIGH', 0)
    medium = global_analysis['statistics']['risk_counts'].get('MEDIUM', 0)
    low = global_analysis['statistics']['risk_counts'].get('LOW', 0)
    score = global_analysis['statistics'].get('security_score', 100)

    # AJOUT :
    # Politique de sortie basée sur le score global.
    # Très utile dans un pipeline DevSecOps.
    if args.fail_score_below is not None and score < args.fail_score_below:
        color.error(
            f"Score de securite insuffisant : {score}/100 "
            f"(seuil requis : {args.fail_score_below}/100)"
        )
        sys.exit(2)

    # AJOUT :
    # Politique de sortie configurable par niveau de risque.
    # --fail-on none permet de générer un rapport sans faire échouer le pipeline.
    fail_on = args.fail_on.lower()

    if fail_on == 'none':
        color.success("Politique CI/CD desactivee (--fail-on none)")
        color.success(f"Score de securite final : {score}/100")
        sys.exit(0)

    should_fail = False
    exit_code = 0
    fail_message = ""

    if fail_on == 'critical' and critical > 0:
        should_fail = True
        exit_code = 2
        fail_message = f"{critical} cookie(s) avec risque CRITIQUE detecte(s)"

    elif fail_on == 'high' and (critical > 0 or high > 0):
        should_fail = True
        exit_code = 2 if critical > 0 else 1
        fail_message = (
            f"{critical} critique(s), {high} eleve(s) detecte(s)"
            if critical > 0 else
            f"{high} cookie(s) avec risque ELEVE detecte(s)"
        )

    elif fail_on == 'medium' and (critical > 0 or high > 0 or medium > 0):
        should_fail = True
        exit_code = 1
        fail_message = f"{critical} critique(s), {high} eleve(s), {medium} moyen(s) detecte(s)"

    elif fail_on == 'low' and (critical > 0 or high > 0 or medium > 0 or low > 0):
        should_fail = True
        exit_code = 1
        fail_message = (
            f"{critical} critique(s), {high} eleve(s), "
            f"{medium} moyen(s), {low} faible(s) detecte(s)"
        )

    if should_fail:
        color.error(f"Politique CI/CD non respectee (--fail-on {fail_on}) : {fail_message}")
        color.error(f"Score de securite final : {score}/100")
        sys.exit(exit_code)

    color.success("Politique CI/CD respectee")
    color.success(f"Score de securite final : {score}/100")
    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Analyse interrompue par l'utilisateur.")
        sys.exit(130)
    except Exception as e:
        print(f"\n[-] Erreur inattendue : {e}")
        sys.exit(3)
