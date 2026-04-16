import requests
from http.cookies import SimpleCookie
from typing import List, Dict, Optional, Set
from urllib.parse import urljoin, urlparse
import time
import logging
import urllib3

from bs4 import BeautifulSoup
from .utils import normalize_url, extract_domain, is_same_domain

# Désactiver les warnings SSL inutiles
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


class CookieCollector:
    """
    Collecteur de cookies à partir d'URLs web.
    Gère les requêtes HTTP, les redirections et un crawling basique contrôlé.
    """

    def __init__(self, timeout: int = 10, delay: float = 1.0,
                 depth: int = 0, verbose: bool = False,
                 verify_ssl: bool = True, max_cookies: int = 100):
        """
        Args:
            timeout: Timeout des requêtes
            delay: Délai entre les requêtes
            depth: Profondeur de crawling (0 = désactivé)
            verbose: Mode verbeux
            verify_ssl: Vérifier les certificats SSL (True par défaut)
            max_cookies: Nombre max de cookies par URL
        """
        self.timeout = timeout
        self.delay = delay
        self.depth = depth
        self.verbose = verbose
        self.verify_ssl = verify_ssl
        self.max_cookies = max_cookies

        self.user_agent = "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"

        if self.verbose:
            logger.setLevel(logging.DEBUG)

    def _create_session(self) -> requests.Session:
        """Crée une nouvelle session HTTP (propre, sans cookies persistants)."""
        session = requests.Session()
        session.headers.update({
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
        })
        session.verify = self.verify_ssl

        adapter = requests.adapters.HTTPAdapter(max_retries=2)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        
        return session

    def collect_from_url(self, url: str) -> Dict:
        """Collecte les cookies d'une seule URL avec une session propre."""
        url = normalize_url(url)
        if self.verbose:
            logger.info(f"Collecte cookies pour {url}")

        # Créer une nouvelle session pour cette URL
        session = self._create_session()

        try:
            response = session.get(
                url,
                timeout=self.timeout,
                allow_redirects=True,
                verify=self.verify_ssl
            )

            cookies_data = []

            # === 1. Extraction via en-têtes Set-Cookie ===
            cookie_strings = response.raw.headers.getlist('Set-Cookie')
            
            for cookie_str in cookie_strings:
                if len(cookies_data) >= self.max_cookies:
                    break
                # _parse_set_cookie retourne maintenant une LISTE
                parsed_cookies = self._parse_set_cookie(cookie_str)
                for cookie in parsed_cookies:
                    if len(cookies_data) >= self.max_cookies:
                        break
                    cookies_data.append(cookie)
                    if self.verbose:
                        logger.info(f"Cookie Set-Cookie: {cookie['name']}")

            # === 2. Extraction des cookies de la session (CORRIGÉ) ===
            for cookie in session.cookies:
                if len(cookies_data) >= self.max_cookies:
                    break
                if not any(c['name'] == cookie.name for c in cookies_data):
                    cookies_data.append({
                        'name': cookie.name,
                        'value': self._truncate_value(cookie.value),
                        'attributes': {
                            'domain': getattr(cookie, 'domain', None),
                            'path': getattr(cookie, 'path', '/'),
                            'secure': getattr(cookie, 'secure', False),
                            'httponly': getattr(cookie, 'httponly', False),
                            'samesite': getattr(cookie, 'samesite', None)
                        },
                        'source': 'session'
                    })
                    if self.verbose:
                        logger.info(f"Cookie session: {cookie.name}")

            if self.verbose:
                logger.info(f"{len(cookies_data)} cookie(s) collecté(s) sur {response.url}")

            time.sleep(self.delay)

            return {
                'url': url,
                'final_url': response.url,
                'status_code': response.status_code,
                'cookies': cookies_data,
                'headers': dict(response.headers),
                'redirect_chain': [r.url for r in response.history]
            }

        except requests.exceptions.SSLError as e:
            error_msg = f"Erreur SSL: {str(e)[:120]}"
            logger.warning(error_msg)
            return {'url': url, 'error': error_msg, 'cookies': []}
        except requests.exceptions.Timeout:
            logger.warning(f"Timeout pour {url}")
            return {'url': url, 'error': "Timeout", 'cookies': []}
        except requests.exceptions.ConnectionError as e:
            logger.warning(f"Erreur de connexion pour {url}: {str(e)[:100]}")
            return {'url': url, 'error': "Connection Error", 'cookies': []}
        except Exception as e:
            logger.error(f"Erreur inattendue pour {url}: {type(e).__name__}")
            return {'url': url, 'error': f"{type(e).__name__}: {str(e)[:100]}", 'cookies': []}

    def collect_multiple_urls(self, urls: List[str], max_depth: int = 0) -> List[Dict]:
        """Collecte les cookies sur plusieurs URLs avec crawling limité."""
        if max_depth <= 0:
            return [self.collect_from_url(u) for u in urls]

        results = []
        visited = set()
        total_cookies = 0
        max_total = 500

        for start_url in urls:
            if start_url in visited or total_cookies >= max_total:
                continue

            result = self.collect_from_url(start_url)
            results.append(result)
            visited.add(start_url)
            total_cookies += len(result.get('cookies', []))

            if max_depth > 0 and 'error' not in result:
                links = self._extract_links(result.get('final_url', start_url))
                for link in list(links)[:max_depth * 8]:
                    if link in visited or total_cookies >= max_total:
                        break
                    sub_result = self.collect_from_url(link)
                    results.append(sub_result)
                    visited.add(link)
                    total_cookies += len(sub_result.get('cookies', []))

        return results

    def _parse_set_cookie(self, cookie_str: str) -> List[Dict]:
        """
        Parse un en-tête Set-Cookie et retourne une liste de cookies.
        CORRIGÉ : retourne une liste (peut contenir plusieurs cookies).
        """
        if not cookie_str:
            return []

        cookies = []
        try:
            parsed = SimpleCookie()
            parsed.load(cookie_str)

            for name, morsel in parsed.items():
                cookies.append({
                    'name': name,
                    'value': self._truncate_value(morsel.value),
                    'attributes': {
                        'domain': morsel.get('domain'),
                        'path': morsel.get('path', '/'),
                        'expires': morsel.get('expires'),
                        'max-age': morsel.get('max-age'),
                        'secure': bool(morsel.get('secure')),
                        'httponly': bool(morsel.get('httponly')),
                        'samesite': morsel.get('samesite')
                    },
                    'raw': self._truncate_raw(cookie_str),
                    'source': 'set-cookie'
                })
        except Exception as e:
            logger.debug(f"Erreur parsing Set-Cookie: {e}")

        return cookies

    def _extract_links(self, url: str, max_links: int = 20) -> Set[str]:
        """Extrait les liens internes (crawling léger)."""
        links = set()
        session = self._create_session()
        
        try:
            response = session.get(url, timeout=self.timeout, verify=self.verify_ssl)
            response.raise_for_status()

            soup = BeautifulSoup(response.text, 'html.parser')
            base_domain = extract_domain(url)

            for a in soup.find_all('a', href=True):
                full_url = urljoin(url, a['href'])
                if is_same_domain(extract_domain(full_url), base_domain):
                    links.add(full_url)
                if len(links) >= max_links:
                    break
        except Exception:
            pass

        return links

    @staticmethod
    def _truncate_value(value: str, max_len: int = 60) -> str:
        if not value:
            return ""
        s = str(value)
        return s[:max_len] + "..." if len(s) > max_len else s

    @staticmethod
    def _truncate_raw(raw: str, max_len: int = 120) -> str:
        if not raw:
            return ""
        return raw[:max_len] + "..." if len(raw) > max_len else raw
