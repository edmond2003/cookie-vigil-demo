import requests
from http.cookies import SimpleCookie
from typing import List, Dict, Set
from urllib.parse import urljoin
import time
import logging
import urllib3
from datetime import datetime
import re
import hashlib

from bs4 import BeautifulSoup
from .utils import normalize_url, extract_domain, is_same_domain

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


class CookieCollector:
    def __init__(self, timeout: int = 10, delay: float = 1.0,
                 depth: int = 0, verbose: bool = False,
                 verify_ssl: bool = True, max_cookies: int = 100):
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

    # MISE A JOUR :
    # Nouvelle fonction centralisée pour récupérer les en-têtes Set-Cookie.
    # Elle utilise response.raw.headers.getlist('Set-Cookie') quand c'est disponible,
    # car response.headers peut fusionner plusieurs Set-Cookie et perdre de l'information.
    def _get_set_cookie_headers(self, response: requests.Response) -> List[str]:
        try:
            raw_headers = getattr(response.raw, 'headers', None)
            if raw_headers and hasattr(raw_headers, 'getlist'):
                return list(raw_headers.getlist('Set-Cookie'))
        except Exception:
            pass

        # Fallback : utile si raw.headers n'est pas disponible.
        # Attention : ce fallback peut être moins fiable pour plusieurs Set-Cookie.
        header = response.headers.get('Set-Cookie')
        return [header] if header else []

    # MISE A JOUR :
    # Cette fonction extrait les cookies d'une réponse donnée.
    # Elle est utilisée pour la réponse finale ET pour chaque réponse de redirection.
    def _collect_cookies_from_response(
        self,
        response: requests.Response,
        start_time: datetime,
        auth_mode: bool = False
    ) -> List[Dict]:
        cookies_data = []
        cookie_strings = self._get_set_cookie_headers(response)

        for cookie_str in cookie_strings:
            if len(cookies_data) >= self.max_cookies:
                break

            parsed_cookies = self._parse_set_cookie(cookie_str)

            for cookie in parsed_cookies:
                if len(cookies_data) >= self.max_cookies:
                    break

                cookie['proof'] = {
                    'source_url': response.url,
                    'timestamp': start_time.isoformat(),
                    'response_status': response.status_code,
                    'tls_verified': self.verify_ssl and response.url.startswith('https://'),
                    'raw_header': cookie_str[:200] + "..." if len(cookie_str) > 200 else cookie_str,
                    # MISE A JOUR :
                    # Indique si le cookie provient d'une réponse intermédiaire de redirection.
                    'from_redirect': response.is_redirect or response.is_permanent_redirect
                }

                if auth_mode:
                    cookie['proof']['auth_mode'] = True

                cookies_data.append(cookie)

                if self.verbose:
                    redir = "redirect" if cookie['proof']['from_redirect'] else "final"
                    logger.info(f"Cookie Set-Cookie ({redir}): {cookie['name']} depuis {response.url}")

        return cookies_data

    # MISE A JOUR :
    # Cette fonction parcourt toute la chaîne HTTP :
    # - réponses de redirection : response.history
    # - réponse finale : response
    # Cela corrige le cas GitHub/Wikipedia/Google où des cookies sont posés avant l'URL finale.
    def _collect_cookies_from_response_chain(
        self,
        response: requests.Response,
        start_time: datetime,
        auth_mode: bool = False
    ) -> List[Dict]:
        cookies_data = []

        response_chain = list(response.history) + [response]

        for item in response_chain:
            if len(cookies_data) >= self.max_cookies:
                break

            extracted = self._collect_cookies_from_response(
                item,
                start_time=start_time,
                auth_mode=auth_mode
            )

            for cookie in extracted:
                if len(cookies_data) >= self.max_cookies:
                    break
                cookies_data.append(cookie)

        return cookies_data

    def collect_from_url(self, url: str) -> Dict:
        url = normalize_url(url)
        start_time = datetime.now()

        if self.verbose:
            logger.info(f"Collecte cookies pour {url}")

        session = self._create_session()

        try:
            response = session.get(
                url,
                timeout=self.timeout,
                allow_redirects=True,
                verify=self.verify_ssl
            )

            # MISE A JOUR :
            # Avant, seuls les Set-Cookie de la réponse finale étaient analysés.
            # Maintenant, on analyse aussi les Set-Cookie présents dans response.history.
            cookies_data = self._collect_cookies_from_response_chain(
                response,
                start_time=start_time,
                auth_mode=False
            )

            raw_headers_list = []
            for item in list(response.history) + [response]:
                raw_headers_list.extend(self._get_set_cookie_headers(item))

            if self.verbose:
                logger.info(f"{len(cookies_data)} cookie(s) collecté(s) sur la chaîne HTTP vers {response.url}")

            time.sleep(self.delay)

            return {
                'url': url,
                'final_url': response.url,
                'status_code': response.status_code,
                'cookies': cookies_data,
                'headers': dict(response.headers),
                'raw_set_cookie_headers': raw_headers_list,
                'redirect_chain': [r.url for r in response.history],
                'collection_timestamp': start_time.isoformat(),
                'collection_duration': (datetime.now() - start_time).total_seconds()
            }

        except Exception as e:
            logger.error(f"Erreur: {type(e).__name__}")
            return {
                'url': url,
                'error': str(e),
                'cookies': [],
                'collection_timestamp': start_time.isoformat()
            }

    def collect_from_url_with_session(self, url: str, session: requests.Session) -> Dict:
        url = normalize_url(url)
        start_time = datetime.now()

        if self.verbose:
            logger.info(f"Collecte avec session authentifiee pour {url}")

        try:
            response = session.get(
                url,
                timeout=self.timeout,
                allow_redirects=True,
                verify=self.verify_ssl
            )

            # MISE A JOUR :
            # Même en mode authentifié, on collecte les cookies de toute la chaîne de redirection.
            cookies_data = self._collect_cookies_from_response_chain(
                response,
                start_time=start_time,
                auth_mode=True
            )

            if hasattr(session, 'auth_cookies') and session.auth_cookies:
                for cookie in session.auth_cookies:
                    if not any(c['name'] == cookie['name'] for c in cookies_data):
                        cookie_copy = cookie.copy()
                        cookie_copy['proof'] = {
                            'source_url': url,
                            'timestamp': start_time.isoformat(),
                            'response_status': response.status_code,
                            'tls_verified': self.verify_ssl and url.startswith('https://'),
                            'raw_header': cookie.get('raw_header', 'cookie_from_authenticated_session'),
                            'auth_mode': True,
                            'from_redirect': False
                        }
                        cookie_copy['source'] = 'authenticated_session'
                        cookies_data.append(cookie_copy)

                        if self.verbose:
                            logger.info(f"Cookie authentifie ajoute: {cookie['name']}")

            raw_headers_list = []
            for item in list(response.history) + [response]:
                raw_headers_list.extend(self._get_set_cookie_headers(item))

            if self.verbose:
                logger.info(f"{len(cookies_data)} cookie(s) collecte(s) sur la chaîne HTTP vers {response.url}")

            time.sleep(self.delay)

            return {
                'url': url,
                'final_url': response.url,
                'status_code': response.status_code,
                'cookies': cookies_data,
                'headers': dict(response.headers),
                'raw_set_cookie_headers': raw_headers_list,
                'redirect_chain': [r.url for r in response.history],
                'collection_timestamp': start_time.isoformat(),
                'collection_duration': (datetime.now() - start_time).total_seconds(),
                'auth_mode': True
            }

        except Exception as e:
            logger.error(f"Erreur: {type(e).__name__}")
            return {'url': url, 'error': str(e), 'cookies': []}

    def verify_cookies_consistency(self, url: str, initial_cookies: List[Dict]) -> Dict:
        verification_result = {
            'verified': False,
            'missing_cookies': [],
            'new_cookies': [],
            'matching_cookies': [],
            'verification_timestamp': datetime.now().isoformat()
        }

        second_result = self.collect_from_url(url)
        second_cookies = second_result.get('cookies', [])

        initial_names = {c['name'] for c in initial_cookies}
        second_names = {c['name'] for c in second_cookies}

        verification_result['missing_cookies'] = list(initial_names - second_names)
        verification_result['new_cookies'] = list(second_names - initial_names)
        verification_result['matching_cookies'] = list(initial_names & second_names)
        verification_result['verified'] = len(verification_result['missing_cookies']) == 0

        if self.verbose:
            logger.info(
                f"Vérification croisée: "
                f"{len(verification_result['matching_cookies'])}/{len(initial_names)} cookies correspondants"
            )

        return verification_result

    def collect_multiple_urls(self, urls: List[str], max_depth: int = 0) -> List[Dict]:
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
        Utilise des regex pour détecter les attributs booléens sans être trompé
        par des noms de cookies contenant les sous-chaînes 'secure' ou 'httponly'.
        """
        if not cookie_str:
            return []

        cookies = []

        try:
            parsed = SimpleCookie()
            parsed.load(cookie_str)

            if self.verbose:
                print(f"[RAW HEADER] {cookie_str}")

            lower = cookie_str.lower()

            has_secure = bool(re.search(r'(?:^|;)\s*secure\s*(?:;|$)', lower))
            has_httponly = bool(re.search(r'(?:^|;)\s*httponly\s*(?:;|$)', lower))

            samesite_value = None
            match_ss = re.search(r'SameSite=([^;]+)', cookie_str, re.IGNORECASE)
            if match_ss:
                samesite_value = match_ss.group(1).strip()

            if self.verbose:
                logger.debug(f"Parsing Set-Cookie: {cookie_str[:100]}")
                logger.debug(f"secure={has_secure}, httponly={has_httponly}, samesite={samesite_value}")

            for name, morsel in parsed.items():
                raw_value = morsel.value or ""

                cookies.append({
                    'name': name,

                    # Valeur tronquée pour affichage dans les rapports.
                    'value': self._truncate_value(raw_value),

                    # Valeur complète réservée à l'analyse interne.
                    'raw_value_for_analysis': raw_value,

                    # Métadonnées utiles sans exposer directement le secret.
                    'value_length': len(raw_value),
                    'value_sha256': hashlib.sha256(raw_value.encode('utf-8')).hexdigest() if raw_value else None,

                    'attributes': {
                        'domain': morsel.get('domain') or None,
                        'path': morsel.get('path', '/'),
                        'expires': morsel.get('expires') or None,
                        'max-age': morsel.get('max-age') or None,
                        'secure': has_secure,
                        'httponly': has_httponly,
                        'samesite': samesite_value
                    },
                    'raw_header': cookie_str,
                    'source': 'set-cookie'
                })

        except Exception as e:
            logger.debug(f"Erreur parsing Set-Cookie: {e}")

        return cookies

    def _extract_links(self, url: str, max_links: int = 20) -> Set[str]:
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
    def _truncate_value(value: str, max_len: int = 200) -> str:
        """
        Tronque une valeur si elle dépasse max_len.
        La valeur complète est conservée séparément dans raw_value_for_analysis.
        """
        if not value:
            return ""

        s = str(value)
        return s[:max_len] + "..." if len(s) > max_len else s

    @staticmethod
    def _truncate_raw(raw: str, max_len: int = 120) -> str:
        if not raw:
            return ""

        return raw[:max_len] + "..." if len(raw) > max_len else raw
