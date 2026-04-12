import requests
from http.cookies import SimpleCookie
from typing import List, Dict, Optional, Set
from urllib.parse import urljoin, urlparse
import time
import logging
from bs4 import BeautifulSoup
from .utils import normalize_url, extract_domain, is_same_domain
import urllib3

# Désactiver les warnings SSL (comme curl)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CookieCollector:
    """
    Collecteur de cookies à partir d'URLs web.
    Gère les requêtes HTTP, les redirections et le crawling basique.
    """
    
    def __init__(self, timeout: int = 10, user_agent: str = None, delay: float = 1.0):
        """
        Initialise le collecteur de cookies.
        
        Args:
            timeout: Délai maximum pour les requêtes (secondes)
            user_agent: User-Agent à utiliser
            delay: Délai entre les requêtes (pour respecter les serveurs)
        """
        self.timeout = timeout
        self.delay = delay
        self.user_agent = user_agent or "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0"
        
        # Créer une session avec des paramètres plus souples
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': self.user_agent})
        
        # Configuration pour être aussi tolérant que curl
        self.session.verify = False  # Ignorer la vérification SSL (comme curl)
        self.session.trust_env = False  # Ignorer les proxy system
        
        # Adapter aux en-têtes que curl envoie
        self.session.headers.update({
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        # Configuration des adapters pour gérer IPv4/IPv6
        self.session.mount('https://', requests.adapters.HTTPAdapter(max_retries=2))
        self.session.mount('http://', requests.adapters.HTTPAdapter(max_retries=2))
        
    def collect_from_url(self, url: str, follow_redirects: bool = True) -> Dict:
        """
        Collecte les cookies d'une seule URL.
        
        Args:
            url: URL à analyser
            follow_redirects: Suivre les redirections
            
        Returns:
            Dictionnaire contenant l'URL, les cookies et les métadonnées
        """
        url = normalize_url(url)
        logger.info(f"Analyse de {url}")
        
        # Liste des URLs à essayer (HTTPS puis HTTP)
        urls_to_try = [url]
        if url.startswith('https://'):
            urls_to_try.append(url.replace('https://', 'http://'))
        
        last_error = None
        
        for test_url in urls_to_try:
            try:
                logger.info(f"Tentative avec {test_url}")
                
                # Requête HTTP avec les mêmes options que curl
                response = self.session.get(
                    test_url, 
                    timeout=self.timeout,
                    allow_redirects=follow_redirects,
                    verify=False,  # Ignorer SSL
                    stream=True  # Pour éviter de télécharger tout le contenu
                )
                
                # Forcer la lecture des en-têtes sans télécharger tout le corps
                response.raw.read(1024)  # Lire juste le début
                
                logger.info(f"Statut: {response.status_code}")
                
                # Extraction des cookies depuis les en-têtes
                cookies_data = []
                
                # Méthode 1: Via les en-têtes Set-Cookie
                set_cookie_headers = response.raw.headers.getlist('Set-Cookie')
                if not set_cookie_headers and 'set-cookie' in response.headers:
                    set_cookie_headers = [response.headers['set-cookie']]
                
                for cookie_str in set_cookie_headers:
                    cookie = self._parse_set_cookie(cookie_str)
                    if cookie:
                        cookies_data.append(cookie)
                        logger.info(f"Cookie trouvé: {cookie['name']}")
                
                # Méthode 2: Via les cookies de session (JS accessible)
                for cookie_name, cookie in self.session.cookies.items():
                    # Vérifier si ce cookie n'a pas déjà été capturé via Set-Cookie
                    if not any(c['name'] == cookie_name for c in cookies_data):
                        cookies_data.append({
                            'name': cookie_name,
                            'value': cookie.value[:50] + "..." if len(cookie.value) > 50 else cookie.value,
                            'attributes': {
                                'domain': cookie.domain,
                                'path': cookie.path,
                                'secure': cookie.secure,
                                'httponly': getattr(cookie, 'httponly', False),
                                'samesite': getattr(cookie, 'samesite', None)
                            },
                            'source': 'session'
                        })
                        logger.info(f"Cookie session: {cookie_name}")
                
                result = {
                    'url': response.url,  # URL finale après redirections
                    'status_code': response.status_code,
                    'cookies': cookies_data,
                    'headers': dict(response.headers),
                    'final_url': response.url,
                    'redirect_chain': [r.url for r in response.history] if follow_redirects else []
                }
                
                # Petit délai pour respecter les serveurs
                time.sleep(self.delay)
                
                return result
                
            except requests.exceptions.SSLError as e:
                logger.warning(f"Erreur SSL pour {test_url}: {str(e)[:100]}")
                last_error = f"SSL Error: {str(e)[:100]}"
                continue
            except requests.exceptions.ConnectionError as e:
                logger.warning(f"Erreur de connexion pour {test_url}: {str(e)[:100]}")
                last_error = f"Connection Error: {str(e)[:100]}"
                continue
            except requests.exceptions.Timeout as e:
                logger.warning(f"Timeout pour {test_url}")
                last_error = "Timeout"
                continue
            except Exception as e:
                logger.warning(f"Erreur inattendue pour {test_url}: {type(e).__name__} - {str(e)[:100]}")
                last_error = f"{type(e).__name__}: {str(e)[:100]}"
                continue
        
        # Si toutes les tentatives ont échoué
        logger.error(f"Échec pour {url} après toutes les tentatives")
        return {'url': url, 'error': last_error or "Unknown error", 'cookies': []}
    
    def collect_multiple_urls(self, urls: List[str], max_depth: int = 0) -> List[Dict]:
        """Collecte les cookies de multiples URLs."""
        results = []
        visited = set()
        
        for url in urls:
            if url in visited:
                continue
                
            # Collecte sur l'URL principale
            result = self.collect_from_url(url)
            results.append(result)
            visited.add(url)
            
            # Crawling si demandé
            if max_depth > 0 and 'error' not in result and result.get('cookies'):
                internal_links = self._extract_links(result.get('final_url', url))
                for link in internal_links[:max_depth * 5]:  # Limiter le nombre
                    if link not in visited:
                        sub_result = self.collect_from_url(link)
                        results.append(sub_result)
                        visited.add(link)
        
        return results
    
    def _parse_set_cookie(self, cookie_str: str) -> Optional[Dict]:
        """Parse une chaîne Set-Cookie."""
        try:
            cookie = SimpleCookie()
            cookie.load(cookie_str)
            
            for key, morsel in cookie.items():
                attributes = {}
                
                # Attributs standards
                for attr in ['domain', 'path', 'expires', 'max-age', 'secure', 'httponly', 'samesite']:
                    if attr in morsel:
                        attributes[attr] = morsel[attr]
                    elif hasattr(morsel, attr):
                        attributes[attr] = getattr(morsel, attr)
                
                # Normalisation des attributs booléens
                attributes['secure'] = attributes.get('secure', False) in [True, 'True', 'true']
                attributes['httponly'] = attributes.get('httponly', False) in [True, 'True', 'true']
                
                return {
                    'name': key,
                    'value': morsel.value[:50] + "..." if len(morsel.value) > 50 else morsel.value,
                    'attributes': attributes,
                    'raw': cookie_str[:100] + "..." if len(cookie_str) > 100 else cookie_str,
                    'source': 'set-cookie'
                }
        except Exception as e:
            logger.debug(f"Erreur parsing cookie: {str(e)[:50]}")
            return None
    
    def _extract_links(self, url: str, max_links: int = 10) -> Set[str]:
        """Extrait les liens internes d'une page."""
        links = set()
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            base_domain = extract_domain(url)
            
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                full_url = urljoin(url, href)
                
                if is_same_domain(extract_domain(full_url), base_domain):
                    links.add(full_url)
                    
                if len(links) >= max_links:
                    break
                    
        except Exception as e:
            logger.debug(f"Erreur extraction liens: {str(e)[:50]}")
            
        return links
