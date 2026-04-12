from typing import Dict, List, Tuple, Any
import re
from .utils import ColorFormatter

class CookieAnalyzer:
    """
    Analyseur de sécurité des cookies basé sur les recommandations OWASP.
    """
    
    # Niveaux de risque
    RISK_LEVELS = {
        'CRITICAL': 4,
        'HIGH': 3,
        'MEDIUM': 2,
        'LOW': 1,
        'INFO': 0
    }
    
    # Matrice des règles de sécurité OWASP
    RULES = [
        {
            'id': 'SECURE_MISSING',
            'name': 'Attribut Secure manquant',
            'description': 'Le cookie peut être transmis en clair sur HTTP',
            'condition': lambda c, ctx: not c.get('attributes', {}).get('secure', False) and ctx.get('is_https', True),
            'risk': 'CRITICAL',
            'recommendation': 'Ajouter l\'attribut "Secure" pour forcer la transmission uniquement en HTTPS'
        },
        {
            'id': 'HTTPONLY_MISSING',
            'name': 'Attribut HttpOnly manquant',
            'description': 'Le cookie est accessible via JavaScript (risque XSS)',
            'condition': lambda c, ctx: not c.get('attributes', {}).get('httponly', False),
            'risk': 'HIGH',
            'recommendation': 'Ajouter l\'attribut "HttpOnly" pour empêcher l\'accès JavaScript'
        },
        {
            'id': 'SAMESITE_MISSING',
            'name': 'Attribut SameSite manquant',
            'description': 'Protection CSRF insuffisante',
            'condition': lambda c, ctx: not c.get('attributes', {}).get('samesite', None),
            'risk': 'MEDIUM',
            'recommendation': 'Ajouter "SameSite=Lax" ou "SameSite=Strict" selon le besoin'
        },
        {
            'id': 'SAMESITE_NONE_INSECURE',
            'name': 'SameSite=None sans Secure',
            'description': 'SameSite=None doit être accompagné de Secure',
            'condition': lambda c, ctx: c.get('attributes', {}).get('samesite', '').lower() == 'none' and not c.get('attributes', {}).get('secure', False),
            'risk': 'CRITICAL',
            'recommendation': 'Ajouter "Secure" avec "SameSite=None" ou utiliser Lax/Strict'
        },
        {
            'id': 'DOMAIN_TOO_BROAD',
            'name': 'Domaine trop large',
            'description': 'Le cookie est envoyé à tous les sous-domaines',
            'condition': lambda c, ctx: c.get('attributes', {}).get('domain', '').startswith('.'),
            'risk': 'MEDIUM',
            'recommendation': 'Limiter le domaine au minimum nécessaire, éviter les domaines commençant par "."'
        },
        {
            'id': 'PATH_TOO_BROAD',
            'name': 'Path trop large',
            'description': 'Le cookie est envoyé sur tout le site',
            'condition': lambda c, ctx: c.get('attributes', {}).get('path', '/') == '/',
            'risk': 'LOW',
            'recommendation': 'Restreindre le path au strict nécessaire'
        },
        {
            'id': 'EXPIRES_LONG',
            'name': 'Expiration longue',
            'description': 'Cookie avec une durée de vie excessive',
            'condition': lambda c, ctx: self._is_long_expiration(c.get('attributes', {})),
            'risk': 'LOW',
            'recommendation': 'Utiliser des sessions ou des durées de vie courtes'
        },
        {
            'id': 'PREFIX_SECURE_MISSING',
            'name': 'Préfixe __Secure- manquant',
            'description': 'Cookie sécuritaire sans le préfixe recommandé',
            'condition': lambda c, ctx: c.get('name', '').startswith('__Secure-') and not c.get('attributes', {}).get('secure', False),
            'risk': 'HIGH',
            'recommendation': 'Les cookies avec préfixe __Secure- doivent avoir Secure=true'
        },
        {
            'id': 'PREFIX_HOST_MISSING',
            'name': 'Préfixe __Host- mal configuré',
            'description': 'Cookie __Host- sans les attributs requis',
            'condition': lambda c, ctx: c.get('name', '').startswith('__Host-') and 
                                      (not c.get('attributes', {}).get('secure', False) or 
                                       c.get('attributes', {}).get('domain') or 
                                       c.get('attributes', {}).get('path') != '/'),
            'risk': 'HIGH',
            'recommendation': '__Host- nécessite Secure=true, pas de domaine, et path=/'
        }
    ]
    
    @classmethod
    def analyze_cookie(cls, cookie: Dict, context: Dict = None) -> Dict:
        """
        Analyse un cookie individuel selon les règles OWASP.
        
        Args:
            cookie: Dictionnaire représentant le cookie
            context: Contexte de l'analyse (ex: is_https)
            
        Returns:
            Résultat d'analyse avec risques et recommandations
        """
        if context is None:
            context = {'is_https': True}
        
        issues = []
        
        for rule in cls.RULES:
            try:
                if rule['condition'](cookie, context):
                    issues.append({
                        'id': rule['id'],
                        'name': rule['name'],
                        'description': rule['description'],
                        'risk': rule['risk'],
                        'recommendation': rule['recommendation']
                    })
            except Exception as e:
                # Ignorer les erreurs de condition
                continue
        
        # Déterminer le niveau de risque maximum
        max_risk = 'INFO'
        for issue in issues:
            if cls.RISK_LEVELS.get(issue['risk'], 0) > cls.RISK_LEVELS.get(max_risk, 0):
                max_risk = issue['risk']
        
        return {
            'cookie': cookie,
            'issues': issues,
            'risk_level': max_risk,
            'is_secure': len(issues) == 0
        }
    
    @classmethod
    def analyze_cookies(cls, cookies: List[Dict], context: Dict = None) -> Dict:
        """
        Analyse une liste de cookies.
        
        Args:
            cookies: Liste des cookies à analyser
            context: Contexte global
            
        Returns:
            Résultats d'analyse globaux
        """
        if context is None:
            context = {'is_https': True}
        
        results = []
        for cookie in cookies:
            result = cls.analyze_cookie(cookie, context)
            results.append(result)
        
        # Statistiques globales
        stats = {
            'total': len(cookies),
            'secure_count': sum(1 for r in results if r['is_secure']),
            'insecure_count': sum(1 for r in results if not r['is_secure']),
            'risk_counts': {
                level: sum(1 for r in results if r['risk_level'] == level)
                for level in cls.RISK_LEVELS.keys()
            }
        }
        
        return {
            'results': results,
            'statistics': stats,
            'context': context
        }
    
    @staticmethod
    def _is_long_expiration(attributes: Dict) -> bool:
        """
        Vérifie si un cookie a une expiration trop longue (> 30 jours).
        """
        # Vérifier max-age
        max_age = attributes.get('max-age')
        if max_age:
            try:
                if int(max_age) > 2592000:  # 30 jours en secondes
                    return True
            except:
                pass
        
        # Vérifier expires
        expires = attributes.get('expires')
        if expires and '203' in expires:  # Approximation grossière
            return True
            
        return False
    
    @classmethod
    def print_analysis_summary(cls, analysis_result: Dict) -> None:
        """
        Affiche un résumé coloré de l'analyse.
        
        Args:
            analysis_result: Résultat de l'analyse
        """
        stats = analysis_result['statistics']
        
        print("\n" + "="*60)
        print("📊 RÉSUMÉ DE L'ANALYSE DES COOKIES")
        print("="*60)
        print(f"Total cookies analysés : {stats['total']}")
        print(f"Cookies sécurisés : {stats['secure_count']}")
        print(f"Cookies non sécurisés : {stats['insecure_count']}")
        
        print("\n📈 Répartition par niveau de risque :")
        for level in cls.RISK_LEVELS:
            count = stats['risk_counts'].get(level, 0)
            if count > 0:
                colored_text = ColorFormatter.colorize(f"  {level}: {count}", level)
                print(colored_text)
        
        print("\n🔍 DÉTAILS PAR COOKIE :")
        for result in analysis_result['results']:
            cookie = result['cookie']
            risk = result['risk_level']
            
            cookie_info = f"\n  🍪 {cookie['name']} ({risk})"
            print(ColorFormatter.colorize(cookie_info, risk))
            
            for issue in result['issues']:
                print(f"    ⚠️  {issue['name']}")
                print(f"       💡 {issue['recommendation']}")
