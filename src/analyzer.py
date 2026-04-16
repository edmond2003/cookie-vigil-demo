from typing import Dict, List, Optional
from datetime import datetime
from .utils import ColorFormatter


class CookieAnalyzer:
    """
    Analyseur de sécurité des cookies basé sur les recommandations OWASP.
    """

    # Liste ordonnée des niveaux de risque
    RISK_LEVELS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

    # Table de priorité
    RISK_PRIORITY = {
        'CRITICAL': 4,
        'HIGH': 3,
        'MEDIUM': 2,
        'LOW': 1,
        'INFO': 0
    }

    # Détection des cookies sensibles
    SENSITIVE_PATTERNS = [
        'session', 'sess', 'sid',
        'auth', 'authorization', 'token',
        'jwt', 'bearer',
        'login', 'logon', 'signin',
        'user', 'account', 'profile',
        'csrf', 'xsrf',
        'remember', 'persistent'
    ]

    # Matrice des règles OWASP (9 règles)
    RULES = [
        {
            'id': 'SECURE_MISSING',
            'name': 'Attribut Secure manquant',
            'description': 'Le cookie est transmis en clair sur les connexions HTTP',
            'risk': 'CRITICAL',
            'recommendation': 'Ajouter l\'attribut "Secure" sur tous les cookies sensibles'
        },
        {
            'id': 'HTTPONLY_MISSING',
            'name': 'Attribut HttpOnly manquant',
            'description': 'Le cookie est accessible via JavaScript (risque de vol par XSS)',
            'risk': 'HIGH',
            'recommendation': 'Ajouter "HttpOnly" pour les cookies de session et sensibles'
        },
        {
            'id': 'SAMESITE_MISSING',
            'name': 'Attribut SameSite manquant',
            'description': 'Protection insuffisante contre les attaques CSRF',
            'risk': 'MEDIUM',
            'recommendation': 'Ajouter "SameSite=Lax" (recommandé) ou "SameSite=Strict"'
        },
        {
            'id': 'SAMESITE_NONE_INSECURE',
            'name': 'SameSite=None sans Secure',
            'description': 'SameSite=None doit toujours être accompagné de Secure',
            'risk': 'CRITICAL',
            'recommendation': 'Ajouter "Secure" lorsque SameSite=None'
        },
        {
            'id': 'DOMAIN_TOO_BROAD',
            'name': 'Domaine trop large',
            'description': 'Le cookie est envoyé à tous les sous-domaines',
            'risk': 'MEDIUM',
            'recommendation': 'Spécifier un domaine précis sans le point initial (.)'
        },
        {
            'id': 'PATH_TOO_BROAD',
            'name': 'Path trop large',
            'description': 'Le cookie est envoyé sur tout le site',
            'risk': 'LOW',
            'recommendation': 'Restreindre le path à un répertoire spécifique'
        },
        {
            'id': 'EXPIRES_LONG',
            'name': 'Durée de vie excessive',
            'description': 'Le cookie a une durée de vie trop longue (> 30 jours)',
            'risk': 'LOW',
            'recommendation': 'Utiliser des durées courtes pour les cookies sensibles'
        },
        {
            'id': 'PREFIX_SECURE_MISSING',
            'name': 'Préfixe __Secure- mal configuré',
            'description': 'Un cookie __Secure- doit obligatoirement avoir l\'attribut Secure',
            'risk': 'HIGH',
            'recommendation': 'Ajouter l\'attribut Secure'
        },
        {
            'id': 'PREFIX_HOST_MISSING',
            'name': 'Préfixe __Host- mal configuré',
            'description': '__Host- nécessite Secure + Path=/ + pas de Domain',
            'risk': 'HIGH',
            'recommendation': 'Respecter les contraintes du préfixe __Host-'
        }
    ]

    @classmethod
    def is_sensitive_cookie(cls, cookie_name: str) -> bool:
        """Détermine si un cookie est sensible."""
        if not cookie_name:
            return False
        name_lower = cookie_name.lower()
        for pattern in cls.SENSITIVE_PATTERNS:
            if pattern in name_lower:
                return True
        return False

    @classmethod
    def analyze_cookie(cls, cookie: Dict, context: Dict = None, source_url: str = None) -> Dict:
        """Analyse un seul cookie."""
        if context is None:
            context = {'is_https': True}

        cookie_name = cookie.get('name', '')
        is_sensitive = cls.is_sensitive_cookie(cookie_name)

        issues = []

        for rule in cls.RULES:
            try:
                check_method = getattr(cls, f"_check_{rule['id'].lower()}", None)
                if check_method and check_method(cookie, context):
                    issues.append({
                        'id': rule['id'],
                        'name': rule['name'],
                        'description': rule['description'],
                        'risk': rule['risk'],
                        'recommendation': rule['recommendation']
                    })
            except Exception:
                continue

        max_risk = 'INFO'
        for issue in issues:
            if cls.RISK_PRIORITY.get(issue['risk'], 0) > cls.RISK_PRIORITY.get(max_risk, 0):
                max_risk = issue['risk']

        result = {
            'cookie': cookie,
            'issues': issues,
            'risk_level': max_risk,
            'is_secure': max_risk in ['INFO', 'LOW'],
            'compliance_level': 'COMPLIANT' if max_risk in ['INFO', 'LOW'] else 'NON_COMPLIANT',
            'is_sensitive': is_sensitive
        }

        if source_url:
            result['source_url'] = source_url
            result['final_url'] = source_url

        return result

    @classmethod
    def analyze_cookies(cls, cookies: List[Dict], context: Dict = None, source_url: str = None) -> Dict:
        """Analyse une liste de cookies."""
        if context is None:
            context = {'is_https': True}

        results = [cls.analyze_cookie(cookie, context, source_url) for cookie in cookies]

        stats = {
            'total': len(cookies),
            'secure_count': sum(1 for r in results if r['is_secure']),
            'insecure_count': sum(1 for r in results if not r['is_secure']),
            'sensitive_count': sum(1 for r in results if r.get('is_sensitive', False)),
            'risk_counts': {
                level: sum(1 for r in results if r['risk_level'] == level)
                for level in cls.RISK_LEVELS
            },
            'compliance_counts': {
                'COMPLIANT': sum(1 for r in results if r['compliance_level'] == 'COMPLIANT'),
                'NON_COMPLIANT': sum(1 for r in results if r['compliance_level'] == 'NON_COMPLIANT')
            }
        }

        return {'results': results, 'statistics': stats, 'context': context}

    # ==================== MÉTHODES DE VÉRIFICATION ====================

    @classmethod
    def _check_secure_missing(cls, cookie: Dict, context: Dict) -> bool:
        attrs = cookie.get('attributes', {})
        is_https = context.get('is_https', False)
        return is_https and not bool(attrs.get('secure', False))

    @classmethod
    def _check_httponly_missing(cls, cookie: Dict, context: Dict) -> bool:
        attrs = cookie.get('attributes', {})
        return not bool(attrs.get('httponly', False))

    @classmethod
    def _check_samesite_missing(cls, cookie: Dict, context: Dict) -> bool:
        attrs = cookie.get('attributes', {})
        samesite = str(attrs.get('samesite', '')).lower().strip()
        return samesite in ('', 'null', 'undefined')

    @classmethod
    def _check_samesite_none_insecure(cls, cookie: Dict, context: Dict) -> bool:
        attrs = cookie.get('attributes', {})
        samesite = str(attrs.get('samesite', '')).lower().strip()
        secure = bool(attrs.get('secure', False))
        return samesite == 'none' and not secure

    @classmethod
    def _check_domain_too_broad(cls, cookie: Dict, context: Dict) -> bool:
        domain = str(cookie.get('attributes', {}).get('domain', '')).strip()
        return domain.startswith('.')

    @classmethod
    def _check_path_too_broad(cls, cookie: Dict, context: Dict) -> bool:
        path = str(cookie.get('attributes', {}).get('path', '/')).strip()
        return path == '/'

    @classmethod
    def _check_expires_long(cls, cookie: Dict, context: Dict) -> bool:
        return cls._is_long_expiration(cookie.get('attributes', {}))

    @classmethod
    def _check_prefix_secure_missing(cls, cookie: Dict, context: Dict) -> bool:
        name = cookie.get('name', '')
        attrs = cookie.get('attributes', {})
        return name.startswith('__Secure-') and not bool(attrs.get('secure', False))

    @classmethod
    def _check_prefix_host_missing(cls, cookie: Dict, context: Dict) -> bool:
        name = cookie.get('name', '')
        attrs = cookie.get('attributes', {})
        if not name.startswith('__Host-'):
            return False
        return (not bool(attrs.get('secure', False)) or
                attrs.get('domain') is not None or
                str(attrs.get('path', '/')).strip() != '/')

    @staticmethod
    def _is_long_expiration(attributes: Dict) -> bool:
        max_age = attributes.get('max-age')
        if max_age:
            try:
                if int(max_age) > 2_592_000:
                    return True
            except (ValueError, TypeError):
                pass

        expires = attributes.get('expires')
        if expires:
            try:
                from email.utils import parsedate_to_datetime
                expire_date = parsedate_to_datetime(expires)
                if expire_date and (expire_date - datetime.now(expire_date.tzinfo)).days > 30:
                    return True
            except Exception:
                if any(y in str(expires) for y in ['203', '204', '205']):
                    return True
        return False

    @classmethod
    def print_analysis_summary(cls, analysis_result: Dict, color: ColorFormatter = None) -> None:
        """Affiche un résumé coloré."""
        if color is None:
            color = ColorFormatter(use_color=True)

        stats = analysis_result.get('statistics', {})

        print("\n" + "=" * 75)
        color.bold("📊 RÉSUMÉ DE L'ANALYSE DES COOKIES - OWASP")
        print("=" * 75)

        print(f"Total cookies analysés   : {stats.get('total', 0)}")
        print(f"Cookies sécurisés        : {stats.get('secure_count', 0)}")
        print(f"Cookies non sécurisés    : {stats.get('insecure_count', 0)}")
        print(f"🔐 Cookies sensibles     : {stats.get('sensitive_count', 0)}")

        print("\n📈 Répartition par niveau de risque :")
        for level in cls.RISK_LEVELS:
            count = stats.get('risk_counts', {}).get(level, 0)
            if count > 0:
                if level == 'CRITICAL':
                    color.error(f"   • {level:<9}: {count} cookie(s)")
                elif level == 'HIGH':
                    color.warning(f"   • {level:<9}: {count} cookie(s)")
                elif level == 'MEDIUM':
                    color.info(f"   • {level:<9}: {count} cookie(s)")
                else:
                    color.success(f"   • {level:<9}: {count} cookie(s)")

        print("\n🔍 DÉTAILS PAR COOKIE :")
        for result in analysis_result.get('results', []):
            cookie = result.get('cookie', {})
            risk = result.get('risk_level', 'INFO')
            name = cookie.get('name', 'unknown')
            is_sensitive = result.get('is_sensitive', False)

            if risk == 'CRITICAL':
                color.error(f"\n 🍪 {name} → Risque : {risk}")
            elif risk == 'HIGH':
                color.warning(f"\n 🍪 {name} → Risque : {risk}")
            elif risk == 'MEDIUM':
                color.info(f"\n 🍪 {name} → Risque : {risk}")
            else:
                color.success(f"\n 🍪 {name} → Risque : {risk}")

            if is_sensitive:
                color.warning(f"   🔐 COOKIE SENSIBLE")

            for issue in result.get('issues', []):
                print(f"   ⚠️  {issue['name']}")
                print(f"   💡 {issue['recommendation']}")
