from typing import Dict, List
from datetime import datetime
from .utils import ColorFormatter


class CookieAnalyzer:
    """
    Analyseur de sécurité des cookies basé sur les recommandations OWASP.

    MISE A JOUR :
    Le moteur ne se contente plus d'appliquer une sévérité fixe.
    La gravité d'une règle dépend maintenant du type de cookie :
    SESSION, AUTH, JWT, CSRF, TRACKING, FUNCTIONAL, etc.
    """

    RISK_LEVELS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

    RISK_PRIORITY = {
        'CRITICAL': 4,
        'HIGH': 3,
        'MEDIUM': 2,
        'LOW': 1,
        'INFO': 0
    }

    RISK_WEIGHTS = {
        'CRITICAL': 35,
        'HIGH': 20,
        'MEDIUM': 10,
        'LOW': 4,
        'INFO': 0
    }

    SENSITIVE_PATTERNS = [
        'session', 'sess', 'sid',
        'auth', 'authorization', 'token',
        'jwt', 'bearer',
        'login', 'logon', 'signin',
        'user', 'account', 'profile',
        'csrf', 'xsrf',
        'remember', 'persistent'
    ]

    RULES = [
        {
            'id': 'SECURE_MISSING',
            'name': 'Attribut Secure manquant',
            'description': 'Le cookie peut être transmis sur une connexion non chiffrée',
            'risk': 'CRITICAL',
            'recommendation': 'Ajouter l\'attribut "Secure" lorsque le cookie doit être limité au HTTPS'
        },
        {
            'id': 'HTTPONLY_MISSING',
            'name': 'Attribut HttpOnly manquant',
            'description': 'Le cookie est accessible via JavaScript',
            'risk': 'HIGH',
            'recommendation': 'Ajouter "HttpOnly" pour les cookies de session, d’authentification et autres cookies sensibles'
        },
        {
            'id': 'SAMESITE_MISSING',
            'name': 'Attribut SameSite manquant',
            'description': 'Protection insuffisante contre certains scénarios CSRF',
            'risk': 'MEDIUM',
            'recommendation': 'Ajouter "SameSite=Lax" ou "SameSite=Strict" selon le besoin métier'
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
            'description': 'Le cookie est envoyé à plusieurs sous-domaines',
            'risk': 'MEDIUM',
            'recommendation': 'Limiter le domaine du cookie au strict nécessaire'
        },
        {
            'id': 'PATH_TOO_BROAD',
            'name': 'Path trop large',
            'description': 'Le cookie est envoyé sur tout le site',
            'risk': 'LOW',
            'recommendation': 'Restreindre le path si le cookie n’est utile que sur une partie de l’application'
        },
        {
            'id': 'EXPIRES_LONG',
            'name': 'Durée de vie excessive',
            'description': 'Le cookie a une durée de vie longue (> 30 jours)',
            'risk': 'LOW',
            'recommendation': 'Réduire la durée de vie des cookies sensibles ou persistants'
        },
        {
            'id': 'PREFIX_SECURE_MISSING',
            'name': 'Préfixe __Secure- mal configuré',
            'description': 'Un cookie __Secure- doit obligatoirement avoir l’attribut Secure',
            'risk': 'HIGH',
            'recommendation': 'Ajouter l’attribut Secure'
        },
        {
            'id': 'PREFIX_HOST_MISSING',
            'name': 'Préfixe __Host- mal configuré',
            'description': '__Host- nécessite Secure + Path=/ + pas de Domain',
            'risk': 'HIGH',
            'recommendation': 'Respecter les contraintes du préfixe __Host-'
        },
        {
            'id': 'WEAK_TOKEN',
            'name': 'Token de session trop court ou prévisible',
            'description': 'Un token court ou prévisible est vulnérable au brute force',
            'risk': 'HIGH',
            'recommendation': 'Utiliser au minimum 128 bits d’entropie'
        },
        {
            'id': 'JWT_DETECTED',
            'name': 'Cookie contenant un JWT',
            'description': 'Un JWT a été détecté. Vérifiez sa signature et son algorithme.',
            'risk': 'INFO',
            'recommendation': 'Vérifier que l’algorithme n’est pas "none" et que la signature est valide'
        }
    ]

    @classmethod
    def is_sensitive_cookie(cls, cookie_name: str) -> bool:
        """Détermine si le nom du cookie évoque une donnée sensible."""
        if not cookie_name:
            return False
        name_lower = cookie_name.lower()
        return any(pattern in name_lower for pattern in cls.SENSITIVE_PATTERNS)

    @classmethod
    def classify_cookie(cls, cookie: Dict) -> str:
        """
        Classe le cookie selon son rôle probable.

        MISE A JOUR :
        Cette classification sert maintenant à adapter la sévérité des règles.
        Un cookie de session sans Secure est plus grave qu’un cookie de préférence UI sans Secure.
        """
        name = cookie.get('name', '').lower()
        value = cookie.get('raw_value_for_analysis', cookie.get('value', ''))

        if cls._looks_like_jwt(value) or 'jwt' in name:
            return 'JWT'

        if any(p in name for p in ['session', 'sess', 'sid', 'phpsessid', 'jsessionid']):
            return 'SESSION'

        if any(p in name for p in ['auth', 'authorization', 'bearer', 'login', 'signin']):
            return 'AUTH'

        if any(p in name for p in ['csrf', 'xsrf']):
            return 'CSRF'

        if any(p in name for p in ['ga', '_ga', '_gid', 'analytics', 'utm']):
            return 'ANALYTICS'

        if any(p in name for p in ['track', 'tracking', 'pixel', 'ad', 'ads', 'fbp', 'fbc']):
            return 'TRACKING'

        if any(p in name for p in ['remember', 'persistent']):
            return 'PERSISTENT_AUTH'

        if cls.is_sensitive_cookie(name):
            return 'SENSITIVE'

        return 'FUNCTIONAL'

    @classmethod
    def contextualize_issue(cls, rule: Dict, cookie: Dict, category: str) -> Dict:
        """
        MISE A JOUR :
        Adapte la sévérité et parfois la recommandation selon la catégorie du cookie.

        Objectif :
        éviter de classer automatiquement en CRITICAL des cookies non sensibles
        comme les cookies analytics, tracking ou fonctionnels.
        """
        issue = {
            'id': rule['id'],
            'name': rule['name'],
            'description': rule['description'],
            'risk': rule['risk'],
            'recommendation': rule['recommendation']
        }

        rule_id = rule['id']
        sensitive_categories = ['SESSION', 'AUTH', 'JWT', 'PERSISTENT_AUTH']
        moderately_sensitive_categories = ['SENSITIVE', 'CSRF']

        if rule_id == 'SECURE_MISSING':
            if category in sensitive_categories:
                issue['risk'] = 'CRITICAL'
                issue['recommendation'] = 'Ajouter Secure pour empêcher l’envoi du cookie sensible hors HTTPS'
            elif category in moderately_sensitive_categories:
                issue['risk'] = 'HIGH'
                issue['recommendation'] = 'Ajouter Secure si ce cookie contient ou protège une donnée sensible'
            else:
                issue['risk'] = 'LOW'
                issue['recommendation'] = 'Ajouter Secure si ce cookie doit être strictement limité aux échanges HTTPS'

        elif rule_id == 'HTTPONLY_MISSING':
            if category in sensitive_categories:
                issue['risk'] = 'HIGH'
                issue['recommendation'] = 'Ajouter HttpOnly pour limiter le vol du cookie via JavaScript en cas de XSS'
            elif category in moderately_sensitive_categories:
                issue['risk'] = 'MEDIUM'
                issue['recommendation'] = 'Ajouter HttpOnly si le cookie n’a pas besoin d’être lu côté client'
            else:
                issue['risk'] = 'INFO'
                issue['recommendation'] = 'HttpOnly est recommandé uniquement si le cookie ne doit pas être accessible à JavaScript'

        elif rule_id == 'SAMESITE_MISSING':
            if category in ['SESSION', 'AUTH', 'JWT', 'CSRF', 'PERSISTENT_AUTH']:
                issue['risk'] = 'MEDIUM'
                issue['recommendation'] = 'Définir SameSite=Lax ou SameSite=Strict pour réduire le risque CSRF'
            else:
                issue['risk'] = 'LOW'
                issue['recommendation'] = 'Définir SameSite=Lax lorsque cela ne casse pas le fonctionnement attendu'

        elif rule_id == 'DOMAIN_TOO_BROAD':
            if category in sensitive_categories:
                issue['risk'] = 'HIGH'
                issue['recommendation'] = 'Éviter de partager un cookie sensible avec tous les sous-domaines'
            elif category in moderately_sensitive_categories:
                issue['risk'] = 'MEDIUM'
                issue['recommendation'] = 'Limiter le domaine si le cookie a un rôle de sécurité ou contient une donnée utilisateur'
            else:
                issue['risk'] = 'LOW'
                issue['recommendation'] = 'Vérifier que le partage entre sous-domaines est volontaire et documenté'

        elif rule_id == 'PATH_TOO_BROAD':
            if category in sensitive_categories or category in moderately_sensitive_categories:
                issue['risk'] = 'LOW'
                issue['recommendation'] = 'Restreindre le Path si le cookie n’est utile que sur une zone précise'
            else:
                issue['risk'] = 'INFO'
                issue['recommendation'] = 'Path=/ est courant ; vérifier seulement si une portée plus stricte est possible'

        elif rule_id == 'EXPIRES_LONG':
            if category in ['SESSION', 'AUTH', 'JWT', 'PERSISTENT_AUTH', 'SENSITIVE']:
                issue['risk'] = 'MEDIUM'
                issue['recommendation'] = 'Réduire la durée de vie des cookies sensibles ou persistants'
            else:
                issue['risk'] = 'LOW'
                issue['recommendation'] = 'Vérifier que cette durée de vie longue est justifiée fonctionnellement'

        elif rule_id == 'SAMESITE_NONE_INSECURE':
            if category in sensitive_categories:
                issue['risk'] = 'CRITICAL'
            else:
                issue['risk'] = 'HIGH'

        return issue

    @classmethod
    def correlate_risks(cls, cookie: Dict, issues: List[Dict], category: str) -> List[Dict]:
        """
        Corrèle plusieurs problèmes pour produire une explication sécurité plus riche.
        """
        issue_ids = {issue.get('id') for issue in issues}
        correlations = []

        if category in ['SESSION', 'AUTH', 'JWT', 'PERSISTENT_AUTH']:
            if 'SECURE_MISSING' in issue_ids and 'HTTPONLY_MISSING' in issue_ids:
                correlations.append({
                    'id': 'SESSION_EXPOSURE_COMBINED',
                    'title': 'Cookie de session exposé',
                    'risk': 'CRITICAL',
                    'message': (
                        'Cookie sensible exposé : absence combinée de Secure et HttpOnly. '
                        'Le cookie peut être intercepté sur HTTP et lu par JavaScript en cas de XSS.'
                    ),
                    'impact': 'Vol ou détournement de session utilisateur',
                    'recommendation': 'Ajouter Secure et HttpOnly, puis vérifier SameSite'
                })

            if 'HTTPONLY_MISSING' in issue_ids and category == 'JWT':
                correlations.append({
                    'id': 'JWT_XSS_EXPOSURE',
                    'title': 'JWT exposé au JavaScript',
                    'risk': 'HIGH',
                    'message': (
                        'Un JWT stocké dans un cookie sans HttpOnly peut être récupéré '
                        'par document.cookie lors d’une attaque XSS.'
                    ),
                    'impact': 'Vol de jeton d’authentification',
                    'recommendation': 'Ajouter HttpOnly ou revoir le mode de stockage du JWT'
                })

        if 'SAMESITE_MISSING' in issue_ids and category in ['SESSION', 'AUTH', 'JWT', 'CSRF']:
            correlations.append({
                'id': 'CSRF_EXPOSURE',
                'title': 'Exposition potentielle CSRF',
                'risk': 'MEDIUM',
                'message': (
                    'Cookie sensible sans SameSite : le navigateur peut l’envoyer '
                    'dans un contexte intersite.'
                ),
                'impact': 'Risque de requêtes non autorisées au nom de l’utilisateur',
                'recommendation': 'Définir SameSite=Lax ou SameSite=Strict selon le besoin métier'
            })

        if 'DOMAIN_TOO_BROAD' in issue_ids and category in ['SESSION', 'AUTH', 'JWT']:
            correlations.append({
                'id': 'SUBDOMAIN_SESSION_EXPOSURE',
                'title': 'Session exposée aux sous-domaines',
                'risk': 'HIGH',
                'message': (
                    'Un cookie sensible avec un Domain trop large peut être partagé '
                    'avec plusieurs sous-domaines.'
                ),
                'impact': 'Compromission possible si un sous-domaine est vulnérable',
                'recommendation': 'Limiter le domaine du cookie au strict nécessaire'
            })

        return correlations

    @classmethod
    def analyze_cookie(cls, cookie: Dict, context: Dict = None, source_url: str = None) -> Dict:
        """Analyse un cookie avec règles unitaires + contextualisation + corrélations."""
        if context is None:
            context = {'is_https': True, 'force_check': False}

        cookie_name = cookie.get('name', '')
        is_sensitive = cls.is_sensitive_cookie(cookie_name)
        category = cls.classify_cookie(cookie)

        issues = []

        for rule in cls.RULES:
            try:
                check_method = getattr(cls, f"_check_{rule['id'].lower()}", None)
                if check_method and check_method(cookie, context):
                    # MISE A JOUR :
                    # On ne copie plus directement la sévérité fixe de RULES.
                    # On l'adapte au type de cookie.
                    issues.append(cls.contextualize_issue(rule, cookie, category))
            except Exception:
                continue

        max_risk = 'INFO'
        for issue in issues:
            if cls.RISK_PRIORITY.get(issue['risk'], 0) > cls.RISK_PRIORITY.get(max_risk, 0):
                max_risk = issue['risk']

        correlations = cls.correlate_risks(cookie, issues, category)

        for correlation in correlations:
            if cls.RISK_PRIORITY.get(correlation['risk'], 0) > cls.RISK_PRIORITY.get(max_risk, 0):
                max_risk = correlation['risk']

        result = {
            'cookie': cookie,
            'issues': issues,
            'correlations': correlations,
            'risk_level': max_risk,
            'is_secure': max_risk in ['INFO', 'LOW'],
            'compliance_level': 'COMPLIANT' if max_risk in ['INFO', 'LOW'] else 'NON_COMPLIANT',
            'is_sensitive': is_sensitive,
            'category': category
        }

        if source_url:
            result['source_url'] = source_url
            result['final_url'] = source_url

        return result

    @classmethod
    def analyze_cookies(cls, cookies: List[Dict], context: Dict = None, source_url: str = None) -> Dict:
        """Analyse une liste de cookies."""
        if context is None:
            context = {'is_https': True, 'force_check': False}

        results = [cls.analyze_cookie(cookie, context, source_url) for cookie in cookies]

        category_counts = {}
        for result in results:
            category = result.get('category', 'UNKNOWN')
            category_counts[category] = category_counts.get(category, 0) + 1

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
            },
            'category_counts': category_counts
        }

        return {'results': results, 'statistics': stats, 'context': context}

    @classmethod
    def calculate_security_score(cls, statistics: Dict) -> int:
        """Calcule un score de sécurité global pondéré."""
        total = max(statistics.get('total', 0), 1)
        risk_counts = statistics.get('risk_counts', {})

        penalty = 0
        for risk, count in risk_counts.items():
            penalty += cls.RISK_WEIGHTS.get(risk, 0) * count

        normalized_penalty = penalty / total
        score = 100 - normalized_penalty

        return max(0, min(100, round(score)))

    @classmethod
    def _check_secure_missing(cls, cookie: Dict, context: Dict) -> bool:
        attrs = cookie.get('attributes', {})
        is_https = context.get('is_https', False)
        force_check = context.get('force_check', False)
        if force_check:
            return not bool(attrs.get('secure', False))
        return is_https and not bool(attrs.get('secure', False))

    @classmethod
    def _check_httponly_missing(cls, cookie: Dict, context: Dict) -> bool:
        attrs = cookie.get('attributes', {})
        return not bool(attrs.get('httponly', False))

    @classmethod
    def _check_samesite_missing(cls, cookie: Dict, context: Dict) -> bool:
        attrs = cookie.get('attributes', {})
        samesite_raw = attrs.get('samesite')
        if samesite_raw is None:
            return True
        samesite = str(samesite_raw).lower().strip()
        return samesite in ('', 'null', 'undefined')

    @classmethod
    def _check_samesite_none_insecure(cls, cookie: Dict, context: Dict) -> bool:
        attrs = cookie.get('attributes', {})
        samesite_raw = attrs.get('samesite')
        if samesite_raw is None:
            return False
        samesite = str(samesite_raw).lower().strip()
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

    @classmethod
    def _check_weak_token(cls, cookie: Dict, context: Dict) -> bool:
        name = cookie.get('name', '').lower()
        value = cookie.get('raw_value_for_analysis', cookie.get('value', ''))

        if not cls.is_sensitive_cookie(name):
            return False

        excluded_patterns = ['username', 'user_name', 'email', 'userid', 'user_id']
        if any(p in name for p in excluded_patterns):
            return False

        if len(value) < 16:
            return True
        if value.isdigit() or value.isalpha():
            return True
        return False

    @classmethod
    def _check_jwt_detected(cls, cookie: Dict, context: Dict) -> bool:
        value = cookie.get('raw_value_for_analysis', cookie.get('value', ''))
        return cls._looks_like_jwt(value)

    @staticmethod
    def _looks_like_jwt(value: str) -> bool:
        parts = str(value).split('.')
        if len(parts) != 3:
            return False

        import base64
        import json

        try:
            header = parts[0]
            padding = '=' * (-len(header) % 4)
            header_json = json.loads(base64.urlsafe_b64decode(header + padding))
            return isinstance(header_json, dict)
        except Exception:
            return False

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
        """Affiche un résumé lisible en console."""
        if color is None:
            color = ColorFormatter(use_color=True)

        stats = analysis_result.get('statistics', {})

        print("\n" + "=" * 75)
        color.bold("RESUME DE L'ANALYSE DES COOKIES - OWASP")
        print("=" * 75)

        print(f"Total cookies analyses   : {stats.get('total', 0)}")
        print(f"Cookies securises        : {stats.get('secure_count', 0)}")
        print(f"Cookies non securises    : {stats.get('insecure_count', 0)}")

        sensitive_count = stats.get('sensitive_count', 0)
        if sensitive_count > 0:
            color.warning(f"Cookies SENSIBLES detectes : {sensitive_count}")

        category_counts = stats.get('category_counts', {})
        if category_counts:
            print("\nClassification des cookies :")
            for category, count in category_counts.items():
                print(f"   - {category:<16}: {count} cookie(s)")

        print("\nRepartition par niveau de risque :")
        for level in cls.RISK_LEVELS:
            count = stats.get('risk_counts', {}).get(level, 0)
            if count > 0:
                if level == 'CRITICAL':
                    color.error(f"   - {level:<9}: {count} cookie(s)")
                elif level == 'HIGH':
                    color.warning(f"   - {level:<9}: {count} cookie(s)")
                elif level == 'MEDIUM':
                    color.info(f"   - {level:<9}: {count} cookie(s)")
                else:
                    color.success(f"   - {level:<9}: {count} cookie(s)")

        print("\nDetails par cookie :")
        for result in analysis_result.get('results', []):
            cookie = result.get('cookie', {})
            risk = result.get('risk_level', 'INFO')
            name = cookie.get('name', 'unknown')
            is_sensitive = result.get('is_sensitive', False)
            category = result.get('category', 'UNKNOWN')
            source_url = result.get('source_url', '')

            if risk == 'CRITICAL':
                color.error(f"\n Cookie: {name} (Risque: {risk})")
            elif risk == 'HIGH':
                color.warning(f"\n Cookie: {name} (Risque: {risk})")
            elif risk == 'MEDIUM':
                color.info(f"\n Cookie: {name} (Risque: {risk})")
            else:
                color.success(f"\n Cookie: {name} (Risque: {risk})")

            print(f"   Categorie: {category}")

            if is_sensitive:
                color.warning("   [SENSIBLE] Ce cookie merite une attention particuliere")

            if source_url:
                print(f"   Source: {source_url}")

            for issue in result.get('issues', []):
                print(f"   - {issue['name']} ({issue['risk']})")
                print(f"     Solution: {issue['recommendation']}")

            for correlation in result.get('correlations', []):
                print(f"   [CORRELATION] {correlation['title']} ({correlation['risk']})")
                print(f"     Impact: {correlation['impact']}")
                print(f"     Solution: {correlation['recommendation']}")
