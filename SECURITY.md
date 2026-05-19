
**SECURITY.md**
```markdown
# Politique De Sécurité

## Périmètre

CookieVigil est un outil académique et DevSecOps destiné à l’audit automatisé de la configuration des cookies web.

Le projet comprend :

- l’outil d’audit CookieVigil ;
- une application Flask volontairement vulnérable pour les démonstrations ;
- des exemples d’intégration Docker et CI/CD ;
- des rapports générés à partir des analyses.

L’application vulnérable incluse dans le projet est intentionnellement non sécurisée. Elle doit être utilisée uniquement dans un environnement de laboratoire contrôlé.

## Utilisation Autorisée

CookieVigil doit être utilisé uniquement sur :

- des applications que vous possédez ;
- des environnements de test ou de laboratoire ;
- des systèmes pour lesquels vous disposez d’une autorisation explicite ;
- des cibles prévues dans un cadre pédagogique ou professionnel autorisé.

L’utilisation de cet outil contre des systèmes tiers sans autorisation peut être illégale.

## Données Sensibles

CookieVigil analyse des en-têtes HTTP `Set-Cookie`. Ces en-têtes peuvent contenir des informations sensibles ou des identifiants de session.

Pour limiter les risques :

- les valeurs des cookies sont tronquées dans les rapports ;
- les valeurs complètes sont réservées à l’analyse interne ;
- des métadonnées comme la longueur et le hash SHA-256 peuvent être générées ;
- les rapports doivent être considérés comme des artefacts sensibles.

Il est déconseillé de publier publiquement des rapports générés sur de vraies applications.

## Gestion Des Secrets

Ne stockez jamais dans le dépôt :

- des identifiants réels ;
- des mots de passe ;
- des tokens d’accès ;
- des cookies de session réels ;
- des rapports contenant des données sensibles ;
- des fichiers `.env` contenant des secrets.

Les identifiants utilisés dans les démonstrations doivent être des comptes de test.

## Rapports Générés

Les rapports produits par CookieVigil peuvent contenir :

- des noms de cookies ;
- des attributs de sécurité ;
- des URLs sources ;
- des en-têtes `Set-Cookie` tronqués ;
- des hashes de valeurs ;
- des horodatages de collecte.

Ces rapports doivent être stockés avec précaution, surtout lorsqu’ils proviennent d’environnements réels.

## Sécurité De L’Outil

CookieVigil applique plusieurs mesures pour réduire l’exposition des données :

- troncature des valeurs de cookies dans les sorties ;
- conservation de la valeur complète uniquement pour certaines analyses internes ;
- génération de hash SHA-256 pour identifier une valeur sans l’afficher directement ;
- possibilité de désactiver l’échec CI/CD avec `--fail-on none` dans un contexte de démonstration ;
- possibilité de contrôler les seuils avec `--fail-on` et `--fail-score-below`.

## Utilisation En CI/CD

Lorsqu’il est intégré dans une chaîne DevSecOps, CookieVigil peut faire échouer un pipeline si une politique de sécurité n’est pas respectée.

Exemple :

```bash
python audit_cookies.py https://example.com --format all --fail-on high
Ou avec un score minimal :

python audit_cookies.py https://example.com --fail-score-below 70
Les rapports générés dans le pipeline doivent être traités comme des artefacts potentiellement sensibles.

Application Vulnérable
Le dossier vulnerable_app/ contient une application volontairement vulnérable.

Elle sert uniquement à démontrer :

l’absence de Secure ;
l’absence de HttpOnly ;
l’absence de SameSite ;
les tokens faibles ;
les cookies contenant des JWT ;
les cookies à durée de vie excessive ;
les scénarios d’authentification.
Cette application ne doit jamais être exposée sur Internet.

Signalement D’Une Vulnérabilité
Si vous identifiez une vulnérabilité dans CookieVigil lui-même, il est recommandé de la signaler de manière responsable au mainteneur du projet.

Le signalement doit idéalement contenir :

une description claire du problème ;
les étapes de reproduction ;
l’impact potentiel ;
la version ou le commit concerné ;
une proposition de correction si possible.
Limites De Sécurité
CookieVigil fournit une analyse automatisée basée sur les cookies observés dans les réponses HTTP.

Il ne remplace pas :

un audit complet d’application web ;
un test d’intrusion ;
une analyse de code source ;
une analyse dynamique dans un navigateur ;
Burp Suite ;
OWASP ZAP ;
une expertise humaine.
Les résultats doivent être interprétés selon le contexte technique et métier de l’application.
