# Politique De Sécurité

## Objectif

Ce document décrit les règles de sécurité liées à l’utilisation, au développement et à la publication de CookieVigil.

CookieVigil est un outil d’audit automatisé de la sécurité des cookies web. Il peut manipuler des métadonnées sensibles, notamment des noms de cookies, des attributs de sécurité et des extraits d’en-têtes HTTP `Set-Cookie`.

L’objectif de cette politique est de réduire les risques liés à l’utilisation de l’outil et de préciser les bonnes pratiques à respecter.

## Périmètre

Le projet comprend :

- l’outil d’audit CookieVigil ;
- les modules Python de collecte, d’analyse et de génération de rapports ;
- une application Flask volontairement vulnérable utilisée pour les démonstrations ;
- des fichiers Docker pour reproduire l’environnement de test ;
- un workflow CI/CD GitHub Actions ;
- des rapports générés lors des analyses.

L’application vulnérable incluse dans le dossier `vulnerable_app/` est intentionnellement non sécurisée. Elle doit être utilisée uniquement dans un environnement de laboratoire contrôlé.

## Utilisation Autorisée

CookieVigil doit être utilisé uniquement sur :

- des applications que vous possédez ;
- des environnements de test ;
- des environnements de laboratoire ;
- des applications de staging ou de préproduction autorisées ;
- des systèmes pour lesquels vous disposez d’une autorisation explicite.

L’utilisation de CookieVigil contre des systèmes tiers sans autorisation peut être illégale.

## Usage Interdit

Il est interdit d’utiliser CookieVigil pour :

- scanner des applications sans autorisation ;
- collecter des cookies de session réels appartenant à des tiers ;
- contourner des mécanismes de sécurité sans cadre légal ;
- publier des rapports contenant des données sensibles ;
- exposer l’application vulnérable sur Internet ;
- intégrer de vrais identifiants dans des scripts, logs ou pipelines publics.

## Données Manipulées

CookieVigil peut traiter les informations suivantes :

- noms de cookies ;
- valeurs de cookies tronquées ;
- attributs `Secure`, `HttpOnly`, `SameSite`, `Domain`, `Path`, `Expires`, `Max-Age` ;
- en-têtes HTTP `Set-Cookie` tronqués ;
- URLs sources ;
- codes de statut HTTP ;
- horodatages de collecte ;
- longueur des valeurs de cookies ;
- hash SHA-256 des valeurs de cookies ;
- catégories de cookies ;
- niveaux de risque ;
- recommandations de sécurité.

## Protection Des Valeurs De Cookies

Pour limiter l’exposition des secrets :

- les valeurs complètes ne sont pas destinées à être affichées dans les rapports ;
- les valeurs affichées sont tronquées ;
- la valeur complète peut être conservée temporairement en mémoire pour certaines analyses internes ;
- un hash SHA-256 peut être généré pour identifier une valeur sans l’exposer directement ;
- les rapports doivent être traités comme des artefacts sensibles.

Même tronqués, certains en-têtes peuvent révéler des informations utiles à un attaquant. Les rapports ne doivent donc pas être publiés sans revue préalable.

## Rapports Générés

Les rapports peuvent être générés en plusieurs formats :

```text
JSON
HTML
CSV
Markdown

Ces rapports peuvent contenir :

des noms de cookies ;
des URLs internes ;
des informations sur l’architecture applicative ;
des en-têtes Set-Cookie tronqués ;
des recommandations de correction ;
des niveaux de risque ;
des hashes de valeurs.
Recommandations :

ne pas publier les rapports générés sur des applications réelles ;
ne pas les envoyer sur des canaux non sécurisés ;
limiter leur accès aux personnes autorisées ;
supprimer les rapports obsolètes ;
ne pas les versionner dans Git sauf s’ils sont anonymisés.
Gestion Des Secrets
Ne stockez jamais dans le dépôt :

mots de passe ;
tokens d’accès ;
cookies de session réels ;
clés privées ;
certificats privés ;
fichiers .env contenant des secrets ;
rapports contenant des données sensibles ;
captures contenant des cookies actifs.
Les identifiants utilisés dans les démonstrations doivent être des comptes de test.

Authentification Et Option --login-data
CookieVigil prend en charge une authentification simple par requête POST avec l’option :

--login-data "username=admin&password=admin123"
Précautions :

utilisez uniquement des comptes de test ;
évitez d’utiliser de vrais mots de passe ;
évitez de conserver ces commandes dans l’historique shell ;
n’affichez pas les identifiants dans les captures d’écran ;
n’utilisez pas de secrets réels dans GitHub Actions ou GitLab CI sans gestionnaire de secrets.
Dans un pipeline CI/CD, utilisez les mécanismes de secrets fournis par la plateforme.

Sécurité De L’Exécution Docker
CookieVigil peut être exécuté dans un conteneur Docker.

Avantages :

isolation de l’environnement d’exécution ;
reproductibilité ;
absence de dépendances Python à installer sur l’hôte ;
meilleure intégration dans les pipelines CI/CD ;
réduction des conflits de versions.
Le conteneur CookieVigil est conçu pour s’exécuter avec un utilisateur non-root afin de limiter l’impact d’une éventuelle compromission.

Le dossier reports/ peut être monté comme volume. Si l’utilisateur non-root du conteneur ne peut pas écrire dans ce dossier, corrigez les permissions :

sudo chown -R 1000:1000 reports
chmod -R u+rwX reports
Application Vulnérable
Le dossier vulnerable_app/ contient une application Flask volontairement vulnérable.

Elle sert à démontrer :

l’absence de Secure ;
l’absence de HttpOnly ;
l’absence de SameSite ;
les tokens faibles ;
les cookies contenant des JWT ;
les cookies à durée de vie excessive ;
les cookies générés après authentification.
Cette application :

ne doit pas être exposée sur Internet ;
ne doit pas être utilisée en production ;
ne doit pas contenir de vrais utilisateurs ;
ne doit pas contenir de secrets réels ;
doit rester confinée à un environnement local, Docker ou laboratoire.
Utilisation En CI/CD
CookieVigil peut être intégré dans une chaîne DevSecOps.

Exemple :

python audit_cookies.py https://example.com --format all --fail-on high
Ou avec un score minimal :

python audit_cookies.py https://example.com --format all --fail-score-below 70
Lorsque l’outil est utilisé dans un pipeline :

les rapports doivent être traités comme des artefacts sensibles ;
les secrets doivent être gérés par la plateforme CI/CD ;
les cibles doivent être des environnements autorisés ;
les seuils de blocage doivent être adaptés à la politique de sécurité du projet.
Politique De Blocage
CookieVigil peut retourner un code de sortie non nul selon :

le niveau de risque détecté avec --fail-on ;
le score global avec --fail-score-below.
Exemples :

python audit_cookies.py https://example.com --fail-on critical
python audit_cookies.py https://example.com --fail-on high
python audit_cookies.py https://example.com --fail-score-below 70
L’option suivante désactive le blocage et convient aux démonstrations :

python audit_cookies.py https://example.com --fail-on none
Bonnes Pratiques Pour Les Développeurs
Lors du développement de CookieVigil :

ne pas journaliser les valeurs complètes des cookies ;
éviter d’ajouter des dépendances inutiles ;
maintenir les dépendances à jour ;
exécuter les tests avant chaque commit ;
éviter les fichiers générés dans le dépôt ;
ne pas versionner venv/, __pycache__/, reports/ ou cookies.db ;
vérifier les permissions des fichiers Docker ;
privilégier l’exécution non-root dans les conteneurs.
Commande recommandée avant commit :

python -m unittest discover -s tests -p "test_*.py" -v
git status
Bonnes Pratiques Pour Les Utilisateurs
Lors de l’utilisation de CookieVigil :

obtenez une autorisation avant tout audit ;
utilisez des comptes de test ;
stockez les rapports dans un emplacement protégé ;
supprimez les rapports qui ne sont plus nécessaires ;
évitez de partager les rapports bruts ;
interprétez les résultats selon le contexte applicatif ;
complétez l’analyse avec des outils comme Burp Suite ou OWASP ZAP si nécessaire.
Limites De Sécurité
CookieVigil fournit une analyse automatisée basée principalement sur les cookies observés dans les réponses HTTP.

Il ne remplace pas :

un audit complet d’application web ;
un test d’intrusion ;
une analyse de code source ;
une analyse dynamique dans un navigateur ;
Burp Suite ;
OWASP ZAP ;
une expertise humaine.
Limites actuelles :

l’outil n’exécute pas encore le JavaScript côté client ;
il ne simule pas un navigateur complet ;
il ne détecte pas tous les cookies créés dynamiquement par scripts ;
il ne valide pas la logique métier de l’application ;
il ne prouve pas automatiquement l’exploitabilité de chaque risque.
Perspectives De Sécurité
Des améliorations futures peuvent renforcer la sécurité et la couverture de l’outil :

intégration d’un navigateur headless comme Playwright ;
support des cookies créés côté client ;
configuration des règles via fichier de politique ;
export SARIF pour GitHub Security ;
signature ou horodatage des rapports ;
intégration avec un coffre de secrets pour les scans authentifiés.
Signalement D’Une Vulnérabilité
Si vous identifiez une vulnérabilité dans CookieVigil lui-même, signalez-la de manière responsable au mainteneur du projet.

Un bon signalement doit contenir :

une description claire du problème ;
les étapes de reproduction ;
l’impact potentiel ;
la version ou le commit concerné ;
les logs utiles si disponibles ;
une proposition de correction si possible.
Ne publiez pas publiquement une vulnérabilité avant qu’une correction ou une mesure d’atténuation ne soit disponible.

Clause De Responsabilité
CookieVigil est fourni dans un objectif pédagogique, académique et DevSecOps.

L’utilisateur est responsable :

du choix des cibles analysées ;
de l’obtention des autorisations nécessaires ;
de la protection des rapports générés ;
de l’interprétation des résultats ;
du respect des lois et règles applicables.
L’auteur du projet ne peut être tenu responsable d’un usage non autorisé ou malveillant de l’outil.


Après remplacement :

```bash
git add SECURITY.md
git commit -m "Rewrite security policy with complete French guidance"
