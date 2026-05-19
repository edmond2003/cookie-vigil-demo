# CookieVigil

CookieVigil est un outil automatisé d’audit de la sécurité des cookies web, conçu pour les environnements DevSecOps et les démonstrations académiques en cybersécurité.

Il analyse les en-têtes HTTP `Set-Cookie`, détecte les mauvaises configurations, classe les cookies selon leur rôle probable, corrèle les risques de sécurité, génère des rapports exploitables et peut faire échouer un pipeline CI/CD selon une politique configurable.

## Contexte Du Projet

Ce projet s’inscrit dans le cadre du mémoire :

**Mise en œuvre d’un outil automatisé d’analyse de la sécurité des cookies web et intégration dans une chaîne DevSecOps.**

L’objectif est de contribuer à la sécurisation des applications web en détectant automatiquement les configurations risquées des cookies dès les premières phases du cycle de développement.

## Fonctionnalités

CookieVigil permet de :

- collecter les cookies depuis les réponses HTTP ;
- analyser les cookies présents dans les redirections HTTP ;
- détecter les mauvaises configurations liées aux attributs de sécurité ;
- classifier les cookies selon leur rôle probable ;
- corréler plusieurs faiblesses pour produire une analyse de risque plus pertinente ;
- générer des rapports dans plusieurs formats ;
- s’intégrer dans une chaîne CI/CD avec des seuils de blocage.

## Règles De Sécurité Analysées

L’outil détecte notamment :

- absence de l’attribut `Secure` ;
- absence de l’attribut `HttpOnly` ;
- absence de l’attribut `SameSite` ;
- utilisation de `SameSite=None` sans `Secure` ;
- domaine trop large via l’attribut `Domain` ;
- chemin trop large via l’attribut `Path` ;
- durée de vie excessive du cookie ;
- mauvaise configuration des préfixes `__Secure-` et `__Host-` ;
- token de session faible ou prévisible ;
- présence d’un JWT dans un cookie.

## Classification Des Cookies

CookieVigil ne se limite pas à signaler les attributs manquants. Il tente également de classifier les cookies afin d’adapter la sévérité du risque.

Catégories prises en charge :

- `SESSION` ;
- `AUTH` ;
- `JWT` ;
- `CSRF` ;
- `TRACKING` ;
- `ANALYTICS` ;
- `PERSISTENT_AUTH` ;
- `SENSITIVE` ;
- `FUNCTIONAL`.

Cette classification permet de distinguer, par exemple, un cookie de session mal protégé d’un cookie fonctionnel ou de suivi moins critique.

## Corrélation Des Risques

L’outil applique une logique de corrélation pour mieux expliquer les scénarios d’attaque possibles.

Exemples :

- cookie de session sans `Secure` et sans `HttpOnly` ;
- JWT accessible via JavaScript ;
- cookie sensible sans protection `SameSite` ;
- cookie sensible partagé avec plusieurs sous-domaines.

Cette approche permet de passer d’une simple détection technique à une analyse de risque plus contextualisée.

## Architecture

Architecture logique de l’outil :

```text
Interface CLI
     |
     v
CookieCollector
     |
     v
Parser Set-Cookie
     |
     v
CookieAnalyzer
     |
     v
Moteur de classification et de corrélation
     |
     v
CookieReporter
     |
     v
Rapports + Code de sortie CI/CD

Architecture de démonstration :

VM1 ou conteneur Docker :
  Application Flask volontairement vulnérable

VM2 ou conteneur Docker :
  CookieVigil
  
Cette séparation permet de simuler un scénario réaliste dans lequel un outil d’audit externe analyse une application web cible.
Arborescence Du Projet:

cookie-vigil-demo/
├── audit_cookies.py
├── cookievigil.py
├── src/
│   ├── analyzer.py
│   ├── collector.py
│   ├── reporter.py
│   ├── utils.py
│   └── __init__.py
├── tests/
├── vulnerable_app/
│   ├── app.py
│   ├── Dockerfile
│   └── requirements.txt
├── reports/
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── README.md
└── SECURITY.md

Installation Locale
Cloner le dépôt :

git clone https://github.com/<votre-utilisateur>/<votre-depot>.git
cd <votre-depot>

Créer un environnement virtuel :

python -m venv venv
source venv/bin/activate

Installer les dépendances :

pip install -r requirements.txt
Vérifier l’installation avec les tests :

python -m unittest discover -s tests -p "test_*.py" -v
Utilisation De Base
Analyser une URL :

python audit_cookies.py https://example.com
Analyser une URL avec sortie détaillée :

python audit_cookies.py https://example.com --verbose
Générer tous les formats de rapport :

python audit_cookies.py https://example.com --format all --output rapport_cookies
Analyser plusieurs URLs :

python audit_cookies.py \
  https://example.com \
  https://example.com/login \
  --format all
Analyse Avec Authentification
CookieVigil permet une authentification simple par requête POST afin d’analyser des cookies générés après connexion.

Exemple :

python audit_cookies.py http://localhost:5000/dashboard \
  --session \
  --login-url http://localhost:5000/login \
  --login-data "username=admin&password=admin123" \
  --format all
Options DevSecOps
Faire échouer l’exécution selon un niveau de risque :

python audit_cookies.py https://example.com --fail-on high
Niveaux disponibles :

none
critical
high
medium
low
Faire échouer l’exécution si le score de sécurité est inférieur à un seuil :

python audit_cookies.py https://example.com --fail-score-below 70
Exemple adapté à un pipeline CI/CD :

python audit_cookies.py https://example.com --format all --fail-on high
Application Vulnérable De Démonstration
Le dossier vulnerable_app/ contient une application Flask volontairement vulnérable.

Routes disponibles :

/set-bad-cookies
/set-good-cookies
/set-weak-token
/set-jwt-cookie
/set-long-expiry
/set-short-expiry
/login
/dashboard
/api/health
Cette application sert à démontrer les cas suivants :

cookies sans attributs de sécurité ;
cookies correctement configurés ;
token faible ;
JWT stocké dans un cookie ;
cookie à durée de vie excessive ;
cookies générés après authentification.
Utilisation Avec Docker
Construire les services :

docker compose build
Démarrer l’application vulnérable :

docker compose up -d vulnerable-app
Lancer CookieVigil contre l’application vulnérable :

docker compose run --rm cookievigil \
  http://vulnerable-app:5000/set-bad-cookies \
  --force-https-context \
  --format all \
  --fail-on none
Arrêter l’environnement :

docker compose down
Remarque : selon l’environnement, la commande peut être docker compose ou docker-compose.

Intégration GitHub Actions
Le projet contient un workflow GitHub Actions :

.github/workflows/cookievigil.yml
Ce workflow permet de :

installer les dépendances Python ;
exécuter les tests unitaires et d’intégration ;
construire l’environnement Docker ;
démarrer l’application vulnérable ;
exécuter CookieVigil ;
générer les rapports ;
publier les rapports comme artefacts de pipeline.
Rapports Générés
Les rapports sont générés dans le dossier reports/.

Formats disponibles :

json
html
csv
md
all
Exemple :

python audit_cookies.py https://example.com --format all --output audit_report
Tests
Lancer tous les tests :

python -m unittest discover -s tests -p "test_*.py" -v
La suite de tests couvre notamment :

le parsing des cookies ;
la collecte des cookies dans les redirections ;
les règles de sécurité ;
la classification des cookies ;
la corrélation des risques ;
la génération des rapports ;
l’intégration entre collecteur, analyseur et générateur de rapports.

Sécurité De L’OutilCookieVigil peut manipuler des métadonnées sensibles liées aux cookies. Les rapports générés doivent donc être protégés.
Voir le fichier SECURITY.md pour les recommandations de sécurité, les limites d’usage et les consignes de divulgation responsable.
LimitesCookieVigil est un outil d’audit automatisé. Il ne remplace pas :
un test d’intrusion complet ;
une revue de sécurité manuelle ;
une analyse dynamique avec navigateur ;
Burp Suite ;
OWASP ZAP ;
une validation métier des risques.
Les résultats doivent être interprétés selon le contexte de l’application auditée.
Statut Du ProjetProjet académique orienté cybersécurité et DevSecOps.
Il peut être utilisé comme base pour :
un mémoire de fin d’études ;
une démonstration DevSecOps ;
un laboratoire de sensibilisation à la sécurité des cookies ;
une extension vers des contrôles de sécurité web plus avancés.
