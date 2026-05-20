# CookieVigil

CookieVigil est un outil automatisé d’audit de la sécurité des cookies web, conçu pour les environnements DevSecOps, les tests de sécurité applicative et les démonstrations académiques en cybersécurité.

L’outil analyse les en-têtes HTTP `Set-Cookie`, détecte les mauvaises configurations, classe les cookies selon leur rôle probable, corrèle les risques, génère des rapports exploitables et peut faire échouer un pipeline CI/CD selon une politique configurable.

## Contexte Du Projet

Ce projet s’inscrit dans le cadre du mémoire :

**Mise en œuvre d’un outil automatisé d’analyse de la sécurité des cookies web et intégration dans une chaîne DevSecOps.**

L’objectif est de contribuer à la sécurisation des applications web en détectant automatiquement les configurations risquées des cookies dès les premières phases du cycle de développement.

CookieVigil peut être utilisé :

- en local sur une machine d’audit ;
- dans un environnement de laboratoire distribué ;
- dans Docker ;
- dans une chaîne CI/CD ;
- contre une application de démonstration ;
- contre une application réelle, uniquement avec autorisation.

## Fonctionnalités Principales

CookieVigil permet de :

- collecter les cookies depuis les réponses HTTP ;
- analyser les cookies présents dans les redirections HTTP ;
- parser les en-têtes `Set-Cookie` ;
- détecter les attributs de sécurité absents ou mal configurés ;
- classifier les cookies selon leur rôle probable ;
- contextualiser la sévérité selon le type de cookie ;
- corréler plusieurs faiblesses pour produire un scénario de risque ;
- calculer un score global de sécurité ;
- générer des rapports en plusieurs formats ;
- retourner des codes de sortie exploitables dans un pipeline CI/CD ;
- fonctionner en environnement Docker ;
- auditer une application après authentification simple par formulaire POST.

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

```text
SESSION
AUTH
JWT
CSRF
TRACKING
ANALYTICS
PERSISTENT_AUTH
SENSITIVE
FUNCTIONAL

Cette classification permet de distinguer un cookie de session mal protégé d’un cookie fonctionnel, analytique ou de suivi.

Exemple :

un cookie SESSION sans Secure peut être classé CRITICAL ;
un cookie TRACKING sans HttpOnly peut être classé INFO ou LOW ;
un cookie JWT sans HttpOnly peut produire une corrélation de risque liée au vol de jeton via XSS.
Corrélation Des Risques
CookieVigil applique une logique de corrélation afin d’expliquer les scénarios d’attaque possibles.

Exemples de corrélations :

cookie de session sans Secure et sans HttpOnly ;
JWT accessible via JavaScript ;
cookie sensible sans protection SameSite ;
cookie sensible partagé avec plusieurs sous-domaines.
Cette approche permet de passer d’une simple détection d’attributs absents à une analyse de risque contextualisée.

Architecture
Architecture logique de l’outil :

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

Arborescence Du Projet
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
│   ├── test_analyzer.py
│   ├── test_collector.py
│   ├── test_integration.py
│   ├── test_reporter.py
│   └── test_utils.py
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

Utilisation Locale
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
  
Installation Comme Commande SystèmePour utiliser CookieVigil comme un outil en ligne de commande, à la manière d’outils comme nmap ou amass :
bash



chmod +x audit_cookies.py
chmod +x cookievigil.py
sudo ln -sf "$(pwd)/cookievigil.py" /usr/local/bin/cookievigil

Vérifier l’installation :
bash



cookievigil --help

Utiliser l’outil :
bash



cookievigil https://example.com --format all

Analyse D’un Site En LigneExemple simple :
bash



cookievigil https://google.com --fail-on none

Exemple avec génération complète des rapports :
bash



cookievigil https://example.com \
  --format all \
  --output audit_site \
  --fail-on none

Exemple avec politique de blocage :
bash



cookievigil https://example.com \
  --format all \
  --fail-on high

Dans ce dernier cas, le programme retourne un code de sortie non nul si un risque HIGH ou CRITICAL est détecté.
Analyse Avec AuthentificationCookieVigil permet une authentification simple par requête POST afin d’analyser des cookies générés après connexion.
Exemple :
bash



cookievigil http://localhost:5000/dashboard \
  --session \
  --login-url http://localhost:5000/login \
  --login-data "username=admin&password=admin123" \
  --format all

Attention : évitez d’utiliser de vrais identifiants dans l’historique shell ou dans un pipeline CI/CD. Préférez des comptes de test.
Options DevSecOpsFaire échouer l’exécution selon un niveau de risque :
bash



cookievigil https://example.com --fail-on high

Niveaux disponibles :
text



none
critical
high
medium
low

Faire échouer l’exécution si le score de sécurité est inférieur à un seuil :
bash



cookievigil https://example.com --fail-score-below 70

Exemple adapté à un pipeline CI/CD :
bash



cookievigil https://example.com \
  --format all \
  --fail-on high

Exemple adapté à une phase d’observation sans blocage :
bash



cookievigil https://example.com \
  --format all \
  --fail-on none

Application Vulnérable De DémonstrationLe dossier vulnerable_app/ contient une application Flask volontairement vulnérable.
Routes disponibles :
text



/set-bad-cookies
/set-good-cookies
/set-weak-token
/set-jwt-cookie
/set-long-expiry
/set-short-expiry
/login
/dashboard
/api/health

Cette application sert à démontrer :
des cookies sans attributs de sécurité ;
des cookies correctement configurés ;
un token faible ;
un JWT stocké dans un cookie ;
un cookie à durée de vie excessive ;
des cookies générés après authentification.
Cette application ne doit pas être exposée sur Internet.
Utilisation Avec DockerConstruire l’image CookieVigil :
bash



docker build -t cookievigil .

Afficher l’aide :
bash



docker run --rm cookievigil --help

Auditer un site en ligne :
bash



docker run --rm cookievigil https://example.com --fail-on none

Générer les rapports dans un dossier local :
bash



mkdir -p reports
sudo chown -R 1000:1000 reports
chmod -R u+rwX reports

docker run --rm \
  -v "$(pwd)/reports:/app/reports" \
  cookievigil https://example.com \
  --format all \
  --output audit_docker \
  --fail-on none

Le conteneur CookieVigil s’exécute avec un utilisateur non-root pour réduire les risques en cas de compromission du processus.
Utilisation Avec Docker ComposeSelon votre environnement, la commande peut être :
bash



docker compose

ou :
bash



docker-compose

Construire les services :
bash



docker-compose build

Démarrer l’application vulnérable :
bash



docker-compose up -d vulnerable-app

Lancer CookieVigil contre l’application vulnérable :
bash



docker-compose run --rm cookievigil \
  http://vulnerable-app:5000/set-bad-cookies \
  --force-https-context \
  --format all \
  --fail-on none

Arrêter l’environnement :
bash



docker-compose down

Si une erreur de permission apparaît lors de la génération des rapports :
text



Permission denied: reports/rapport_cookies.json

corriger les droits du dossier local :
bash



sudo chown -R 1000:1000 reports
chmod -R u+rwX reports

Intégration GitHub ActionsLe projet contient un workflow GitHub Actions :
text



.github/workflows/cookievigil.yml

Ce workflow permet de :
installer les dépendances Python ;
exécuter les tests unitaires et d’intégration ;
construire les conteneurs Docker ;
démarrer l’application vulnérable ;
exécuter CookieVigil ;
générer les rapports ;
publier les rapports comme artefacts de pipeline.
Exemple D’Intégration CI/CD Pour Une Application RéelleDans une chaîne CI/CD, CookieVigil peut être exécuté contre une application de test, de staging ou de préproduction.
Exemple générique :
yaml



- name: Audit des cookies avec CookieVigil
  run: |
    python audit_cookies.py https://staging.example.com \
      --format all \
      --output audit_cookies \
      --fail-on high

Avec Docker :
yaml



- name: Audit des cookies avec CookieVigil dans Docker
  run: |
    docker run --rm cookievigil https://staging.example.com \
      --format all \
      --fail-on high

Avec un seuil de score :
yaml



- name: Audit avec seuil de score
  run: |
    python audit_cookies.py https://staging.example.com \
      --format all \
      --fail-score-below 70

Rapports GénérésLes rapports sont générés dans le dossier reports/.
Formats disponibles :
text



json
html
csv
md
all

Exemple :
bash



cookievigil https://example.com --format all --output audit_report

Fichiers générés :
text



reports/audit_report.json
reports/audit_report.html
reports/audit_report.csv
reports/audit_report.md

Les rapports peuvent contenir des métadonnées sensibles. Ils ne doivent pas être publiés sans vérification.
TestsLancer tous les tests :
bash



python -m unittest discover -s tests -p "test_*.py" -v

La suite de tests couvre notamment :
le parsing des cookies ;
la détection fiable des attributs Secure et HttpOnly ;
la collecte des cookies dans les redirections ;
les règles de sécurité ;
la classification des cookies ;
la corrélation des risques ;
le score de sécurité ;
la génération des rapports ;
l’intégration entre collecteur, analyseur et générateur de rapports.
Exemple de résultat attendu :
text



Ran 53 tests
OK

Sécurité De L’OutilCookieVigil peut manipuler des métadonnées sensibles liées aux cookies. Les rapports générés doivent donc être protégés.
Mesures prises :
troncature des valeurs de cookies affichées ;
conservation de la valeur complète uniquement pour l’analyse interne ;
génération de hash SHA-256 pour éviter l’exposition directe des valeurs ;
exécution Docker avec utilisateur non-root ;
séparation entre l’application vulnérable et l’outil d’audit ;
possibilité de contrôler les seuils de blocage CI/CD.
Voir le fichier SECURITY.md pour les recommandations de sécurité, les limites d’usage et les consignes de divulgation responsable.
LimitesCookieVigil est un outil d’audit automatisé. Il ne remplace pas :
un test d’intrusion complet ;
une revue de sécurité manuelle ;
une analyse dynamique avec navigateur ;
Burp Suite ;
OWASP ZAP ;
une validation métier des risques.
Limites actuelles :
l’outil analyse principalement les cookies observés dans les réponses HTTP ;
il ne simule pas encore un navigateur complet ;
il n’exécute pas le JavaScript côté client ;
il ne remplace pas une analyse fonctionnelle de l’application ;
il nécessite une interprétation humaine des résultats.
Perspectives D’ÉvolutionÉvolutions possibles :
intégration d’un navigateur headless comme Playwright ;
détection des cookies créés dynamiquement côté client ;
export SARIF pour intégration avancée avec GitHub Security ;
configuration des règles via fichier YAML ;
tableau de bord web pour visualiser les résultats ;
comparaison automatique entre plusieurs environnements.
Statut Du ProjetProjet académique orienté cybersécurité et DevSecOps.
Il peut être utilisé comme base pour :
un mémoire de fin d’études ;
une démonstration DevSecOps ;
un laboratoire de sensibilisation à la sécurité des cookies ;
une extension vers des contrôles de sécurité web plus avancés.





Après remplacement :

```bash
git add README.md
git commit -m "Rewrite README with complete French usage documentation"
