#!/bin/bash
set -e  # Arrêt en cas d'erreur
set -u  # Détection des variables non définies

# Répertoire de travail (adapter si besoin)
WORKDIR=~/Bureau/cookie-vigil-demo
cd "$WORKDIR"

echo "=== 1. Tests curl + CookieVigil sur application vulnérable (premier extrait) ==="

# /set-bad-cookies
echo "--- /set-bad-cookies ---"
curl http://192.168.56.3:5000/set-bad-cookies -v 2>&1 | grep "Set-Cookie" || true
cookievigil http://192.168.56.3:5000/set-bad-cookies --format all --output rapport_bad_cookies --fail-on none --force-https-context --verbose

# /set-good-cookies
echo "--- /set-good-cookies ---"
curl http://192.168.56.3:5000/set-good-cookies -v 2>&1 | grep "Set-Cookie" || true
cookievigil http://192.168.56.3:5000/set-good-cookies --format all --output rapport_good_cookies --fail-on none --force-https-context --verbose

# /set-weak-token
echo "--- /set-weak-token ---"
curl http://192.168.56.3:5000/set-weak-token -v 2>&1 | grep "Set-Cookie" || true
cookievigil http://192.168.56.3:5000/set-weak-token --format all --output rapport_weak_token --fail-on none --force-https-context --verbose

# /set-jwt-cookie
echo "--- /set-jwt-cookie ---"
curl http://192.168.56.3:5000/set-jwt-cookie -v 2>&1 | grep "Set-Cookie" || true
cookievigil http://192.168.56.3:5000/set-jwt-cookie --format all --output rapport_jwt_cookie --fail-on none --force-https-context --verbose

# /set-long-expiry
echo "--- /set-long-expiry ---"
curl http://192.168.56.3:5000/set-long-expiry -v 2>&1 | grep "Set-Cookie" || true
cookievigil http://192.168.56.3:5000/set-long-expiry --format all --output rapport_set_long_expiry --fail-on none --force-https-context --verbose

# /set-short-expiry (premier appel avec output rapport_set_long_expiry par erreur dans l'extrait, on corrige)
echo "--- /set-short-expiry (1er appel) ---"
curl http://192.168.56.3:5000/set-short-expiry -v 2>&1 | grep "Set-Cookie" || true
cookievigil http://192.168.56.3:5000/set-short-expiry --format all --output rapport_set_long_expiry --fail-on none --force-https-context --verbose

# second appel à /set-short-expiry avec bon output
echo "--- /set-short-expiry (2e appel) ---"
cookievigil http://192.168.56.3:5000/set-short-expiry --format all --output rapport_short_expiry --fail-on none --force-https-context --verbose

# Authentification /dashboard
echo "--- Authentification /dashboard ---"
curl -X POST http://192.168.56.3:5000/login -d "username=admin&password=admin123" -v 2>&1 | grep "Set-Cookie" || true
cookievigil http://192.168.56.3:5000/dashboard --insecure --session --login-url http://192.168.56.3:5000/login --login-data "username=admin&password=admin123" --force-https-context --format all --output rapport_auth_corrige --verbose

# Test sur sites publics
echo "--- Tests sur sites publics (site.txt) ---"
cookievigil -f site.txt --verbose --format all --output sitepublic

# Docker Compose
echo "--- Docker Compose ---"
docker compose up -d vulnerable-app

echo "--- Attente de l'application vulnérable ---"
for i in {1..20}; do
  curl -fsS http://localhost:5000/api/health && break
  sleep 2
done

echo "--- Scan Docker ---"
cookievigil http://localhost:5000/set-bad-cookies --force-https-context --format html --fail-on none
echo "CODE_SORTIE=$?"

# Tests des politiques --fail-on
echo "--- Test --fail-on high (avec force-https-context) ---"
cookievigil http://localhost:5000/set-bad-cookies --force-https-context --format html --fail-on high
echo "CODE_SORTIE=$?"

echo "--- Test --fail-on high (sans force-https-context) ---"
cookievigil http://localhost:5000/set-bad-cookies --format html --fail-on high
echo "CODE_SORTIE=$?"

echo "--- Test --fail-score-below 70 ---"
cookievigil http://localhost:5000/set-weak-token --force-https-context --format html --fail-on none --fail-score-below 70
echo "CODE_SORTIE=$?"

echo "=== 2. Tests unitaires (deuxième extrait) ==="
python -m unittest discover -s tests -p "test_*.py" -v

echo "=== Tous les tests sont terminés ==="
