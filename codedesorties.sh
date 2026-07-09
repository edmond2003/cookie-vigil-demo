#!/bin/bash
# test_exit_codes_quick.sh - Test des codes de sortie avec affichage des commandes
# Style : chaque commande est affichée avant exécution, comme dans votre exemple

BASE_URL="http://192.168.56.3:5000"

# Couleurs
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
RESET='\033[0m'

echo -e "${BOLD}${BLUE}╔═══════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${BLUE}║              TEST DES CODES DE SORTIE COOKIEVIGIL                ║${RESET}"
echo -e "${BOLD}${BLUE}║                   VÉRIFICATION DU SECURITY GATE                   ║${RESET}"
echo -e "${BOLD}${BLUE}╚═══════════════════════════════════════════════════════════════════╝${RESET}"
echo ""

# Fonction qui exécute une commande et affiche son code de sortie
# Style : comme dans votre exemple (cookievigil ... 2>&1; echo "CODE_SORTIE=$?")
test_exit() {
    local desc="$1"
    local cmd="$2"
    
    echo -e "${BOLD}${YELLOW}▶ Test : $desc${RESET}"
    echo -e "${BLUE}  Commande : $cmd${RESET}"
    
    # Exécution de la commande avec capture du code de sortie
    # Style identique à votre exemple : cmd 2>&1; echo "CODE_SORTIE=$?"
    eval "$cmd 2>&1; echo \"CODE_SORTIE=\$?\"" | grep -E "(Politique CI/CD|Score de sécurité|CODE_SORTIE)"
    
    echo ""
}

echo -e "${BOLD}${BLUE}═══════════════════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}${YELLOW}🔹 TESTS --fail-on${RESET}"
echo -e "${BOLD}${BLUE}═══════════════════════════════════════════════════════════════════${RESET}"
echo ""

# Test 1 : Mode observation --fail-on none
# Code attendu : 0
test_exit "Mode observation (--fail-on none)" \
    "cookievigil $BASE_URL/set-bad-cookies --force-https-context --fail-on none"

# Test 2 : Blocage CRITICAL --fail-on high
# Code attendu : 2
test_exit "Blocage CRITICAL (--fail-on high)" \
    "cookievigil $BASE_URL/set-bad-cookies --force-https-context --fail-on high"

# Test 3 : Avertissement MEDIUM --fail-on medium
# Code attendu : 1
test_exit "Avertissement MEDIUM (--fail-on medium)" \
    "cookievigil $BASE_URL/set-long-expiry --force-https-context --fail-on medium"

echo -e "${BOLD}${BLUE}═══════════════════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}${YELLOW}🔹 TESTS --fail-score-below${RESET}"
echo -e "${BOLD}${BLUE}═══════════════════════════════════════════════════════════════════${RESET}"
echo ""

# Test 4 : Score < 70
# Code attendu : 2
test_exit "Score < 70 (--fail-score-below 70)" \
    "cookievigil $BASE_URL/set-weak-token --force-https-context --fail-score-below 70"

# Test 5 : Score >= 70
# Code attendu : 0
test_exit "Score >= 70 (--fail-score-below 60)" \
    "cookievigil $BASE_URL/set-good-cookies --force-https-context --fail-score-below 60"

echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}${GREEN} Tous les tests sont terminés${RESET}"
echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════════════════════════${RESET}"
