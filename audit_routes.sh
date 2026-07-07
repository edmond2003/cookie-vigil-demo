#!/bin/bash
# Script d'audit automatique des routes de l'application vulnérable
# Comparaison curl vs CookieVigil pour chaque route

set -e  # quitte en cas d'erreur, mais on peut le désactiver si besoin

# Configuration
BASE_URL="http://192.168.56.3:5000"
OUTPUT_DIR="reports"
mkdir -p "$OUTPUT_DIR"

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# Fonction d'affichage d'un en-tête de route
print_route_header() {
    echo -e "\n${BOLD}${CYAN}═══════════════════════════════════════════════════════════════════${RESET}"
    echo -e "${BOLD}${CYAN}  Route : $1${RESET}"
    echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════════════${RESET}"
}

# Fonction d'exécution d'une commande avec affichage de la commande et de la sortie
run_cmd() {
    echo -e "${BOLD}${BLUE}▶ $1${RESET}"
    eval "$1"
    echo ""
}

# Définir les routes avec leurs options spécifiques
routes=(
    "/set-bad-cookies"
    "/set-good-cookies"
    "/set-weak-token"
    "/set-jwt-cookie"
    "/set-long-expiry"
    "/set-short-expiry"
    "/dashboard"  # nécessite authentification
)

# Parcourir les routes
for route in "${routes[@]}"; do
    route_name=$(echo "$route" | sed 's/\//_/g' | sed 's/^_//')
    print_route_header "$route"

    # === ÉTAPE 1 : curl pour capturer les en-têtes Set-Cookie bruts ===
    echo -e "${BOLD}${YELLOW}--- 1. Collecte avec curl (en-têtes Set-Cookie bruts) ---${RESET}"
    CURL_CMD="curl -s -v $BASE_URL$route 2>&1 | grep -i 'Set-Cookie' | grep -v '^<' || echo 'Aucun Set-Cookie trouvé'"
    run_cmd "$CURL_CMD"

    # === ÉTAPE 2 : CookieVigil avec --verbose ===
    echo -e "${BOLD}${YELLOW}--- 2. Audit avec CookieVigil (collecte + analyse) ---${RESET}"
    
    # Construction de la commande CookieVigil de base
    COOKIEVIGIL_CMD="cookievigil $BASE_URL$route --force-https-context --format all --output ${OUTPUT_DIR}/rapport_${route_name} --fail-on high --verbose"
    
    # Cas particulier de /dashboard : ajout de l'authentification
    if [[ "$route" == "/dashboard" ]]; then
        COOKIEVIGIL_CMD="cookievigil $BASE_URL$route --session --login-url $BASE_URL/login --login-data 'username=admin&password=admin123' --force-https-context --format all --output ${OUTPUT_DIR}/rapport_${route_name} --fail-on high --verbose"
    fi

    run_cmd "$COOKIEVIGIL_CMD"

    echo -e "${GREEN}✅ Route $route terminée.${RESET}"
    echo -e "   Rapport généré dans : ${OUTPUT_DIR}/rapport_${route_name}.{json,html,csv,md}"
    
    # Petite pause entre les routes pour éviter de surcharger
    sleep 2
done

echo -e "\n${BOLD}${GREEN}🎉 Tous les audits sont terminés. Les rapports sont dans le dossier '${OUTPUT_DIR}/'.${RESET}"
