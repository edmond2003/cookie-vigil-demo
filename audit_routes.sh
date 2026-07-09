#!/bin/bash
# audit_routes.sh - Version complète et corrigée

# Configuration
BASE_URL="http://192.168.56.3:5000"
OUTPUT_DIR="reports"
mkdir -p "$OUTPUT_DIR"

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

print_route_header() {
    echo -e "\n${BOLD}${CYAN}═══════════════════════════════════════════════════════════════════${RESET}"
    echo -e "${BOLD}${CYAN}  Route : $1${RESET}"
    echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════════════${RESET}"
}

run_cmd() {
    echo -e "${BOLD}${BLUE}▶ $1${RESET}"
    eval "$1"
    echo ""
}

#  TOUTES LES ROUTES
routes=(
    "/set-bad-cookies"
    "/set-good-cookies"
    "/set-weak-token"
    "/set-jwt-cookie"
    "/set-long-expiry"
    "/set-short-expiry"
    "/dashboard"
)

#  BOUCLE SUR TOUTES LES ROUTES
for route in "${routes[@]}"; do
    route_name=$(echo "$route" | sed 's/\//_/g' | sed 's/^_//')
    print_route_header "$route"

    # Étape 1 : curl (version corrigée)
    echo -e "${BOLD}${YELLOW}--- 1. Collecte avec curl (en-têtes Set-Cookie bruts) ---${RESET}"
    #  Correction : utiliser -D - pour afficher les en-têtes
    CURL_CMD="curl -D - -s -o /dev/null $BASE_URL$route 2>&1 | grep -i 'Set-Cookie' || echo 'Aucun Set-Cookie trouvé'"
    run_cmd "$CURL_CMD"

    # Étape 2 : CookieVigil
    echo -e "${BOLD}${YELLOW}--- 2. Audit avec CookieVigil (collecte + analyse) ---${RESET}"
    
    if [[ "$route" == "/dashboard" ]]; then
        COOKIEVIGIL_CMD="cookievigil $BASE_URL$route --session --login-url $BASE_URL/login --login-data 'username=admin&password=admin123' --force-https-context --format all --output rapport_${route_name} --fail-on high --verbose"
    else
        COOKIEVIGIL_CMD="cookievigil $BASE_URL$route --force-https-context --format all --output rapport_${route_name} --fail-on high --verbose"
    fi

    run_cmd "$COOKIEVIGIL_CMD"

    echo -e "${GREEN} Route $route terminée.${RESET}"
    echo -e "    Rapports : ${OUTPUT_DIR}/rapport_${route_name}.{json,html,csv,md}"
    
    sleep 2
done

echo -e "\n${BOLD}${GREEN} Tous les audits sont terminés.${RESET}"
echo -e "    Dossier : ${OUTPUT_DIR}/"
ls -la "$OUTPUT_DIR" | grep rapport_
