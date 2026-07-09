#!/bin/bash
# audit_public_sites_docker.sh - Version corrigée

set -e

# Configuration
OUTPUT_DIR="reports/public_sites"
mkdir -p "$OUTPUT_DIR"

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
RESET='\033[0m'

declare -A SITES=(
    ["google"]="https://www.google.com"
    ["github"]="https://github.com"
    ["wikipedia"]="https://www.wikipedia.org"
    ["lemonde"]="https://www.lemonde.fr"
)

print_separator() {
    echo -e "${CYAN}══════════════════════════════════════════════════════════════════════════════════════════════════${RESET}"
}

run_cmd() {
    echo -e "${BOLD}${BLUE}▶ $1${RESET}"
    eval "$1"
    echo ""
}

audit_site() {
    local site_name="$1"
    local site_url="$2"
    
    echo -e "\n${BOLD}${MAGENTA} AUDIT : $site_name${RESET}"
    echo -e "${BLUE}   URL : $site_url${RESET}"
    print_separator
    
    # Étape 1 : curl
    echo -e "${BOLD}${YELLOW}--- 1. Collecte avec curl ---${RESET}"
    CURL_CMD="curl -D - -s -o /dev/null '$site_url' 2>&1 | grep -i 'Set-Cookie' | head -20 || echo 'Aucun Set-Cookie trouvé'"
    run_cmd "$CURL_CMD"
    
    # Étape 2 : CookieVigil Docker
    echo -e "${BOLD}${YELLOW}--- 2. Audit avec CookieVigil (Docker) ---${RESET}"
    
    LOG_FILE="${OUTPUT_DIR}/rapport_${site_name}.log"
    
    #  CORRECTION : Ne pas inclure "reports/" dans --output
    echo -e "${BOLD}${BLUE}▶ docker compose run --rm cookievigil '$site_url' --verbose --fail-on none --format all --output public_sites/rapport_${site_name}${RESET}"
    docker compose run --rm cookievigil \
        "$site_url" \
        --verbose \
        --fail-on none \
        --format all \
        --output "public_sites/rapport_${site_name}" \
        2>&1 | tee "$LOG_FILE"
    
    echo ""
    echo -e "${GREEN} Audit de $site_name terminé.${RESET}"
    echo -e "    Rapports : ${OUTPUT_DIR}/rapport_${site_name}.{json,html,csv,md}"
    echo -e "    Logs : $LOG_FILE"
    print_separator
    echo ""
    sleep 2
}

# ============================================================
# EXÉCUTION
# ============================================================

echo -e "${BOLD}${CYAN}╔═══════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${CYAN}║          CookieVigil - Audit des sites publics (Docker)        ║${RESET}"
echo -e "${BOLD}${CYAN}║              Validation de la collecte en conditions réelles    ║${RESET}"
echo -e "${BOLD}${CYAN}╚═══════════════════════════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "${BOLD}${YELLOW} Note éthique :${RESET}"
echo -e "${YELLOW}   Tests à des fins de validation technique uniquement.${RESET}"
echo -e "${YELLOW}   Conformément à SECURITY.md - Aucun audit de sécurité.${RESET}"
echo ""
echo -e "${BOLD}${BLUE} DÉMARRAGE - $(date '+%Y-%m-%d %H:%M:%S')${RESET}"
echo ""

for site_name in "${!SITES[@]}"; do
    audit_site "$site_name" "${SITES[$site_name]}"
done

# Récapitulatif
echo -e "\n${BOLD}${GREEN}╔═══════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${GREEN}║                    RÉCAPITULATIF DES AUDITS                   ║${RESET}"
echo -e "${BOLD}${GREEN}╚═══════════════════════════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "${BOLD}${BLUE}TABLEAU 3.3 : Résultats des analyses sur sites publics${RESET}"
echo -e "${CYAN}┌──────────────┬─────────────┬───────────┬──────────────────────────────────────────────────────────────┐${RESET}"
echo -e "${CYAN}│ Site         │ Cookies     │ Score     │ Observations                                                │${RESET}"
echo -e "${CYAN}├──────────────┼─────────────┼───────────┼──────────────────────────────────────────────────────────────┤${RESET}"

for site_name in google github wikipedia lemonde; do
    log_file="${OUTPUT_DIR}/rapport_${site_name}.log"
    if [ -f "$log_file" ]; then
        cookie_count=$(grep -E "Total cookies analyses|Total cookies analysés" "$log_file" 2>/dev/null | sed -E 's/.*[ :]+([0-9]+).*/\1/' | head -1)
        security_score=$(grep -E "Score de securite|Score de sécurité" "$log_file" 2>/dev/null | sed -E 's/.*[ :]+([0-9]+)\/.*/\1/' | head -1)
        obs=$(grep -E "(Domaine trop large|Path trop large|Durée de vie excessive|SameSite manquant|Secure manquant)" "$log_file" 2>/dev/null | head -2 | sed -E 's/.*- (.*) \(.*\)/\1/' | tr '\n' '; ' | sed 's/; $//')
        [ -z "$obs" ] && obs="Configuration OK"
        obs=$(echo "$obs" | cut -c1-60)
        
        printf "${GREEN}│ %-12s │ %-11s │ %-9s │ %-60s │${RESET}\n" \
            "$site_name" "${cookie_count:-N/A}" "${security_score:-N/A}/100" "$obs"
    else
        printf "${RED}│ %-12s │ %-11s │ %-9s │ %-60s │${RESET}\n" \
            "$site_name" "N/A" "N/A" "Non audité"
    fi
done

echo -e "${CYAN}└──────────────┴─────────────┴───────────┴──────────────────────────────────────────────────────────────┘${RESET}"
echo ""
echo -e "${BOLD}${GREEN} Tous les audits sont terminés.${RESET}"
echo -e "    Rapports : ${OUTPUT_DIR}/${RESET}"
echo ""
echo -e "${BOLD}${YELLOW} Note éthique :${RESET}"
echo -e "${YELLOW}   Tests à des fins de validation technique uniquement.${RESET}"
echo -e "${YELLOW}   Conformément à SECURITY.md - Aucun audit de sécurité.${RESET}"
echo ""
echo -e "${BOLD}${BLUE}Fin : $(date '+%Y-%m-%d %H:%M:%S')${RESET}"
