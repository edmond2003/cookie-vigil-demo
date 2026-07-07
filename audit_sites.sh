#!/bin/bash
# audit_public_sites.sh - Audit des sites publics pour validation de CookieVigil
# Tableau 3.3 du mémoire : google.com, wikipedia.org, lemonde.fr, github.com

set +e

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

# Sites à auditer (nom, URL)
declare -A SITES=(
    ["google"]="https://www.google.com"
    ["github"]="https://github.com"
    ["wikipedia"]="https://www.wikipedia.org"
    ["lemonde"]="https://www.lemonde.fr"
)

echo -e "${BOLD}${CYAN}╔═══════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${CYAN}║          CookieVigil - Audit des sites publics                  ║${RESET}"
echo -e "${BOLD}${CYAN}║              Validation de la collecte en conditions réelles    ║${RESET}"
echo -e "${BOLD}${CYAN}╚═══════════════════════════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "${BOLD}${YELLOW} Note éthique${RESET}"
echo -e "${YELLOW}   Tests ponctuels à des fins de validation technique uniquement.${RESET}"
echo -e "${YELLOW}   Conformément au fichier SECURITY.md - Aucun audit de sécurité.${RESET}"
echo -e "${YELLOW}   Les résultats ne sont pas publiés ni utilisés à des fins malveillantes.${RESET}"
echo ""
echo -e "${BOLD}${BLUE} DÉMARRAGE DES AUDITS - $(date '+%Y-%m-%d %H:%M:%S')${RESET}"
echo ""

# Fonction pour afficher un séparateur
print_separator() {
    echo -e "${CYAN}══════════════════════════════════════════════════════════════════════════════════════════════════${RESET}"
}

# Fonction pour auditer un site
audit_site() {
    local site_name="$1"
    local site_url="$2"
    local output_name="${site_name}_$(date +%Y%m%d_%H%M%S)"
    
    print_separator
    echo -e "${BOLD}${MAGENTA} AUDIT : $site_name${RESET}"
    echo -e "${BLUE}   URL : $site_url${RESET}"
    echo -e "${BLUE}   Début : $(date '+%H:%M:%S')${RESET}"
    print_separator
    
    # Étape 1 : Collecte avec curl (en-têtes Set-Cookie)
    echo -e "\n${BOLD}${YELLOW}--- 1. Collecte avec curl (en-têtes Set-Cookie bruts) ---${RESET}"
    echo -e "${CYAN}▶ curl -s -v $site_url 2>&1 | grep -i 'Set-Cookie' | head -20${RESET}"
    echo ""
    curl -s -v "$site_url" 2>&1 | grep -i 'Set-Cookie' | head -20 || echo "   Aucun Set-Cookie trouvé"
    echo ""
    
    # Étape 2 : Audit avec CookieVigil
    echo -e "${BOLD}${YELLOW}--- 2. Audit avec CookieVigil ---${RESET}"
    echo -e "${CYAN}▶ cookievigil $site_url --format all --output ${OUTPUT_DIR}/${output_name} --verbose 2>&1${RESET}"
    echo ""
    
    # Exécution de CookieVigil avec capture des données clés
    {
        cookievigil "$site_url" \
            --format all \
            --output "${OUTPUT_DIR}/${output_name}" \
            --verbose \
            --fail-on none \
            2>&1
    } | tee "${OUTPUT_DIR}/${output_name}.log"
    
    local exit_code=$?
    
    # Extraction des statistiques clés
    echo ""
    echo -e "${BOLD}${BLUE}--- RÉSULTATS DE L'AUDIT ---${RESET}"
    
    # Extraire le nombre de cookies (depuis le résumé)
    local cookie_count=$(grep -E "Total cookies analyses|Total cookies analysés" "${OUTPUT_DIR}/${output_name}.log" 2>/dev/null | sed -E 's/.*[ :]+([0-9]+).*/\1/' | head -1)
    
    # Extraire le score de sécurité
    local security_score=$(grep -E "Score de securite|Score de sécurité" "${OUTPUT_DIR}/${output_name}.log" 2>/dev/null | sed -E 's/.*[ :]+([0-9]+)\/.*/\1/' | head -1)
    
    # Extraire les cookies collectés (noms)
    local cookie_names=$(grep -E "Cookie: .* \(Risque:" "${OUTPUT_DIR}/${output_name}.log" 2>/dev/null | sed -E 's/.*Cookie: ([^ ]+) .*/\1/' | tr '\n' ', ' | sed 's/, $//')
    
    # Extraire les catégories
    local categories=$(grep -E "Categorie:" "${OUTPUT_DIR}/${output_name}.log" 2>/dev/null | sed -E 's/.*Categorie: ([A-Z_]+).*/\1/' | sort -u | tr '\n' ', ' | sed 's/, $//')
    
    # Extraire les risques détectés
    local risks=$(grep -E "CRITICAL|HIGH|MEDIUM|LOW|INFO" "${OUTPUT_DIR}/${output_name}.log" 2>/dev/null | grep -E "risque" | head -5 | sed -E 's/.*\((CRITICAL|HIGH|MEDIUM|LOW|INFO)\).*/\1/' | sort -u | tr '\n' ', ' | sed 's/, $//')
    
    # Afficher le résumé formaté
    echo -e "${GREEN} Site : $site_name${RESET}"
    echo -e "    Cookies analysés : ${cookie_count:-N/A}"
    echo -e "    Score de sécurité : ${security_score:-N/A}/100"
    echo -e "     Catégories : ${categories:-N/A}"
    echo -e "    Cookies : ${cookie_names:-Aucun}"
    echo -e "     Risques détectés : ${risks:-Aucun}"
    echo -e "    Rapports : ${OUTPUT_DIR}/${output_name}.{json,html,csv,md}"
    
    echo ""
    echo -e "${BOLD}${BLUE}--- EXTRAIT DU RAPPORT (premiers problèmes détectés) ---${RESET}"
    grep -E "(Attribut|Domaine|Durée|Path|SameSite|Secure)" "${OUTPUT_DIR}/${output_name}.log" 2>/dev/null | head -10 | sed 's/^/   /'
    
    echo ""
    echo -e "${GREEN} Audit de $site_name terminé (code de sortie : $exit_code)${RESET}"
    print_separator
    echo ""
    sleep 2
}

# Fonction pour afficher le récapitulatif final
print_summary() {
    echo -e "\n${BOLD}${GREEN}╔═══════════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${BOLD}${GREEN}║                    RÉCAPITULATIF DES AUDITS                   ║${RESET}"
    echo -e "${BOLD}${GREEN}╚═══════════════════════════════════════════════════════════════════╝${RESET}"
    echo ""
    
    echo -e "${BOLD}${BLUE}TABLEAU 3.3 : Résultats des analyses sur sites publics${RESET}"
    echo -e "${CYAN}┌──────────────┬─────────────┬───────────┬──────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${CYAN}│ Site         │ Cookies     │ Score     │ Observations                                                │${RESET}"
    echo -e "${CYAN}├──────────────┼─────────────┼───────────┼──────────────────────────────────────────────────────────────┤${RESET}"
    
    for site_name in google github wikipedia lemonde; do
        local log_file="${OUTPUT_DIR}/${site_name}_*.log"
        local latest_log=$(ls -t ${OUTPUT_DIR}/${site_name}_*.log 2>/dev/null | head -1)
        
        if [ -f "$latest_log" ]; then
            local cookie_count=$(grep -E "Total cookies analyses|Total cookies analysés" "$latest_log" 2>/dev/null | sed -E 's/.*[ :]+([0-9]+).*/\1/' | head -1)
            local security_score=$(grep -E "Score de securite|Score de sécurité" "$latest_log" 2>/dev/null | sed -E 's/.*[ :]+([0-9]+)\/.*/\1/' | head -1)
            
            # Extraire quelques observations clés
            local obs=$(grep -E "(Domaine trop large|Path trop large|Durée de vie excessive|SameSite manquant|Secure manquant)" "$latest_log" 2>/dev/null | head -2 | sed -E 's/.*- (.*) \(.*\)/\1/' | tr '\n' '; ' | sed 's/; $//')
            [ -z "$obs" ] && obs="Configuration OK"
            
            # Limiter la longueur de l'observation
            obs=$(echo "$obs" | cut -c1-60)
            
            printf "${GREEN}│ %-12s │ %-11s │ %-9s │ %-60s │${RESET}\n" \
                "$site_name" \
                "${cookie_count:-N/A}" \
                "${security_score:-N/A}/100" \
                "$obs"
        else
            printf "${RED}│ %-12s │ %-11s │ %-9s │ %-60s │${RESET}\n" \
                "$site_name" \
                "N/A" \
                "N/A" \
                "Non audité"
        fi
    done
    
    echo -e "${CYAN}└──────────────┴─────────────┴───────────┴──────────────────────────────────────────────────────────────┘${RESET}"
    echo ""
    
    echo -e "${BOLD}${BLUE}🏷️  Légende des catégories :${RESET}"
    echo -e "   🟢 FUNCTIONAL  - Cookies fonctionnels (langue, préférences)"
    echo -e "   🔵 ANALYTICS   - Cookies d'analyse d'audience"
    echo -e "   🟡 TRACKING    - Cookies de suivi publicitaire"
    echo -e "   🔴 SESSION     - Cookies de session"
    echo -e "   ⚪ INFO        - Simple observation, pas de risque réel"
}

# ============================================================
# EXÉCUTION DES AUDITS
# ============================================================

echo -e "${BOLD}${YELLOW}[!] Début des audits sur les sites publics...${RESET}"
echo -e "${YELLOW}   (Connexion Internet requise)${RESET}"
echo ""

# Auditer chaque site
for site_name in "${!SITES[@]}"; do
    audit_site "$site_name" "${SITES[$site_name]}"
done

# Afficher le récapitulatif
print_summary

echo ""
echo -e "${BOLD}${GREEN} Tous les audits sont terminés.${RESET}"
echo -e "${GREEN}    Rapports disponibles dans : ${OUTPUT_DIR}/${RESET}"
echo -e "${GREEN}    Logs disponibles dans : ${OUTPUT_DIR}/*.log${RESET}"
echo ""
echo -e "${BOLD}${YELLOW} Note éthique :${RESET}"
echo -e "${YELLOW}   Ces tests ont été réalisés à des fins de validation technique${RESET}"
echo -e "${YELLOW}   uniquement, conformément au fichier SECURITY.md du projet.${RESET}"
echo -e "${YELLOW}   Aucun audit de sécurité de ces plateformes n'a été effectué.${RESET}"
echo ""
echo -e "${BOLD}${BLUE}Fin : $(date '+%Y-%m-%d %H:%M:%S')${RESET}"
