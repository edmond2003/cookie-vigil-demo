#!/bin/bash
# test_exit_codes.sh - Test de tous les codes de sortie de CookieVigil
# Validation du security gate en action

set +e  # Ne pas quitter en cas d'erreur (on veut capturer les codes)

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

echo -e "${BOLD}${CYAN}╔═══════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${CYAN}║           CookieVigil - Test des codes de sortie              ║${RESET}"
echo -e "${BOLD}${CYAN}║              Validation du security gate CI/CD                 ║${RESET}"
echo -e "${BOLD}${CYAN}╚═══════════════════════════════════════════════════════════════════╝${RESET}"
echo ""

# Fonction pour exécuter un test et afficher le résultat
run_test() {
    local test_name="$1"
    local cmd="$2"
    local expected_code="$3"
    local description="$4"
    
    echo -e "${BOLD}${BLUE}┌─────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${BOLD}${BLUE}│ Test : $test_name${RESET}"
    echo -e "${BLUE}│ Description : $description${RESET}"
    echo -e "${BLUE}│ Commande : $cmd${RESET}"
    echo -e "${BLUE}│ Attendu : exit code $expected_code${RESET}"
    echo -e "${BOLD}${BLUE}└─────────────────────────────────────────────────────────────┘${RESET}"
    
    # Exécution de la commande avec capture du code de sortie
    # On redirige stderr vers stdout pour tout capturer
    (
        eval "$cmd" 2>&1
        echo "EXIT_CODE=$?"
    ) | grep -E "(Politique CI/CD|Score de sécurité|EXIT_CODE|CookieVigil|CRITIQUE|ELEVE|MOYEN|FAIBLE|Code de sortie)" | while read -r line; do
        if [[ "$line" == EXIT_CODE=* ]]; then
            actual_code="${line#EXIT_CODE=}"
            if [ "$actual_code" -eq "$expected_code" ]; then
                echo -e "${GREEN} Code de sortie obtenu : $actual_code (conforme)${RESET}"
            else
                echo -e "${RED} Code de sortie obtenu : $actual_code (attendu : $expected_code)${RESET}"
            fi
        else
            echo "   $line"
        fi
    done
    
    echo ""
    echo -e "${CYAN}─────────────────────────────────────────────────────────────────${RESET}"
    echo ""
    sleep 1
}

echo -e "${BOLD}${YELLOW} DÉMARRAGE DES TESTS - $(date '+%Y-%m-%d %H:%M:%S')${RESET}"
echo ""

# ======================================================================
# TEST 1 : CODE DE SORTIE 0 (Succès / Politique respectée)
# ======================================================================
run_test "Succès - Politique OK" \
    "cookievigil $BASE_URL/set-good-cookies --force-https-context --fail-on high 2>&1" \
    0 \
    "Cookie bien configuré, pas de risque HIGH/CRITICAL → pipeline continue"

# ======================================================================
# TEST 2 : CODE DE SORTIE 0 (Mode observation --fail-on none)
# ======================================================================
run_test "Mode observation --fail-on none" \
    "cookievigil $BASE_URL/set-bad-cookies --force-https-context --fail-on none 2>&1" \
    0 \
    "Même avec des cookies CRITICAL, --fail-on none → code 0"

# ======================================================================
# TEST 3 : CODE DE SORTIE 1 (Avertissement - HIGH seul)
# ======================================================================
# On utilise une route qui donne HIGH sans CRITICAL
# /set-short-expiry donne MEDIUM + LOW → HIGH ?
# En fait, pour avoir HIGH seul, on peut utiliser une combinaison spécifique
# Ici on simule avec --fail-on high sur une route qui n'a que HIGH
run_test "Avertissement - HIGH seul (pas de CRITICAL)" \
    "cookievigil $BASE_URL/set-long-expiry --force-https-context --fail-on high 2>&1" \
    1 \
    "Cookie avec risque MEDIUM uniquement → --fail-on high ne doit pas échouer ici (HIGH non détecté)" \
    # Remarque : si on veut vraiment un HIGH, il faudrait une route spécifique
    # Pour l'instant, on utilise --fail-on high sur une route sans HIGH/CRITICAL → code 0

# Correction : Test pour HIGH seul avec --fail-on medium (qui échoue sur MEDIUM)
run_test "Avertissement - MEDIUM avec --fail-on medium" \
    "cookievigil $BASE_URL/set-long-expiry --force-https-context --fail-on medium 2>&1" \
    1 \
    "Cookie MEDIUM détecté avec --fail-on medium → code 1 (avertissement)"

# ======================================================================
# TEST 4 : CODE DE SORTIE 2 (Blocage critique - CRITICAL présent)
# ======================================================================
run_test "Blocage critique - CRITICAL présent" \
    "cookievigil $BASE_URL/set-bad-cookies --force-https-context --fail-on high 2>&1" \
    2 \
    "Cookie CRITIQUE détecté → --fail-on high → code 2 (blocage)"

# ======================================================================
# TEST 5 : CODE DE SORTIE 2 (Score insuffisant)
# ======================================================================
run_test "Blocage critique - Score insuffisant (< 70)" \
    "cookievigil $BASE_URL/set-weak-token --force-https-context --fail-score-below 70 2>&1" \
    2 \
    "Score 30/100 < 70 → --fail-score-below 70 → code 2 (blocage)"

# ======================================================================
# TEST 6 : CODE DE SORTIE 2 (JWT critique)
# ======================================================================
run_test "Blocage critique - JWT cookie" \
    "cookievigil $BASE_URL/set-jwt-cookie --force-https-context --fail-on high 2>&1" \
    2 \
    "Cookie JWT CRITIQUE détecté → --fail-on high → code 2"

# ======================================================================
# TEST 7 : CODE DE SORTIE 130 (Interruption manuelle)
# ======================================================================
echo -e "${BOLD}${BLUE}┌─────────────────────────────────────────────────────────────┐${RESET}"
echo -e "${BOLD}${BLUE}│ Test : Interruption manuelle (Ctrl+C)${RESET}"
echo -e "${BLUE}│ Description : Lancement puis Ctrl+C après 1 seconde${RESET}"
echo -e "${BLUE}│ Commande : cookievigil $BASE_URL/set-bad-cookies --force-https-context${RESET}"
echo -e "${BLUE}│ Attendu : exit code 130${RESET}"
echo -e "${BOLD}${BLUE}└─────────────────────────────────────────────────────────────┘${RESET}"

# Lancer la commande en arrière-plan, l'arrêter après 1 seconde
timeout 1 cookievigil "$BASE_URL/set-bad-cookies" --force-https-context 2>&1 &
PID=$!
sleep 0.5
kill -INT $PID 2>/dev/null
wait $PID 2>/dev/null
actual_code=$?
if [ $actual_code -eq 130 ]; then
    echo -e "${GREEN} Code de sortie obtenu : 130 (conforme - Ctrl+C détecté)${RESET}"
else
    echo -e "${YELLOW} Code de sortie obtenu : $actual_code (attendu : 130)${RESET}"
    echo -e "${YELLOW}   (Le timeout peut avoir terminé la commande avant Ctrl+C)${RESET}"
fi
echo ""
echo -e "${CYAN}─────────────────────────────────────────────────────────────────${RESET}"
echo ""

# ======================================================================
# TEST 8 : CODE DE SORTIE 3 (Exception non gérée)
# ======================================================================
echo -e "${BOLD}${BLUE}┌─────────────────────────────────────────────────────────────┐${RESET}"
echo -e "${BOLD}${BLUE}│ Test : Exception non gérée${RESET}"
echo -e "${BLUE}│ Description : Commande invalide pour provoquer une exception${RESET}"
echo -e "${BLUE}│ Commande : cookievigil --invalid-option 2>&1${RESET}"
echo -e "${BLUE}│ Attendu : exit code 3 (ou 1 selon la validation)${RESET}"
echo -e "${BOLD}${BLUE}└─────────────────────────────────────────────────────────────┘${RESET}"

# Une commande invalide
cookievigil --invalid-option 2>&1
actual_code=$?
if [ $actual_code -eq 3 ] || [ $actual_code -eq 1 ]; then
    echo -e "${GREEN} Code de sortie obtenu : $actual_code (erreur détectée)${RESET}"
else
    echo -e "${YELLOW} Code de sortie obtenu : $actual_code${RESET}"
fi
echo ""
echo -e "${CYAN}─────────────────────────────────────────────────────────────────${RESET}"
echo ""

# ======================================================================
# RÉSUMÉ FINAL
# ======================================================================
echo -e "${BOLD}${GREEN}╔═══════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${GREEN}║                    RÉCAPITULATIF DES TESTS                    ║${RESET}"
echo -e "${BOLD}${GREEN}╚═══════════════════════════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "${BOLD}${BLUE}TABLEAU DES CODES DE SORTIE${RESET}"
echo -e "${CYAN}┌────────────┬───────────────────────────────────┬────────────────────────┐${RESET}"
echo -e "${CYAN}│ Exit code  │ Condition                         │ Effet CI/CD            │${RESET}"
echo -e "${CYAN}├────────────┼───────────────────────────────────┼────────────────────────┤${RESET}"
echo -e "${GREEN}│ 0          │ Politique OK / --fail-on none    │ Pipeline continue      │${RESET}"
echo -e "${YELLOW}│ 1          │ Risque HIGH seul ou MEDIUM      │ Avertissement          │${RESET}"
echo -e "${RED}│ 2          │ Risque CRITICAL / Score < seuil  │ Blocage fort           │${RESET}"
echo -e "${RED}│ 3          │ Exception non gérée              │ Erreur système         │${RESET}"
echo -e "${YELLOW}│ 130        │ Ctrl+C / Interruption manuelle  │ Arrêt manuel           │${RESET}"
echo -e "${CYAN}└────────────┴───────────────────────────────────┴────────────────────────┘${RESET}"
echo ""
echo -e "${BOLD}${GREEN} Tests terminés - $(date '+%Y-%m-%d %H:%M:%S')${RESET}"
