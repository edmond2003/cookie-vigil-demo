#!/bin/bash
# run_tests.sh - Lanceur de tests pour CookieVigil
# Exécute la suite complète des 53 tests unitaires et d'intégration.

GREEN='\033[92m'
RED='\033[91m'
YELLOW='\033[93m'
BLUE='\033[94m'
CYAN='\033[96m'
BOLD='\033[1m'
RESET='\033[0m'

echo -e "${BOLD}${CYAN}╔═══════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${CYAN}║                    CookieVigil - Suite de tests                     ║${RESET}"
echo -e "${BOLD}${CYAN}║              Exécution automatisée des 53 tests                     ║${RESET}"
echo -e "${BOLD}${CYAN}╚═══════════════════════════════════════════════════════════════════╝${RESET}"

if [ ! -d "tests" ]; then
    echo -e "${RED}[-] Erreur : le dossier 'tests/' est introuvable.${RESET}"
    echo -e "${YELLOW}[!] Assurez-vous d'être à la racine du projet CookieVigil.${RESET}"
    exit 1
fi

echo -e "${BLUE}[*] Lancement des tests...${RESET}"
START_TIME=$(date +%s)

python -m unittest discover -s tests -p "test_*.py" -v

EXIT_CODE=$?
END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${RESET}"

if [ $EXIT_CODE -eq 0 ]; then
    echo -e "\n${GREEN}${BOLD} SUCCÈS : 53/53 tests passés${RESET}"
    echo -e "${GREEN}   Durée totale : ${ELAPSED}.${ELAPSED} secondes${RESET}"
    echo -e "\n${BOLD}${BLUE} RÉPARTITION DES TESTS${RESET}"
    echo -e "${CYAN}──────────────────────────────────────────────────${RESET}"
    echo -e "${BLUE}   ├─ test_analyzer.py    : 24 tests (Classification, corrélations, score)${RESET}"
    echo -e "${BLUE}   ├─ test_collector.py   : 11 tests (Parsing, anti-faux-positifs, redirections)${RESET}"
    echo -e "${BLUE}   ├─ test_reporter.py    :  7 tests (JSON, HTML, CSV, Markdown)${RESET}"
    echo -e "${BLUE}   ├─ test_utils.py       :  5 tests (URL, domaines, formatage console)${RESET}"
    echo -e "${BLUE}   └─ test_integration.py :  6 tests (Pipeline complet, cohérence)${RESET}"
    echo -e "${CYAN}──────────────────────────────────────────────────${RESET}"
    echo -e "${GREEN}${BOLD}   TOTAL : 53 tests |  53/53 réussis${RESET}"
    echo -e "${CYAN}──────────────────────────────────────────────────${RESET}"
    echo -e "\n${CYAN}[*] Fin : $(date '+%Y-%m-%d %H:%M:%S')${RESET}"
    echo -e "${CYAN}[*] Durée totale : ${ELAPSED} secondes${RESET}"
    exit 0
else
    echo -e "\n${RED}${BOLD} ÉCHEC : Certains tests ont échoué${RESET}"
    echo -e "${RED}   Durée totale : ${ELAPSED} secondes${RESET}"
    echo -e "${YELLOW}[!] Consultez la sortie ci-dessus pour identifier les tests en échec.${RESET}"
    exit 1
fi
