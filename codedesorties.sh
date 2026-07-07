#!/bin/bash
# test_exit_codes_quick.sh - Version rapide

BASE_URL="http://192.168.56.3:5000"
GREEN='\033[0;32m'
RED='\033[0;31m'
BOLD='\033[1m'
RESET='\033[0m'

echo -e "${BOLD}🧪 Test des codes de sortie CookieVigil${RESET}\n"

test_exit() {
    local desc="$1"
    local cmd="$2"
    local expected="$3"
    echo -n "  $desc... "
    eval "$cmd" >/dev/null 2>&1
    actual=$?
    if [ $actual -eq $expected ]; then
        echo -e "${GREEN} OK (code $actual)${RESET}"
    else
        echo -e "${RED} ÉCHEC (attendu $expected, obtenu $actual)${RESET}"
    fi
}

echo -e "${BOLD}--- Tests --fail-on ---${RESET}"
test_exit "Mode observation (--fail-on none)" \
    "cookievigil $BASE_URL/set-bad-cookies --force-https-context --fail-on none" 0

test_exit "Blocage CRITICAL (--fail-on high)" \
    "cookievigil $BASE_URL/set-bad-cookies --force-https-context --fail-on high" 2

test_exit "Avertissement MEDIUM (--fail-on medium)" \
    "cookievigil $BASE_URL/set-long-expiry --force-https-context --fail-on medium" 1

echo -e "\n${BOLD}--- Tests --fail-score-below ---${RESET}"
test_exit "Score < 70 (--fail-score-below 70)" \
    "cookievigil $BASE_URL/set-weak-token --force-https-context --fail-score-below 70" 2

test_exit "Score >= 70 (--fail-score-below 60)" \
    "cookievigil $BASE_URL/set-good-cookies --force-https-context --fail-score-below 60" 0

echo -e "\n${BOLD} Tests terminés${RESET}"
