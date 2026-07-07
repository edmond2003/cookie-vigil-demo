#!/bin/bash
# push.sh - Simule un push vers la branche main pour déclencher le pipeline GitHub Actions

set -e

# Couleurs
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
RED='\033[0;31m'
BOLD='\033[1m'
RESET='\033[0m'

echo -e "${BOLD}${CYAN}╔═══════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${CYAN}║        Déclenchement du pipeline GitHub Actions par PUSH         ║${RESET}"
echo -e "${BOLD}${CYAN}╚═══════════════════════════════════════════════════════════════════╝${RESET}"
echo ""

# Vérifier que nous sommes dans un dépôt Git
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    echo -e "${RED} Ce répertoire n'est pas un dépôt Git.${RESET}"
    exit 1
fi

# Vérifier la branche actuelle
CURRENT_BRANCH=$(git branch --show-current)
if [ "$CURRENT_BRANCH" != "main" ]; then
    echo -e "${YELLOW}  Vous êtes sur la branche '$CURRENT_BRANCH', pas sur 'main'.${RESET}"
    echo -e "${YELLOW}   Voulez-vous continuer ? (y/N)${RESET}"
    read -r response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        echo -e "${BLUE}  Opération annulée.${RESET}"
        exit 0
    fi
fi

# Vérifier s'il y a des modifications à committer
if git status --porcelain | grep -q .; then
    echo -e "${YELLOW} Des modifications non commitées ont été détectées.${RESET}"
    echo -e "${BLUE}   Fichiers modifiés :${RESET}"
    git status --porcelain | sed 's/^/   /'
    echo ""
    echo -e "${YELLOW}   Voulez-vous les committer avant de pousser ? (Y/n)${RESET}"
    read -r response
    if [[ ! "$response" =~ ^[Nn]$ ]]; then
        echo -e "${BLUE} Entrez le message de commit (ou laissez vide pour 'Update CookieVigil'):${RESET}"
        read -r commit_msg
        if [ -z "$commit_msg" ]; then
            commit_msg="Update CookieVigil"
        fi
        git add .
        git commit -m "$commit_msg"
        echo -e "${GREEN} Commit effectué : $commit_msg${RESET}"
    fi
fi

echo ""
echo -e "${BOLD}${BLUE} Déclenchement du pipeline par git push...${RESET}"
echo -e "${CYAN}▶ git push origin main${RESET}"
echo ""

# Exécution du push
if git push origin main; then
    echo ""
    echo -e "${GREEN} Push effectué avec succès.${RESET}"
    echo -e "${GREEN}    Voir le pipeline sur GitHub :${RESET}"
    REPO_URL=$(git remote get-url origin 2>/dev/null | sed 's/git@github.com:/https:\/\/github.com\//' | sed 's/\.git$//')
    if [ -n "$REPO_URL" ]; then
        echo -e "${CYAN}   $REPO_URL/actions${RESET}"
    fi
    echo ""
    echo -e "${BOLD}${YELLOW} Le pipeline GitHub Actions est maintenant déclenché.${RESET}"
    echo -e "${YELLOW}   Jobs exécutés :${RESET}"
    echo -e "   ├─  tests (Tests unitaires et intégration)"
    echo -e "   └─  docker-lab (Laboratoire Docker DevSecOps)"
    echo -e "${YELLOW}    Attendez environ 1 minute pour voir les résultats.${RESET}"
else
    echo ""
    echo -e "${RED} Le push a échoué.${RESET}"
    echo -e "${YELLOW}   Vérifiez que vous avez les droits d'écriture sur le dépôt.${RESET}"
    exit 1
fi
