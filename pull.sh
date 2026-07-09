#!/bin/bash
# pull_request.sh - Simule l'ouverture d'une Pull Request vers main

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
echo -e "${BOLD}${CYAN}║       Déclenchement du pipeline GitHub Actions par PULL REQUEST   ║${RESET}"
echo -e "${BOLD}${CYAN}╚═══════════════════════════════════════════════════════════════════╝${RESET}"
echo ""

# Vérifier que nous sommes dans un dépôt Git
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    echo -e "${RED} Ce répertoire n'est pas un dépôt Git.${RESET}"
    exit 1
fi

# Vérifier la branche actuelle
CURRENT_BRANCH=$(git branch --show-current)
if [ "$CURRENT_BRANCH" = "main" ]; then
    echo -e "${YELLOW}  Vous êtes sur la branche 'main'.${RESET}"
    echo -e "${BLUE}   Pour ouvrir une Pull Request, créez d'abord une branche de fonctionnalité.${RESET}"
    echo ""
    echo -e "${YELLOW}   Voulez-vous créer une nouvelle branche ? (Y/n)${RESET}"
    read -r response
    if [[ ! "$response" =~ ^[Nn]$ ]]; then
        echo -e "${BLUE} Entrez le nom de la nouvelle branche :${RESET}"
        read -r branch_name
        if [ -z "$branch_name" ]; then
            branch_name="feature/update_$(date +%Y%m%d_%H%M%S)"
        fi
        git checkout -b "$branch_name"
        echo -e "${GREEN} Branche '$branch_name' créée.${RESET}"
        
        # Faire un petit changement pour avoir quelque chose à pousser
        echo "# $(date)" >> PUSH_TEST.txt 2>/dev/null || echo "# $(date)" > PUSH_TEST.txt
        git add PUSH_TEST.txt 2>/dev/null || true
        git commit -m "Test: Push pour déclencher PR" 2>/dev/null || true
        
        git push -u origin "$branch_name"
        echo -e "${GREEN} Branche '$branch_name' poussée.${RESET}"
        echo ""
        echo -e "${BOLD}${BLUE}🔗 Ouvrez maintenant une Pull Request sur GitHub :${RESET}"
        REPO_URL=$(git remote get-url origin 2>/dev/null | sed 's/git@github.com:/https:\/\/github.com\//' | sed 's/\.git$//')
        echo -e "${CYAN}   $REPO_URL/pull/new/$branch_name${RESET}"
        echo ""
        echo -e "${YELLOW} Dès que la PR sera ouverte, le pipeline se déclenchera.${RESET}"
        exit 0
    else
        echo -e "${BLUE}  Opération annulée.${RESET}"
        exit 0
    fi
fi

# Ici, on est sur une branche non-main
echo -e "${BOLD}${BLUE} Vérification de la branche '$CURRENT_BRANCH'...${RESET}"

# Vérifier s'il y a des modifications non poussées
if git status --porcelain | grep -q .; then
    echo -e "${YELLOW} Des modifications non commitées ont été détectées.${RESET}"
    echo -e "${BLUE}   Voulez-vous les committer et pousser ? (Y/n)${RESET}"
    read -r response
    if [[ ! "$response" =~ ^[Nn]$ ]]; then
        git add .
        git commit -m "Update avant PR"
        git push
        echo -e "${GREEN} Modifications poussées.${RESET}"
    fi
fi

echo ""
echo -e "${BOLD}${BLUE}🔗 Pour déclencher le pipeline par Pull Request :${RESET}"
echo -e "${YELLOW}   1. Ouvrez votre navigateur sur GitHub${RESET}"
echo -e "${YELLOW}   2. Créez une Pull Request de '$CURRENT_BRANCH' vers 'main'${RESET}"
REPO_URL=$(git remote get-url origin 2>/dev/null | sed 's/git@github.com:/https:\/\/github.com\//' | sed 's/\.git$//')
if [ -n "$REPO_URL" ]; then
    echo -e "${CYAN}   $REPO_URL/pull/new/main...$CURRENT_BRANCH${RESET}"
fi
echo -e "${YELLOW}   3. Le pipeline se déclenchera automatiquement${RESET}"
echo ""

# Proposition d'ouvrir la PR via gh (GitHub CLI)
if command -v gh &> /dev/null; then
    echo -e "${BLUE} GitHub CLI (gh) est disponible.${RESET}"
    echo -e "${YELLOW}   Voulez-vous ouvrir une PR avec 'gh pr create' ? (Y/n)${RESET}"
    read -r response
    if [[ ! "$response" =~ ^[Nn]$ ]]; then
        echo -e "${BLUE} Entrez le titre de la PR (ou laissez vide) :${RESET}"
        read -r pr_title
        if [ -z "$pr_title" ]; then
            pr_title="Update CookieVigil - $(date +%Y-%m-%d)"
        fi
        gh pr create --base main --title "$pr_title" --body "Pipeline déclenché automatiquement"
        echo -e "${GREEN} Pull Request créée !${RESET}"
        echo -e "${GREEN}    $REPO_URL/pull${RESET}"
    fi
fi

echo -e "\n${BOLD}${YELLOW} Le pipeline GitHub Actions est déclenché par l'événement 'pull_request'.${RESET}"
echo -e "${YELLOW}   Jobs exécutés :${RESET}"
echo -e "   ├─  tests (Tests unitaires et intégration)"
echo -e "   └─  docker-lab (Laboratoire Docker DevSecOps)"
