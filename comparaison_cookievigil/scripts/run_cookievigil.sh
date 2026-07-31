#!/bin/bash
# =====================================================================
# CookieVigil - Campagne de comparaison (CORRIGÉ)
# =====================================================================
# CORRECTION 2026-07-22 :
#   CookieVigil préfixe en interne un dossier "reports/" devant le
#   chemin fourni via --output, sans jamais créer ce dossier lui-même
#   (os.makedirs manquant côté outil), ce qui faisait échouer
#   silencieusement l'écriture du rapport JSON sur TOUTES les routes
#   et TOUS les runs (le script ne relevait que le code retour, sans
#   vérifier qu'un fichier .json avait bien été produit).
#   -> On crée désormais le dossier miroir sous reports/ avant chaque
#      appel, PUIS on copie le fichier produit vers l'emplacement
#      attendu par normalize_metrics.py (comparaison/cookievigil/...),
#      qui lui ne connaît pas le préfixe reports/.
#   -> On vérifie aussi explicitement la présence du fichier après
#      coup, au lieu de se fier uniquement au code de sortie.
# =====================================================================

set -uo pipefail

BASE_URL="${BASE_URL:-http://192.168.56.3:5000}"
REPEATS="${REPEATS:-5}"

OUTPUT_DIR="comparaison/cookievigil"
mkdir -p "$OUTPUT_DIR"

routes=(
    set-bad-cookies
    set-good-cookies
    set-weak-token
    set-jwt-cookie
    set-long-expiry
    set-short-expiry
)

# ---------------------------------------------------------------------
# Fonction utilitaire : exécute cookievigil, crée le dossier reports/
# nécessaire en interne, puis copie le rapport au bon endroit pour
# normalize_metrics.py. Vérifie explicitement le résultat.
# ---------------------------------------------------------------------
run_cookievigil() {
    local target="$1"
    local output_path="$2"   # ex: comparaison/cookievigil/run_1/set-bad-cookies
    local time_log="$3"
    shift 3
    local extra_args=("$@")

    # CookieVigil écrit en réalité dans reports/<output_path>.json
    mkdir -p "reports/$(dirname "$output_path")"

    /usr/bin/time -v \
    cookievigil \
        "$target" \
        --format json \
        --force-https-context \
        --output "$output_path" \
        "${extra_args[@]}" \
        >"$time_log" 2>&1

    local status=$?

    local produced="reports/${output_path}.json"
    local expected="${output_path}.json"

    if [ -f "$produced" ]; then
        cp "$produced" "$expected"
    fi

    if [ $status -ne 0 ] || [ ! -f "$expected" ]; then
        echo "⚠ Échec (code $status) ou fichier manquant pour $output_path"
        return 1
    fi

    echo "✓ terminé"
    return 0
}

echo
echo "==========================================="
echo " CookieVigil - Lancement des comparaisons"
echo "==========================================="
echo

for ((i=1;i<=REPEATS;i++)); do

    echo
    echo "###########################################"
    echo "RUN $i / $REPEATS"
    echo "###########################################"

    RUN_DIR="$OUTPUT_DIR/run_$i"
    mkdir -p "$RUN_DIR"

    ############################################################
    # Routes publiques
    ############################################################

    for route in "${routes[@]}"; do
        echo
        echo "Analyse : $route"
        run_cookievigil \
            "$BASE_URL/$route" \
            "$RUN_DIR/$route" \
            "$RUN_DIR/${route}_time.log"
    done

    ############################################################
    # Dashboard authentifié
    ############################################################

    echo
    echo "Analyse : dashboard"
    run_cookievigil \
        "$BASE_URL/dashboard" \
        "$RUN_DIR/dashboard" \
        "$RUN_DIR/dashboard_time.log" \
        --session \
        --login-url "$BASE_URL/login" \
        --login-data "username=admin&password=admin123"

done

echo
echo "==========================================="
echo "Toutes les campagnes sont terminées."
echo "Résultats disponibles dans :"
echo "    $OUTPUT_DIR"
echo "==========================================="
