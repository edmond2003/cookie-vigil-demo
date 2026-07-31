#!/bin/bash
# =====================================================================
# Nikto - Campagne de comparaison (CORRIGÉ)
# =====================================================================
# CORRECTION : Utilisation de -id pour forcer Nikto à scanner
# la route spécifique au lieu de la racine.
# =====================================================================

set -uo pipefail

BASE_URL="${BASE_URL:-http://192.168.56.3:5000}"
REPEATS="${REPEATS:-5}"

OUTPUT_DIR="comparaison/nikto"
mkdir -p "$OUTPUT_DIR"

routes=(
    set-bad-cookies
    set-good-cookies
    set-weak-token
    set-jwt-cookie
    set-long-expiry
    set-short-expiry
    # dashboard supprimé car nécessite authentification
)

echo
echo "==========================================="
echo " Nikto - Lancement des comparaisons"
echo "==========================================="
echo

for ((i=1;i<=REPEATS;i++)); do

    echo
    echo "###########################################"
    echo "RUN $i / $REPEATS"
    echo "###########################################"

    RUN_DIR="$OUTPUT_DIR/run_$i"
    mkdir -p "$RUN_DIR"

    for route in "${routes[@]}"; do

        echo
        echo "Analyse : $route"

        # CORRECTION : Utiliser -id pour forcer la route comme identifiant
        # et -mutate 1 pour limiter les tests aux chemins relatifs
        printf "n\n" | \
        /usr/bin/time -v \
        nikto \
            -h "$BASE_URL/$route" \
            -id "$BASE_URL/$route" \
            -Tuning 4 \
            -Format json \
            -nointeractive \
            -nossl \
            -output "$RUN_DIR/${route}.json" \
            >"$RUN_DIR/${route}_time.log" 2>&1

        status=$?

        if [ $status -ne 0 ] && [ $status -ne 130 ]; then
            echo "⚠ Nikto a retourné le code $status pour $route"
        else
            echo "✓ terminé"
        fi

    done

done

echo
echo "==========================================="
echo "Toutes les campagnes Nikto sont terminées."
echo "Résultats disponibles dans :"
echo "    $OUTPUT_DIR"
echo
echo "NB :"
echo "Nikto est un scanner Web généraliste."
echo "Les fichiers JSON contiendront beaucoup de résultats"
echo "qui ne concernent pas les cookies."
echo
echo "normalize_metrics.py filtrera automatiquement"
echo "uniquement les résultats liés aux cookies."
echo "==========================================="
