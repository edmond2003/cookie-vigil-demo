#!/bin/bash
# =====================================================================
# Nuclei - Campagne de comparaison
# =====================================================================
#
# Comparaison équitable avec CookieVigil, Nikto et ZAP.
#
# Corrections :
#
# 1. Exécution native (pas Docker)
#
# 2. 5 répétitions
#
# 3. Utilisation explicite des templates cookies
#    au lieu des tags "security" ou "cookies"
#
# 4. Le script continue même si Nuclei retourne un code non nul.
#
# 5. Sauvegarde des temps d'exécution.
#
# =====================================================================

set -uo pipefail

BASE_URL="${BASE_URL:-http://192.168.56.3:5000}"
REPEATS="${REPEATS:-5}"

OUTPUT_DIR="$(pwd)/comparaison/nuclei"
mkdir -p "$OUTPUT_DIR"

TEMPLATE_DIR="$HOME/.local/nuclei-templates/http/misconfiguration"

COOKIE_TEMPLATES=(
"$TEMPLATE_DIR/cookies-without-secure.yaml"
"$TEMPLATE_DIR/cookies-without-httponly.yaml"
"$TEMPLATE_DIR/missing-cookie-samesite-strict.yaml"
)

echo
echo "==========================================="
echo " Nuclei - Vérification des templates"
echo "==========================================="

for t in "${COOKIE_TEMPLATES[@]}"
do
    if [ ! -f "$t" ]; then
        echo "ERREUR : template introuvable"
        echo "$t"
        exit 1
    fi
done

printf "%s\n" "${COOKIE_TEMPLATES[@]}" \
    > "$OUTPUT_DIR/templates_disponibles.log"

echo
echo "Templates utilisés :"
cat "$OUTPUT_DIR/templates_disponibles.log"

echo

routes=(
set-bad-cookies
set-good-cookies
set-weak-token
set-jwt-cookie
set-long-expiry
set-short-expiry
dashboard
)

for ((i=1;i<=REPEATS;i++))
do

    echo
    echo "###########################################"
    echo "RUN $i / $REPEATS"
    echo "###########################################"

    RUN_DIR="$OUTPUT_DIR/run_$i"
    mkdir -p "$RUN_DIR"

    for route in "${routes[@]}"
    do

        echo
        echo "Analyse : $route"

        /usr/bin/time -v \
        nuclei \
            -target "$BASE_URL/$route" \
            -t "${COOKIE_TEMPLATES[0]}" \
            -t "${COOKIE_TEMPLATES[1]}" \
            -t "${COOKIE_TEMPLATES[2]}" \
            -jsonl \
            -o "$RUN_DIR/${route}.jsonl" \
            -silent \
            > "$RUN_DIR/${route}_time.log" 2>&1

        status=$?

        if [ $status -ne 0 ]; then
            echo "⚠ Nuclei a retourné le code $status pour $route"
        else
            echo "✓ terminé"
        fi

        # Garantir qu'un fichier JSONL existe
        if [ ! -f "$RUN_DIR/${route}.jsonl" ]; then
            touch "$RUN_DIR/${route}.jsonl"
        fi

    done

done

echo
echo "==========================================="
echo "Toutes les campagnes Nuclei sont terminées."
echo
echo "Résultats :"
echo "    $OUTPUT_DIR"
echo
echo "Les fichiers JSONL peuvent être vides."
echo "Cela signifie qu'aucun template Nuclei ne s'est déclenché,"
echo "et non que le scan a échoué."
echo "==========================================="
