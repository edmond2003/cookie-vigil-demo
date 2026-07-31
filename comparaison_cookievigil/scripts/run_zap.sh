#!/bin/bash
# =====================================================================
# OWASP ZAP - Script de comparaison (version Docker)
# =====================================================================
# Corrections apportées par rapport à la version initiale :
#   1. SÉPARATION scan passif / scan actif (cf. commentaire d'origine) :
#      Le scan principal (comparaison temps/mémoire/précision) est
#      SPIDER + PASSIF uniquement. Un scan actif complémentaire est
#      proposé en option (RUN_ACTIVE_SCAN=true) mais mesuré et présenté
#      SÉPARÉMENT dans le mémoire.
#   2. Reset de session ZAP entre chaque route (newSession), pour
#      éviter que le spider d'une route ne découvre et contamine les
#      résultats avec des liens vers d'autres routes.
#   3. Parsing avec jq au lieu de grep -oP (plus robuste).
#   4. Boucle de répétitions (REPEATS, défaut 5).
#   5. Utilisation de accessUrl au lieu de spider pour garantir la visite.
#   6. Dashboard exclu car nécessite authentification.
#
#   CORRECTIONS 2026-07-22 (v2 - Docker) :
#   - ZAP lancé via Docker (ghcr.io/zaproxy/zaproxy:stable) au lieu du
#     binaire Kali, dont plusieurs add-ons (oast, scripts, client,
#     authhelper, fuzz) échouaient à s'initialiser
#     (NoClassDefFoundError sur Jackson/JDO), provoquant un crash de
#     l'API sur core/action/newSession.
#   - --network host pour que le conteneur atteigne directement
#     192.168.56.3 (réseau host-only VirtualBox) sans NAT Docker.
#   - reset_session() avec vérification explicite de la réponse API
#     au lieu de compter sur `set -e` (qui tuait le script en silence
#     à la moindre erreur transitoire de l'API).
#   - trap EXIT/ERR pour garantir l'arrêt + la suppression du
#     conteneur ZAP même en cas de plantage du script.
#   - Échantillonnage mémoire via `docker stats` au lieu de `ps -o rss=`
#     (le process Java tourne maintenant dans le conteneur).
# =====================================================================
set -uo pipefail   # note : -e retiré volontairement, les erreurs API
                    # sont désormais gérées explicitement (voir reset_session)

command -v jq >/dev/null 2>&1 || { echo "jq est requis (sudo apt install jq)"; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "docker est requis"; exit 1; }

BASE_URL="${BASE_URL:-http://192.168.56.3:5000}"
REPEATS="${REPEATS:-5}"
ZAP_PORT="${ZAP_PORT:-8090}"
ZAP_IMAGE="${ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy:stable}"
CONTAINER_NAME="${CONTAINER_NAME:-zap_comparaison}"
RUN_ACTIVE_SCAN="${RUN_ACTIVE_SCAN:-false}"
OUTPUT_DIR="comparaison/zap"
mkdir -p "$OUTPUT_DIR"

# dashboard exclu car nécessite authentification pour des tests équitables
routes=(set-bad-cookies set-good-cookies set-weak-token set-jwt-cookie set-long-expiry set-short-expiry)

SAMPLER_PID=""

# ---------------------------------------------------------------------
# Nettoyage garanti (conteneur + sampler) même en cas d'erreur/Ctrl+C
# ---------------------------------------------------------------------
cleanup() {
    echo
    echo "Nettoyage..."
    [ -n "$SAMPLER_PID" ] && kill "$SAMPLER_PID" 2>/dev/null || true
    docker stop "$CONTAINER_NAME" >/dev/null 2>&1 || true
    docker rm "$CONTAINER_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# ---------------------------------------------------------------------
# Fonction API avec encodage correct des paramètres
# ---------------------------------------------------------------------
zap_api() {
  local path="$1"
  shift
  local query=""
  for arg in "$@"; do
    query="${query} --data-urlencode ${arg}"
  done
  eval curl -s --fail "http://localhost:${ZAP_PORT}/JSON/${path}" ${query} 2>/dev/null
}

# ---------------------------------------------------------------------
# Reset de session avec vérification explicite (au lieu de set -e)
# ---------------------------------------------------------------------
reset_session() {
  local resp
  resp=$(curl -s --fail \
    "http://localhost:${ZAP_PORT}/JSON/core/action/newSession/?name=&overwrite=true" 2>/dev/null)
  if [ $? -ne 0 ] || ! echo "$resp" | jq -e '.Result == "OK"' >/dev/null 2>&1; then
    echo "  ⚠ Échec du reset de session ZAP, réponse : $resp" >&2
    return 1
  fi
  return 0
}

# ---------------------------------------------------------------------
# Fonction pour attendre la fin du scan passif
# ---------------------------------------------------------------------
wait_for_passive_scan() {
  local max_wait=30
  local waited=0
  while [ $waited -lt $max_wait ]; do
    local records=$(curl -s "http://localhost:${ZAP_PORT}/JSON/pscan/view/recordsToScan/" | jq -r '.recordsToScan // "0"')
    if [ "$records" = "0" ]; then
      return 0
    fi
    sleep 1
    waited=$((waited + 1))
  done
  echo "  Timeout scan passif" >&2
  return 1
}

# ---------------------------------------------------------------------
# Démarrage du conteneur ZAP
# ---------------------------------------------------------------------
echo "Nettoyage d'un éventuel conteneur précédent..."
docker stop "$CONTAINER_NAME" >/dev/null 2>&1 || true
docker rm "$CONTAINER_NAME" >/dev/null 2>&1 || true

echo "Démarrage du démon ZAP via Docker (clé API désactivée : usage local uniquement)..."
docker run -d --name "$CONTAINER_NAME" --network host \
  "$ZAP_IMAGE" \
  zap.sh -daemon -host 0.0.0.0 -port "$ZAP_PORT" -config api.disablekey=true \
  > "$OUTPUT_DIR/zap_daemon_container_id.log" 2>&1

echo "Attente du démarrage de ZAP..."
until curl -s --fail "http://localhost:${ZAP_PORT}/JSON/core/view/version/" > /dev/null 2>&1; do
  sleep 2
done
echo "ZAP prêt (conteneur $CONTAINER_NAME)."
sleep 5   # laisse le temps aux sous-systèmes internes (session, pscan...) de charger

for i in $(seq 1 "$REPEATS"); do
  RUN_DIR="$OUTPUT_DIR/run_${i}"
  mkdir -p "$RUN_DIR"

  # Échantillonnage mémoire en arrière-plan pendant ce run (via docker stats)
  : > "$RUN_DIR/ram_samples.log"
  ( while docker inspect -f '{{.State.Running}}' "$CONTAINER_NAME" 2>/dev/null | grep -q true; do
      docker stats "$CONTAINER_NAME" --no-stream --format "{{.MemUsage}}" \
        | awk -F'/' '{print $1}' >> "$RUN_DIR/ram_samples.log" 2>/dev/null || true
      sleep 1
    done ) &
  SAMPLER_PID=$!

  for route in "${routes[@]}"; do
    TARGET="$BASE_URL/$route"
    echo "=== [run $i] $route ==="

    # Reset de session pour ne pas contaminer les résultats entre routes
    if ! reset_session; then
      echo "  → tentative 2 après pause de 3s..." >&2
      sleep 3
      if ! reset_session; then
        echo "  → abandon de cette route" >&2
        continue
      fi
    fi

    START=$(date +%s%N)

    echo "  Visite de $TARGET..."
    if ! zap_api "core/action/accessUrl" "url=$TARGET" > /dev/null; then
      echo "   Erreur lors de la visite" >&2
      continue
    fi

    # Attendre la fin du scan passif
    wait_for_passive_scan

    END=$(date +%s%N)
    DURATION=$(( (END-START)/1000000000 ))
    echo "Durée (access+passif): ${DURATION}s" > "$RUN_DIR/${route}_time.log"

    # Récupérer les alertes
    zap_api "core/view/alerts" "baseurl=$TARGET" > "$RUN_DIR/${route}_alerts.json" 2>/dev/null || echo '{"alerts":[]}' > "$RUN_DIR/${route}_alerts.json"

    # Récupérer les messages HTTP pour vérification
    zap_api "core/view/messages" "baseurl=$TARGET" > "$RUN_DIR/${route}_messages.json" 2>/dev/null || echo '{"messages":[]}' > "$RUN_DIR/${route}_messages.json"

    # Récupérer les URL découvertes
    zap_api "core/view/urls" > "$RUN_DIR/${route}_urls.json" 2>/dev/null || echo '[]' > "$RUN_DIR/${route}_urls.json"

    if [ "$RUN_ACTIVE_SCAN" == "true" ]; then
      ASTART=$(date +%s%N)
      echo "  Scan actif..."
      SCAN_RESP=$(zap_api "ascan/action/scan" "url=$TARGET")
      ASCAN_ID=$(echo "$SCAN_RESP" | jq -r '.scan // ""')
      if [ -n "$ASCAN_ID" ] && [ "$ASCAN_ID" != "null" ]; then
        while true; do
          ASTATUS=$(curl -s "http://localhost:${ZAP_PORT}/JSON/ascan/view/status/?scanId=${ASCAN_ID}" | jq -r '.status // "0"')
          [ "$ASTATUS" = "100" ] && break
          sleep 2
        done
        AEND=$(date +%s%N)
        echo "Durée (scan actif): $(( (AEND-ASTART)/1000000000 ))s" > "$RUN_DIR/${route}_active_time.log"
        zap_api "core/view/alerts" "baseurl=$TARGET" > "$RUN_DIR/${route}_alerts_full.json" 2>/dev/null || echo '{"alerts":[]}' > "$RUN_DIR/${route}_alerts_full.json"
      fi
    fi
  done

  kill "$SAMPLER_PID" 2>/dev/null || true
  SAMPLER_PID=""
done

zap_api "core/action/shutdown" > /dev/null
echo "Terminé. Résultats dans $OUTPUT_DIR/run_1 .. run_${REPEATS}"
# Le trap cleanup se charge d'arrêter/supprimer le conteneur à la sortie.
