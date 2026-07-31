#!/bin/bash
BASE_URL="http://192.168.56.3:5000"
OUTPUT_DIR="comparaison/zap"
ZAP_PORT=8090
mkdir -p $OUTPUT_DIR

# Démarrage du démon ZAP (clé API désactivée : usage local uniquement)
zaproxy -daemon -port $ZAP_PORT -config api.disablekey=true \
  > "$OUTPUT_DIR/zap_daemon.log" 2>&1 &
ZAP_PID=$!

echo "Attente du démarrage de ZAP..."
until curl -s "http://localhost:$ZAP_PORT/JSON/core/view/version/" > /dev/null 2>&1; do
  sleep 2
done
echo "ZAP prêt (PID $ZAP_PID)."

# Échantillonnage RAM en arrière-plan pendant toute la durée des scans
( while kill -0 $ZAP_PID 2>/dev/null; do
    ps -o rss= -p $ZAP_PID >> "$OUTPUT_DIR/ram_samples.log"
    sleep 3
  done ) &
SAMPLER_PID=$!

routes=(set-bad-cookies set-good-cookies set-weak-token set-jwt-cookie set-long-expiry set-short-expiry dashboard)

for route in "${routes[@]}"; do
  TARGET="$BASE_URL/$route"
  echo "=== $route ==="
  START=$(date +%s%N)

  SCAN_ID=$(curl -s "http://localhost:$ZAP_PORT/JSON/spider/action/scan/?url=$TARGET" | grep -oP '"scan":"\K[0-9]+')
  while true; do
    STATUS=$(curl -s "http://localhost:$ZAP_PORT/JSON/spider/view/status/?scanId=$SCAN_ID" | grep -oP '"status":"\K[0-9]+')
    [ "$STATUS" == "100" ] && break
    sleep 1
  done

  ASCAN_ID=$(curl -s "http://localhost:$ZAP_PORT/JSON/ascan/action/scan/?url=$TARGET" | grep -oP '"scan":"\K[0-9]+')
  while true; do
    ASTATUS=$(curl -s "http://localhost:$ZAP_PORT/JSON/ascan/view/status/?scanId=$ASCAN_ID" | grep -oP '"status":"\K[0-9]+')
    [ "$ASTATUS" == "100" ] && break
    sleep 2
  done

  END=$(date +%s%N)
  echo "Durée: $(( (END-START)/1000000000 ))s" >> "$OUTPUT_DIR/${route}_time.log"

  curl -s "http://localhost:$ZAP_PORT/JSON/core/view/alerts/?baseurl=$TARGET" \
    > "$OUTPUT_DIR/${route}_alerts.json"
done

kill $SAMPLER_PID 2>/dev/null
curl -s "http://localhost:$ZAP_PORT/JSON/core/action/shutdown/"
