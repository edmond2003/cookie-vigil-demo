#!/bin/bash
BASE_URL="http://192.168.56.3:5000"
OUTPUT_DIR="$(pwd)/comparaison/nuclei"
mkdir -p $OUTPUT_DIR

# Vérifier d'abord que des templates "cookies" existent réellement
docker run --rm projectdiscovery/nuclei:latest -tl -tags cookies 2>&1 | tee "$OUTPUT_DIR/templates_disponibles.log"

routes=(set-bad-cookies set-good-cookies set-weak-token set-jwt-cookie set-long-expiry set-short-expiry dashboard)

for route in "${routes[@]}"; do
  echo "=== $route ==="
  /usr/bin/time -v docker run --rm --network host \
    -v "$OUTPUT_DIR":/output \
    projectdiscovery/nuclei:latest \
    -target "$BASE_URL/$route" \
    -tags cookies \
    -jsonl -o "/output/${route}.jsonl" \
    > "$OUTPUT_DIR/${route}_time.log" 2>&1
done
