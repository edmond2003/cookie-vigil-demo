#!/bin/bash
BASE_URL="http://192.168.56.3:5000"
OUTPUT_DIR="comparaison/nikto"
mkdir -p $OUTPUT_DIR

routes=(set-bad-cookies set-good-cookies set-weak-token set-jwt-cookie set-long-expiry set-short-expiry dashboard)

for route in "${routes[@]}"; do
  echo "=== $route ==="
  /usr/bin/time -v nikto -h "$BASE_URL/$route" -Format json \
    -output "$OUTPUT_DIR/${route}.json" \
    > "$OUTPUT_DIR/${route}_time.log" 2>&1
done
