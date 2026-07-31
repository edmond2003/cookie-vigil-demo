#!/bin/bash
BASE_URL="http://192.168.56.3:5000"
OUTPUT_DIR="comparaison/cookievigil"
mkdir -p $OUTPUT_DIR

routes=(set-bad-cookies set-good-cookies set-weak-token set-jwt-cookie set-long-expiry set-short-expiry dashboard)

for route in "${routes[@]}"; do
  echo "=== $route ==="
  /usr/bin/time -v cookievigil "$BASE_URL/$route" \
    --format json \
    --output "$OUTPUT_DIR/${route}.json" \
    > "$OUTPUT_DIR/${route}_time.log" 2>&1
done

# Cas particulier : dashboard nécessite authentification
/usr/bin/time -v cookievigil "$BASE_URL/dashboard" \
  --session --login-url "$BASE_URL/login" \
  --login-data "username=admin&password=admin123" \
  --format json --output "$OUTPUT_DIR/dashboard.json" \
  > "$OUTPUT_DIR/dashboard_time.log" 2>&1
