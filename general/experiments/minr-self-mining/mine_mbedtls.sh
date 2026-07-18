#!/bin/sh
# Mine mbedTLS releases into the same LDB KB the FreeRTOS baseline used, so the
# marginal (delta) allocated size per additional component can be measured.
# Tag set covers the corpus ground truth (esp-idf ~v3.6.2, ST ~v3.6.6,
# NXP ~2.28.10, synthetic v3.5.0+v3.6.0) plus near neighbors.
#
# Note: mbedTLS 3.x is dual-licensed "Apache-2.0 OR GPL-2.0-or-later", but the
# -d metadata is comma-separated so the declared field is simplified to
# Apache-2.0 here; the per-file license table carries minr's own detection.
set -eu

TAGS="v2.28.8 v2.28.9 v2.28.10 v3.5.0 v3.5.2 v3.6.0 v3.6.1 v3.6.2 v3.6.3 v3.6.4 v3.6.5 v3.6.6"

cd /work

for TAG in $TAGS; do
    VERSION=${TAG#v}
    DATE=$(curl -sf "https://api.github.com/repos/Mbed-TLS/mbedtls/releases/tags/$TAG" \
           | jq -r '.published_at // empty' | cut -dT -f1)
    [ -n "$DATE" ] || DATE=1970-01-01

    URL="https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/$TAG.zip"
    echo "=== mining $TAG (released $DATE)"
    minr -d "Mbed-TLS,mbedtls,$VERSION,$DATE,Apache-2.0,pkg:github/mbed-tls/mbedtls" -u "$URL"
done

echo "=== snippet mining (.mz -> wfp)"
minr -z mined

echo "=== mined/ size before import"
du -sh mined

echo '{"monthly":"26.07", "daily":"26.07.18"}' > mined/version.json

echo "=== importing into LDB (wipes mined/)"
minr -i mined/
