#!/bin/sh
# Mine a scoped set of FreeRTOS-Kernel releases into a self-hosted LDB KB.
# Runs INSIDE the minr container (see Dockerfile). The tag set covers every
# version appearing in this repo's FreeRTOS corpus ground truth (V10.4.3,
# V10.5.1, V11.0.0, V11.2.0) plus near neighbors, so the engine has to
# actually discriminate versions rather than win by default.
#
# minr -d takes the metadata WE declare: vendor,component,version,date,license,purl.
# That is the attribution-by-construction property under test: every mined file
# hash traces back to this declared identity, not to an arbitrary containing repo.
#
# minr writes to ./mined under the cwd; -i requires mined/version.json and
# WIPES the mined dir after importing into /var/lib/ldb/oss.
set -eu

TAGS="V10.4.3 V10.4.4 V10.4.5 V10.4.6 V10.5.0 V10.5.1 V10.6.0 V10.6.1 V10.6.2 V11.0.0 V11.0.1 V11.1.0 V11.2.0"

cd /work

for TAG in $TAGS; do
    VERSION=$(echo "$TAG" | sed 's/^V//')
    # Release date from the GitHub API (unauthenticated; 13 calls, well under limit).
    DATE=$(curl -sf "https://api.github.com/repos/FreeRTOS/FreeRTOS-Kernel/releases/tags/$TAG" \
           | jq -r '.published_at // empty' | cut -dT -f1)
    [ -n "$DATE" ] || DATE=1970-01-01

    URL="https://github.com/FreeRTOS/FreeRTOS-Kernel/archive/refs/tags/$TAG.zip"
    echo "=== mining $TAG (released $DATE)"
    minr -d "FreeRTOS,FreeRTOS-Kernel,$VERSION,$DATE,MIT,pkg:github/freertos/freertos-kernel" -u "$URL"
done

echo "=== snippet mining (.mz -> wfp)"
minr -z mined

echo "=== mined/ size before import"
du -sh mined

echo '{"monthly":"26.07", "daily":"26.07.18"}' > mined/version.json

echo "=== importing into LDB (wipes mined/)"
minr -i mined/

echo "=== done; LDB size and tables:"
du -sh /var/lib/ldb/oss/ && ls /var/lib/ldb/oss/
