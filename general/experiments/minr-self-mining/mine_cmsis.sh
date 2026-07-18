#!/bin/sh
# Mine CMSIS releases into the same LDB KB as FreeRTOS/mbedTLS (third component,
# marginal-cost measurement continues). Spans the CMSIS_5 -> CMSIS_6 repo split,
# mirroring the bespoke reference DB. Corpus ground truth needs 5.6.0 and 5.9.0;
# 5.5.0/5.7.0/5.8.0 are the discrimination neighbors, v6.x tests the new lineage.
#
# Granularity note (deliberate): mining the umbrella repos attributes every file
# (Core headers, DSP, NN, RTX, ...) to one "CMSIS" component at the pack version -
# exactly the umbrella-vs-sub-component granularity question flagged in the CMSIS
# research. Good enough for the baseline; sub-component purls would need per-tree
# mining (-u accepts local folders) if ever wanted.
set -eu

cd /work

mine() { # repo tag version
    DATE=$(curl -sf "https://api.github.com/repos/ARM-software/$1/releases/tags/$2" \
           | jq -r '.published_at // empty' | cut -dT -f1)
    [ -n "$DATE" ] || DATE=1970-01-01
    URL="https://github.com/ARM-software/$1/archive/refs/tags/$2.zip"
    echo "=== mining $1 $2 (released $DATE)"
    minr -d "ARM-software,CMSIS,$3,$DATE,Apache-2.0,pkg:github/arm-software/$(echo "$1" | tr "A-Z" "a-z")" -u "$URL"
}

for T in 5.5.0 5.6.0 5.7.0 5.8.0 5.9.0; do mine CMSIS_5 "$T" "$T"; done
for T in v6.0.0 v6.1.0; do mine CMSIS_6 "$T" "${T#v}"; done

echo "=== snippet mining (.mz -> wfp)"
minr -z mined

echo "=== mined/ size before import"
du -sh mined

echo '{"monthly":"26.07", "daily":"26.07.18"}' > mined/version.json

echo "=== importing into LDB (wipes mined/)"
minr -i mined/
