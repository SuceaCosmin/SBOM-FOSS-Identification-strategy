#!/bin/sh
# Scan one component's ground-truth corpus against the self-mined LDB KB.
# Usage: scan_corpus.sh <component>   (e.g. freertos, mbedtls)
# Runs INSIDE the container; expects the repo mounted at /repo (read-only)
# and writes one JSON result per corpus tree to /work/results/<component>/.
set -eu

COMPONENT=${1:?usage: scan_corpus.sh <component>}
CORPUS=/repo/components/$COMPONENT/corpus
OUT=/work/results/$COMPONENT
mkdir -p "$OUT"

for DIR in "$CORPUS"/*/; do
    TREE=$(basename "$DIR")
    echo "=== scanning $TREE"
    # jq . : keep checked-in JSON human-readable (repo convention), scanoss emits one-liners
    scanoss "$DIR" | jq . > "$OUT/$TREE.json" || echo "scan failed on $TREE"
done

echo "=== results written to $OUT"
