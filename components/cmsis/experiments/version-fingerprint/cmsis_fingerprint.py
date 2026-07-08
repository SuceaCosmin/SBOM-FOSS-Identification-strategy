"""Normalization, exact hashing, and winnowing fingerprints for CMSIS-Core
version/similarity matching. Shared by build_reference_db.py and match_target.py.

Identical algorithm to the FreeRTOS-Kernel and Mbed TLS experiments
(components/freertos/experiments/version-fingerprint/freertos_fingerprint.py,
components/mbedtls/experiments/version-fingerprint/mbedtls_fingerprint.py) - kept as its
own copy per component per this repo's layout convention, not shared code.
"""

import hashlib
import re

GRAM_SIZE = 30
WINDOW_SIZE = 50
# Guarantee threshold: any shared substring of at least GRAM_SIZE + WINDOW_SIZE - 1
# (~79) normalized characters between two files is guaranteed to produce at least one
# shared fingerprint entry (Schleimer/Wilkerson/Aiken winnowing guarantee property).

_COMMENT_RE = re.compile(r"/\*.*?\*/|//[^\n]*", re.DOTALL)
_WHITESPACE_RE = re.compile(r"\s+")


def normalize(source: str) -> str:
    """Strip C comments and collapse whitespace so reformatting/comment edits don't
    change the fingerprint.

    Deliberate consequence for CMSIS-Core specifically: cmsis_version.h's file-level
    @version/@date/copyright-year docstring lives inside the header comment block and
    is stripped by normalization, while the actual __CM_CMSIS_VERSION_MAIN/_SUB macros
    (the real version anchor - see ../../README.md section 7) are plain code and
    survive. This matters because the docstring and the macro can disagree within the
    same file (confirmed this session: NXP's MCUX_2.16.000 fork's cmsis_version.h
    docstring said "V5.0.5" while diffing against tag 5.6.0 initially looked wrong -
    the macros, not the docstring, are what actually pin the release; see build_reference_db.py).
    """
    no_comments = _COMMENT_RE.sub(" ", source)
    return _WHITESPACE_RE.sub(" ", no_comments).strip()


def sha256_hex(normalized: str) -> str:
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _hash_gram(gram: str) -> int:
    # 32-bit (not 64-bit): not a security context, and at ~1-2k hashes per file the
    # birthday collision probability is well under 0.1% - see general/README.md
    # "Reference DB size scales with component shape, not a fixed constant".
    return int.from_bytes(hashlib.blake2b(gram.encode("utf-8"), digest_size=4).digest(), "big")


def winnow(normalized: str, gram_size: int = GRAM_SIZE, window_size: int = WINDOW_SIZE) -> set:
    """Classic winnowing (Schleimer/Wilkerson/Aiken): hash every gram_size-char
    substring, then within each sliding window of window_size grams keep only the
    minimum hash (rightmost on ties). The surviving hashes are the fingerprint - a
    compact set that's robust to small local edits, unlike a whole-file hash."""
    if len(normalized) <= gram_size:
        return {_hash_gram(normalized)} if normalized else set()

    grams = [normalized[i:i + gram_size] for i in range(len(normalized) - gram_size + 1)]
    hashes = [_hash_gram(g) for g in grams]

    if len(hashes) <= window_size:
        return {min(hashes)}

    fingerprint = set()
    prev_min_idx = -1
    for i in range(len(hashes) - window_size + 1):
        window = hashes[i:i + window_size]
        min_val = min(window)
        min_idx = i + max(j for j, v in enumerate(window) if v == min_val)
        if min_idx != prev_min_idx:
            fingerprint.add(hashes[min_idx])
            prev_min_idx = min_idx
    return fingerprint


def jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def fingerprint_source(source: str) -> dict:
    normalized = normalize(source)
    return {
        "sha256": sha256_hex(normalized),
        "winnow": sorted(winnow(normalized)),
    }
