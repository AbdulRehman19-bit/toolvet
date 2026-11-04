"""Deterministic text features shared by training and inference.

Pure Python: lowercase word unigrams and bigrams, plus a few marker tokens, hashed into a
fixed number of buckets and L2-normalised. No scikit-learn is needed at inference time.
"""

from __future__ import annotations

import itertools
import math
import re
import zlib

DIM = 2048

_WORD = re.compile(r"[a-z0-9_]+")
_MARKERS = [
    ("__url__", re.compile(r"https?://")),
    ("__home_path__", re.compile(r"(~|/home/\w+|%userprofile%)[/\\]")),
    ("__dotfile__", re.compile(r"(^|[\s/\\])\.[a-z][a-z0-9_]+")),
    ("__tag__", re.compile(r"</?[a-z]+>")),
    ("__email__", re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")),
    ("__ip__", re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b")),
]


def tokens(text: str) -> list[str]:
    lowered = text.lower()
    words = _WORD.findall(lowered)
    grams = words + [f"{a} {b}" for a, b in itertools.pairwise(words)]
    grams += [name for name, pattern in _MARKERS if pattern.search(lowered)]
    return grams


def featurize(text: str) -> list[float]:
    """Return a DIM-length, L2-normalised hashed bag of n-grams."""
    vector = [0.0] * DIM
    for token in tokens(text):
        vector[zlib.crc32(token.encode("utf-8")) % DIM] += 1.0
    norm = math.sqrt(sum(v * v for v in vector))
    return [v / norm for v in vector] if norm else vector
