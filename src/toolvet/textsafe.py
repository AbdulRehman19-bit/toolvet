"""Make text from untrusted files safe to print.

Server names, arguments, URLs and tool descriptions come from files an attacker may control.
Printed raw, they can carry terminal control sequences (clear the screen, rewrite earlier
lines, set the window title) or Unicode bidirectional overrides that reorder what the reader
sees. A scanner must not be the carrier, so every such character is replaced by a visible
escape: a backslash, then x and two hex digits, or u and four hex digits. Newlines and tabs
are kept.
"""

from __future__ import annotations

BACKSLASH = chr(92)

# C0 controls except tab (0x09) and newline (0x0A), which includes ESC and carriage return;
# DEL and the C1 controls; and the bidirectional formatting characters used for
# "Trojan Source" style spoofing.
_UNSAFE_RANGES = (
    (0x00, 0x08),
    (0x0B, 0x1F),
    (0x7F, 0x9F),
    (0x200E, 0x200F),
    (0x202A, 0x202E),
    (0x2066, 0x2069),
)


def _is_unsafe(code: int) -> bool:
    return any(low <= code <= high for low, high in _UNSAFE_RANGES)


def _escape(char: str) -> str:
    code = ord(char)
    if code < 0x100:
        return f"{BACKSLASH}x{code:02x}"
    return f"{BACKSLASH}u{code:04x}"


def visible(text: str) -> str:
    """Replace characters that can control a terminal or reorder text with visible escapes."""
    return "".join(_escape(c) if _is_unsafe(ord(c)) else c for c in text)
