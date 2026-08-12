"""One-time upload token format: offline verify (client) + shared test vectors.

Must stay aligned with the sibling backend generator/ingest
(PROMPT_WL_CHECKER_HARDENING_backend_hop_frontend.md). Do not invent a second
algorithm.

Format (32 characters exactly):
- Positions 1-17 and 20-32 (1-based): body, A-Z / 0-9 only
- Body: at least 10 letters and at least 10 digits among the 30 body chars
- Positions 18-19: checksum digits = (sum of body code points) mod 100, zero-padded

This check catches typos and truncated pastes. It does not prove the token is
unused on the server.
"""

from __future__ import annotations

from typing import List, Optional, Tuple

TOKEN_LENGTH = 32
# 1-based positions 18-19 -> 0-based indices 17-18
_CHECKSUM_START = 17
_CHECKSUM_END = 19  # exclusive
_MIN_LETTERS = 10
_MIN_DIGITS = 10

# Shared with sibling backend tests. Do not treat as a live upload credential.
# VALID: body ABCDEFGHIJ0123456789KLMNOPQRST, checksum 15.
SHARED_VALID_TOKEN = "ABCDEFGHIJ012345615789KLMNOPQRST"

SHARED_INVALID_TOO_SHORT = SHARED_VALID_TOKEN[:31]
SHARED_INVALID_WRONG_CHECKSUM = (
    SHARED_VALID_TOKEN[:17] + "16" + SHARED_VALID_TOKEN[19:]
)


def _expected_checksum(body: str) -> str:
    return "{:02d}".format(sum(ord(c) for c in body) % 100)


def _token_from_body(body: str) -> str:
    if len(body) != 30:
        raise ValueError("body must be 30 characters")
    return body[:17] + _expected_checksum(body) + body[17:]


# 9 letters + 21 digits; checksum is correct so only composition fails.
SHARED_INVALID_TOO_FEW_LETTERS = _token_from_body("A" * 9 + "0" * 21)


def _body_chars(token: str) -> str:
    return token[:_CHECKSUM_START] + token[_CHECKSUM_END:]


def verify_upload_token(token: str) -> Tuple[bool, str]:
    """Return (ok, reason). reason is empty on success."""
    if token is None:
        return False, "token is missing"
    raw = token.strip()
    if len(raw) != TOKEN_LENGTH:
        return False, "token must be exactly {} characters".format(TOKEN_LENGTH)

    checksum = raw[_CHECKSUM_START:_CHECKSUM_END]
    if not (len(checksum) == 2 and checksum.isdigit()):
        return False, "token checksum positions 18-19 must be digits"

    body = _body_chars(raw)
    if len(body) != 30:
        return False, "token body length is invalid"
    for ch in body:
        if not (("A" <= ch <= "Z") or ("0" <= ch <= "9")):
            return False, "token body must be A-Z and 0-9 only"

    n_letters = sum(1 for c in body if "A" <= c <= "Z")
    n_digits = sum(1 for c in body if "0" <= c <= "9")
    if n_letters < _MIN_LETTERS:
        return False, "token body needs at least {} letters".format(_MIN_LETTERS)
    if n_digits < _MIN_DIGITS:
        return False, "token body needs at least {} digits".format(_MIN_DIGITS)

    expected = _expected_checksum(body)
    if checksum != expected:
        return False, "token checksum is invalid"
    return True, ""


def is_valid_upload_token(token: str) -> bool:
    ok, _ = verify_upload_token(token)
    return ok


def shared_format_test_vectors() -> List[Tuple[str, bool, str]]:
    """(token, expect_valid, label) - shared with sibling backend."""
    return [
        (SHARED_VALID_TOKEN, True, "valid"),
        (SHARED_INVALID_TOO_SHORT, False, "wrong_length"),
        (SHARED_INVALID_WRONG_CHECKSUM, False, "wrong_checksum"),
        (SHARED_INVALID_TOO_FEW_LETTERS, False, "too_few_letters"),
    ]


def normalize_pasted_token(raw: Optional[str]) -> str:
    """Strip whitespace; volunteers paste the 32-char token itself."""
    if raw is None:
        return ""
    return "".join(raw.split())
