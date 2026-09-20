import sys
import argparse
from datasets import dataclass 
from typing import Literal

from rich.console import console 
from rich.table import table

confidence = Literal["low","medium","high"]
@dataclass (frozen = True, slots = True)
class HashCandidates:
    def __init__(self, algorithm : str, confidence : Confidence,reason : str):
        self.algorithm = algorithm
        self.confidence = confidence 
        self.reason = reason

    def __repr__(self): 
        return f"HashCandidate(algorithm={self.algorithm!r}, ...)"

PREFIX_RULES: list[tuple[str, str, str]] = [
    ("$argon2id$", "Argon2id", "modern PHC string, the current standard"),
    ("$argon2i$",  "Argon2i",  "PHC string, side-channel-resistant variant"),
]

HEX_CHARSET: frozenset[str] = frozenset("0123456789abcdefABCDEF")
_HEX_UPPER_CHARSET: frozenset[str] = frozenset("0123456789ABCDEF")
HEX_LENGTH_RULES: dict[int, list[str]] = {
    16:  ["MySQL323", "CRC-64"],
    32:  ["MD5", "NTLM", "MD4", "RIPEMD-128"],
    40:  ["SHA-1", "RIPEMD-160"],
}
def __is__hex(text: str) -> bool:
    return bool(text) and all(c in HEX_CHARSET for c in text)


_MYSQL5_HEX_BODY_LENGTH = 40
_MYSQL5_TOTAL_LENGTH = _MYSQL5_HEX_BODY_LENGTH + 1
def _is_mysql5(text: str) -> bool:
    if len(text) != _MYSQL5_TOTAL_LENGTH or not text.startswith("*"):
        return False
    body = text[1:]
    return all(c in _HEX_UPPER_CHARSET for c in body)



_DESCRYPT_CHARSET: frozenset[str] = frozenset(
    "./0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
)
_DESCRYPT_TOTAL_LENGTH = 13

def _is_descrypt(text: str) -> bool:
    return (len(text) == _DESCRYPT_TOTAL_LENGTH and all(c in _DESCRYPT_CHARSET for c in text))

def identify(raw_in: str) -> list[HashCandidate]:
    text = raw_in.strip()
    if not text:
        return []
    for prefix, algo, note in PREFIX_RULES:
        if text.startswith(prefix): 
            return [HashCandidate(
                algorithm=algorithm,
                confidence="high",
                reason=f"prefix `{prefix}` — {note}",
            )]
    if "::" in text and text.count(":") >= 4 :
        parts = text.split(":")
        if (len(parts)  >= 6 and len(parts[4]) >= 32 and _is_hex(parts[4])):
            return [HashCandidate(algorithm="NetNTLMv2", ...)]
        if (len(parts) >= 6 and len(parts[3]) == 48 and _is_hex(parts[3])):
            return [HashCandidate(algorithm="NetNTLMv1", ...)]
    
    if _is_mysql5(text):
    return [HashCandidate(algorithm="MySQL5", confidence="high", ...)]
    if _is_descrypt(text):
    return [HashCandidate(algorithm="DES crypt", confidence="medium", ...)]

hash = sys.argv[1]
print(hash)


