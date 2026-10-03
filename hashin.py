import sys
import argparse
from dataclasses import dataclass 
from typing import Literal

from rich.console import Console 
from rich.table import Table

Confidence = Literal["low","medium","high"]

@dataclass (frozen = True, slots = True)
class HashCandidate:
    algorithm : str
    confidence : Confidence 
    reason : str


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
            return [
                HashCandidate(
                algorithm=algo,
                confidence="high",
                reason=f"prefix `{prefix}` — {note}",
            )]
    if "::" in text and text.count(":") >= 4 :
        parts = text.split(":")
        if (len(parts)  >= 6 and len(parts[4]) >= 32 and _is__hex(parts[4])):
            return [
                HashCandidate(algorithm="NetNTLMv2",
                              confidence="medium", 
                              reason = "colon-separated format with a 32+ hex response field",
                              )]
        if (len(parts) >= 6 and len(parts[3]) == 48 and _is__hex(parts[3])):
            return [
                HashCandidate(algorithm="NetNTLMv1",
                              cofidnece = "medium", 
                              reason = "colon-saperated format with aa 48-char hex field"
                              )]
    
    if _is_mysql5(text): #MYSQL HASH
        return [
            HashCandidate(
                algorithm="MySQL5", 
                confidence="high", 
                reason = "starts with '*' followed by 40 uppercase hex char"
                )]
    
    if _is_descrypt(text):
        return [
            HashCandidate(
                algorithm="DES crypt", 
                confidence="medium", 
                reason = "13 char from the crypt(3) alphabet"
                )]
    
    if __is__hex(text):
        algorithms = HEX_LENGTH_RULES.get(len(text), [])
        candidates: list[HashCandidate] = []
        for index, algorithm in enumerate(algorithms):
            confidence: confidence = "medium" if index == 0 else "low"
            label = (
                "most likely candidate at this length"
                if index == 0 else "also possible at this length"
            )
            candidates.append(
                HashCandidate(algorithm=algorithm, 
                              confidence=confidence, 
                              reason= f"{label} ({len(text)} hex chars)"
            ))
        if candidates:
            return candidates
    
    if text.startswith("$"):
        rest = text[1:]
        if "$" in rest:
            algo_name = rest.split("$", 1)[0]
            if algo_name and all(c.isalnum() or c in "-_" for c in algo_name):
                return [
                        HashCandidate(
                            algorithm=f"PHC string ({algo_name})", 
                            confidence = "medium",
                            reason = "PHC-style `$algorithm$params$salt$hash` layout"
                            )]

    if text.startswith("eyJ"): #JWT hash
        return [
                HashCandidate(
                    algorithm="JWT (not a hash)", 
                    confidence='high',
                    reason='''eyJ is base64 for '{' which is a JWT header'''
                )]
    if any(c in text for c in "+/=") and len(text) > 8:
        return[
            HashCandidate(
                algorithm="Base64 blob (not a hash)",
                confidence="low",
                reason="contains base64 alphabet characters; probably encoded data",
            )]    
    return []

def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hashid", description="...")
    parser.add_argument("hash", help="The hash string to identify ...")
    parser.add_argument("--top", "-n", type=int, default=5, help="...")
    return parser

def _render_table(raw_input, candidates, console) -> None:
    table = Table(title=f"Candidates for: {raw_input.strip()}")
    table.add_column("algorithm", style="bold white", no_wrap=True)
    table.add_column("confidence", no_wrap=True)
    table.add_column("reason", style="dim")

    confidence_colors: dict[confidence, str] = {
        "high": "green",
        "medium": "yellow",
        "low": "cyan",
    }
    for candidate in candidates:
        color = confidence_colors[candidate.confidence]
        table.add_row(
            candidate.algorithm,
            f"[{color}]{candidate.confidence}[/{color}]",
            candidate.reason,
        )
    console.print(table)

def main() -> int:
    parser = _build_argument_parser()
    args = parser.parse_args()
    console = Console()

    candidates = identify(args.hash)

    if not candidates:
        console.print("[red]No identification possible.[/red] ...")
        return 1

    trimmed = candidates[:args.top]
    _render_table(args.hash, trimmed, console)

    if trimmed[0].confidence == "high":
        console.print("\n[dim]Next step: try the matching cracker ...[/dim]")

    return 0

if __name__ == "__main__":
    sys.exit(main())
