#!/usr/bin/env python3
"""
Password Strength Checker (portfolio version)

- Estimates password entropy (bits)
- Checks basic policy requirements
- Detects common weak patterns (repeats, sequences, keyboard runs, common passwords)
- Produces a rating + prioritized improvements
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from dataclasses import dataclass
from typing import List, Tuple


# ----------------------------
# Data: simple weak pattern lists
# ----------------------------

# Very small "common passwords" sample (expand later if you want)
COMMON_PASSWORDS = {
    "password", "password1", "password123", "admin", "admin123",
    "qwerty", "qwerty123", "letmein", "welcome", "iloveyou",
    "123456", "1234567", "12345678", "123456789", "1234567890",
}

# Simple sequences to catch (you can expand)
SEQUENCES = [
    "0123456789",
    "abcdefghijklmnopqrstuvwxyz",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
]

KEYBOARD_RUNS = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
]


# ----------------------------
# Models
# ----------------------------

@dataclass
class Result:
    password_length: int
    entropy_bits: float
    rating: str
    issues: List[str]


# ----------------------------
# Helpers
# ----------------------------

def estimate_charset_size(pw: str) -> int:
    """Estimate the effective character set size used by the password."""
    has_lower = any("a" <= c <= "z" for c in pw)
    has_upper = any("A" <= c <= "Z" for c in pw)
    has_digit = any(c.isdigit() for c in pw)
    has_space = any(c.isspace() for c in pw)
    has_other = any(not c.isalnum() and not c.isspace() for c in pw)

    size = 0
    if has_lower:
        size += 26
    if has_upper:
        size += 26
    if has_digit:
        size += 10
    if has_space:
        size += 1  # treat space separately
    if has_other:
        size += 32  # rough typical printable specials bucket

    # Fallback (shouldn't happen unless empty)
    return max(size, 1)


def estimate_entropy_bits(pw: str) -> float:
    """
    Shannon-style estimate using log2(charset_size^length) = length * log2(charset_size).
    This is a simplification but good for a portfolio project.
    """
    if not pw:
        return 0.0
    charset = estimate_charset_size(pw)
    return len(pw) * math.log2(charset)


def has_repeated_char_run(pw: str) -> bool:
    """Detects repeated same character 3+ times, e.g., 'aaa' or '111'."""
    return re.search(r"(.)\1{2,}", pw) is not None


def has_sequence(pw_lower: str) -> bool:
    """Detect simple ascending sequences length >= 4 in known sequence strings."""
    for seq in SEQUENCES:
        for i in range(len(seq) - 3):
            chunk = seq[i:i + 4]
            if chunk in pw_lower:
                return True
    # Also check reverse sequences
    for seq in SEQUENCES:
        rseq = seq[::-1]
        for i in range(len(rseq) - 3):
            chunk = rseq[i:i + 4]
            if chunk in pw_lower:
                return True
    return False


def has_keyboard_run(pw_lower: str) -> bool:
    """Detect keyboard-ish runs length >= 4."""
    for run in KEYBOARD_RUNS:
        for i in range(len(run) - 3):
            chunk = run[i:i + 4]
            if chunk in pw_lower:
                return True
    # Reverse runs
    for run in KEYBOARD_RUNS:
        rrun = run[::-1]
        for i in range(len(rrun) - 3):
            chunk = rrun[i:i + 4]
            if chunk in pw_lower:
                return True
    return False


def is_common_password(pw_lower: str) -> bool:
    """Checks if password is in a small common-password list (case-insensitive)."""
    return pw_lower in COMMON_PASSWORDS


def policy_issues(pw: str, min_length: int = 12) -> List[str]:
    """Return a list of policy/quality issues with prioritized ordering."""
    issues: List[str] = []
    pw_lower = pw.lower()

    # High-impact issues first
    if len(pw) < min_length:
        issues.append(f"Password is shorter than {min_length} characters.")

    if is_common_password(pw_lower):
        issues.append("Password appears in a common-password list.")

    if has_keyboard_run(pw_lower):
        issues.append("Password contains a keyboard pattern (e.g., qwerty/asdf).")

    if has_sequence(pw_lower):
        issues.append("Password contains an easy-to-guess sequence (e.g., 1234/abcd).")

    if has_repeated_char_run(pw):
        issues.append("Password contains repeated character runs (e.g., 'aaa', '111').")

    # Composition checks (helpful but secondary)
    if not any(c.isdigit() for c in pw):
        issues.append("Add at least one number.")
    if not any("A" <= c <= "Z" for c in pw):
        issues.append("Add at least one uppercase letter.")
    if not any("a" <= c <= "z" for c in pw):
        issues.append("Add at least one lowercase letter.")
    if not any(not c.isalnum() and not c.isspace() for c in pw):
        issues.append("Add at least one special character (e.g., !, @, #).")

    return issues


def rate_from_entropy(entropy_bits: float) -> str:
    """
    Updated thresholds (more realistic):
    < 28  -> VERY WEAK
    < 36  -> WEAK
    < 60  -> MEDIUM
    >=60  -> STRONG
    """
    if entropy_bits < 28:
        return "VERY WEAK"
    if entropy_bits < 36:
        return "WEAK"
    if entropy_bits < 60:
        return "MEDIUM"
    return "STRONG"


def evaluate_password(pw: str, min_length: int) -> Result:
    entropy = estimate_entropy_bits(pw)
    rating = rate_from_entropy(entropy)
    issues = policy_issues(pw, min_length=min_length)
    return Result(
        password_length=len(pw),
        entropy_bits=entropy,
        rating=rating,
        issues=issues,
    )


def print_human(result: Result, pw: str) -> None:
    print("\nResults")
    print("-" * 28)
    print(f"Length: {result.password_length}")
    print(f"Estimated entropy: {result.entropy_bits:.1f} bits")
    print(f"Rating: {result.rating}")

    if result.issues:
        print("\nImprovements:")
        for i, issue in enumerate(result.issues, start=1):
            print(f"{i}. {issue}")
    else:
        print("\nNo critical weaknesses detected.")


def exit_code_from_rating(rating: str) -> int:
    """Useful for scripting/CI: strong=0, medium=1, weak=2, very weak=3"""
    mapping = {
        "STRONG": 0,
        "MEDIUM": 1,
        "WEAK": 2,
        "VERY WEAK": 3,
    }
    return mapping.get(rating, 4)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Password Strength Checker (portfolio version)")
    p.add_argument("--min-length", type=int, default=12, help="Minimum recommended length")
    p.add_argument("--json", action="store_true", help="Output JSON")
    p.add_argument("--password", type=str, default=None, help="Provide a password (otherwise prompts)")
    return p.parse_args()


def main() -> int:
    args = parse_args()

    if args.password is None:
        pw = input("Enter a password: ").strip()
    else:
        pw = args.password

    result = evaluate_password(pw, min_length=args.min_length)

    if args.json:
        payload = {
            "length": result.password_length,
            "entropy_bits": result.entropy_bits,
            "rating": result.rating,
            "issues": result.issues,
            "exit_code": exit_code_from_rating(result.rating),
        }
        print(json.dumps(payload, indent=2))
    else:
        print_human(result, pw)

    return exit_code_from_rating(result.rating)


if __name__ == "__main__":
    raise SystemExit(main())
