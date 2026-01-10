#!/usr/bin/env python3
"""
Password Strength Checker (portfolio version)

What it does:
- Estimates password strength using entropy + heuristics
- Detects weak patterns (common passwords, sequences, repeats, keyboard runs)
- Supports interactive mode OR CLI flags
- Outputs human-friendly results or JSON
- Returns useful exit codes (good for automation)

No external dependencies.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from dataclasses import dataclass
from typing import List, Tuple, Optional


# ----------------------------
# Common / breached-style passwords (small built-in starter list)
# NOTE: This is intentionally short for a portfolio demo.
# You can expand later or load from a file.
# ----------------------------
COMMON_PASSWORDS = {
    "password",
    "password1",
    "password123",
    "123456",
    "1234567",
    "12345678",
    "123456789",
    "1234567890",
    "qwerty",
    "qwerty123",
    "qwertyuiop",
    "abc123",
    "letmein",
    "admin",
    "admin123",
    "welcome",
    "iloveyou",
    "football",
    "baseball",
    "dragon",
    "monkey",
    "shadow",
    "master",
    "sunshine",
    "princess",
    "login",
    "passw0rd",
    "trustno1",
}


# ----------------------------
# Policy presets (NIST-style-ish)
# - NIST guidance is nuanced; this is an interview-friendly approximation:
#   - Prefer length over complexity
#   - Block common/compromised passwords
#   - Allow passphrases
# ----------------------------
@dataclass(frozen=True)
class Policy:
    name: str
    min_length: int
    min_entropy_bits: float
    require_mixed_case: bool
    require_digit: bool
    require_symbol: bool
    block_common: bool

    def describe(self) -> str:
        parts = [
            f"Policy: {self.name}",
            f"- min length: {self.min_length}",
            f"- min entropy: {self.min_entropy_bits:.1f} bits",
            f"- block common passwords: {self.block_common}",
        ]
        # Requirements are optional in some policies; show only if enabled
        if self.require_mixed_case:
            parts.append("- requires mixed case")
        if self.require_digit:
            parts.append("- requires a digit")
        if self.require_symbol:
            parts.append("- requires a symbol")
        if not (self.require_mixed_case or self.require_digit or self.require_symbol):
            parts.append("- complexity requirements: none (length/entropy focused)")
        return "\n".join(parts)


POLICIES = {
    "basic": Policy(
        name="basic",
        min_length=8,
        min_entropy_bits=45.0,
        require_mixed_case=False,
        require_digit=False,
        require_symbol=False,
        block_common=True,
    ),
    "nist": Policy(
        name="nist",
        min_length=12,
        min_entropy_bits=60.0,
        require_mixed_case=False,   # length/passphrase-friendly
        require_digit=False,
        require_symbol=False,
        block_common=True,
    ),
    "strict": Policy(
        name="strict",
        min_length=14,
        min_entropy_bits=75.0,
        require_mixed_case=True,
        require_digit=True,
        require_symbol=True,
        block_common=True,
    ),
}


# ----------------------------
# Utilities / Heuristics
# ----------------------------
KEYBOARD_RUNS = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
]


def normalize_for_matching(pw: str) -> str:
    """Normalize to catch simple leetspeak-ish variants."""
    pw = pw.lower()
    pw = pw.replace("@", "a").replace("0", "o").replace("$", "s").replace("!", "i")
    return pw


def has_keyboard_run(pw_lower: str, run_len: int = 4) -> bool:
    """Detects keyboard-ish runs (length >= run_len) inside password."""
    for run in KEYBOARD_RUNS:
        for i in range(len(run) - run_len + 1):
            chunk = run[i : i + run_len]
            if chunk in pw_lower:
                return True
    return False


def has_repeated_char_run(pw: str, run_len: int = 3) -> bool:
    """Detect repeated same character 3+ times (e.g., 'aaa', '111')."""
    return re.search(rf"(.)\1{{{run_len - 1},}}", pw) is not None


def has_sequence(pw_lower: str, seq_len: int = 4) -> bool:
    """Detect ascending/descending sequences like abcd, dcba, 1234, 4321."""
    alpha = "abcdefghijklmnopqrstuvwxyz"
    digit = "0123456789"

    def contains_seq(base: str) -> bool:
        for i in range(len(base) - seq_len + 1):
            asc = base[i : i + seq_len]
            desc = asc[::-1]
            if asc in pw_lower or desc in pw_lower:
                return True
        return False

    return contains_seq(alpha) or contains_seq(digit)


def char_pools_used(pw: str) -> Tuple[bool, bool, bool, bool]:
    lower = any(c.islower() for c in pw)
    upper = any(c.isupper() for c in pw)
    digit = any(c.isdigit() for c in pw)
    symbol = any(not c.isalnum() for c in pw)
    return lower, upper, digit, symbol


def estimate_entropy_bits(pw: str) -> float:
    """
    Rough entropy estimate:
    - Determine character pool size based on types used
    - entropy = len(pw) * log2(pool_size)
    """
    lower, upper, digit, symbol = char_pools_used(pw)

    pool = 0
    if lower:
        pool += 26
    if upper:
        pool += 26
    if digit:
        pool += 10
    if symbol:
        # Approx typical printable symbol count (varies). Use a conservative number.
        pool += 32

    if pool == 0:
        return 0.0

    return len(pw) * math.log2(pool)


def rating_from_entropy(entropy_bits: float) -> str:
    # Thresholds tuned to look “security-team-ish” but still understandable
    if entropy_bits < 35:
        return "VERY WEAK"
    if entropy_bits < 50:
        return "WEAK"
    if entropy_bits < 65:
        return "MEDIUM"
    if entropy_bits < 80:
        return "STRONG"
    return "VERY STRONG"


def exit_code_from_rating(rating: str) -> int:
    # Useful for automation / CI checks
    mapping = {
        "VERY WEAK": 3,
        "WEAK": 2,
        "MEDIUM": 1,
        "STRONG": 0,
        "VERY STRONG": 0,
    }
    return mapping.get(rating, 2)


@dataclass
class Result:
    length: int
    entropy_bits: float
    rating: str
    issues: List[str]
    improvements: List[str]
    policy_pass: bool
    policy_name: str


def check_against_policy(pw: str, policy: Policy) -> Tuple[bool, List[str], List[str]]:
    """
    Returns:
    - pass/fail
    - issues (hard failures)
    - improvements (suggestions)
    """
    issues: List[str] = []
    improvements: List[str] = []

    pw_stripped = pw.strip()
    if pw_stripped != pw:
        improvements.append("Avoid leading/trailing spaces (easy to mistype).")

    if len(pw) < policy.min_length:
        issues.append(f"Too short for policy ({len(pw)} < {policy.min_length}).")

    entropy_bits = estimate_entropy_bits(pw)
    if entropy_bits < policy.min_entropy_bits:
        issues.append(
            f"Entropy below policy minimum ({entropy_bits:.1f} < {policy.min_entropy_bits:.1f} bits)."
        )

    lower, upper, digit, symbol = char_pools_used(pw)
    if policy.require_mixed_case and not (lower and upper):
        issues.append("Policy requires mixed case (both upper + lower).")
    if policy.require_digit and not digit:
        issues.append("Policy requires at least one digit.")
    if policy.require_symbol and not symbol:
        issues.append("Policy requires at least one symbol.")

    if policy.block_common:
        normalized = normalize_for_matching(pw)
        if normalized in COMMON_PASSWORDS:
            issues.append("Password is in a common/compromised password list.")
        # Also catch obvious suffix patterns like password123
        if any(normalized.startswith(x) for x in ("password", "qwerty")) and any(c.isdigit() for c in normalized):
            issues.append("Looks like a common base word with digits appended (easy to guess).")

    # Pattern detections (not always “fail”, but should be called out)
    pw_lower = pw.lower()
    if has_sequence(pw_lower):
        improvements.append("Avoid sequences like 'abcd' or '1234'.")
    if has_repeated_char_run(pw):
        improvements.append("Avoid repeated characters like 'aaa' or '111'.")
    if has_keyboard_run(pw_lower):
        improvements.append("Avoid keyboard patterns like 'qwerty' / 'asdf'.")

    # Positive suggestions (NIST-ish: length/passphrase)
    if len(pw) < 16:
        improvements.append("Consider a longer passphrase (16+ chars) for stronger security.")
    if not symbol:
        improvements.append("Adding a symbol can increase strength (optional if using a long passphrase).")

    passed = len(issues) == 0
    return passed, issues, improvements


def evaluate_password(pw: str, policy: Policy) -> Result:
    entropy_bits = estimate_entropy_bits(pw)
    rating = rating_from_entropy(entropy_bits)

    policy_pass, issues, improvements = check_against_policy(pw, policy)

    # If policy fails, rating should not “overrule” it. Keep rating but mark policy fail.
    # Add a quick note if rating is high but policy fails (rare, but possible).
    if not policy_pass and entropy_bits >= policy.min_entropy_bits:
        improvements.insert(0, "Meets entropy, but fails one or more policy requirements.")

    return Result(
        length=len(pw),
        entropy_bits=entropy_bits,
        rating=rating,
        issues=issues,
        improvements=improvements,
        policy_pass=policy_pass,
        policy_name=policy.name,
    )


def print_human(result: Result) -> None:
    print("\nResults")
    print("-" * 28)
    print(f"Length: {result.length}")
    print(f"Estimated entropy: {result.entropy_bits:.1f} bits")
    print(f"Rating: {result.rating}")
    print(f"Policy: {result.policy_name} -> {'PASS' if result.policy_pass else 'FAIL'}")

    if result.issues:
        print("\nPolicy issues (must fix):")
        for i, issue in enumerate(result.issues, start=1):
            print(f"  {i}. {issue}")
    else:
        print("\nNo policy issues found.")

    if result.improvements:
        print("\nImprovements (recommended):")
        # Deduplicate while preserving order
        seen = set()
        cleaned = []
        for item in result.improvements:
            if item not in seen:
                cleaned.append(item)
                seen.add(item)

        for i, tip in enumerate(cleaned, start=1):
            print(f"  {i}. {tip}")
    else:
        print("\nNo obvious improvements found. Nice.")


def to_json(result: Result) -> str:
    payload = {
        "length": result.length,
        "entropy_bits": round(result.entropy_bits, 1),
        "rating": result.rating,
        "policy": result.policy_name,
        "policy_pass": result.policy_pass,
        "issues": result.issues,
        "improvements": result.improvements,
        "exit_code": exit_code_from_rating(result.rating) if result.policy_pass else 2,
    }
    return json.dumps(payload, indent=2)


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="password-checker",
        description="Password Strength Checker (portfolio CLI).",
    )
    parser.add_argument(
        "-p",
        "--password",
        type=str,
        default=None,
        help="Password string to evaluate. If omitted, interactive prompt is used.",
    )
    parser.add_argument(
        "--policy",
        type=str,
        choices=sorted(POLICIES.keys()),
        default="nist",
        help="Policy preset to enforce (default: nist).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON.",
    )
    parser.add_argument(
        "--show-policy",
        action="store_true",
        help="Print the selected policy rules and exit.",
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    policy = POLICIES[args.policy]

    if args.show_policy:
        print(policy.describe())
        return 0

    if args.password is None:
        # Interactive
        pw = input("Enter a password: ").strip()
    else:
        pw = args.password

    result = evaluate_password(pw, policy)

    if args.json:
        print(to_json(result))
    else:
        print_human(result)

    # Exit code design:
    # - If policy FAIL => 2
    # - Else based on rating severity
    if not result.policy_pass:
        return 2
    return exit_code_from_rating(result.rating)


if __name__ == "__main__":
    raise SystemExit(main())
