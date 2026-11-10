"""Unit tests for the password strength checker."""

from __future__ import annotations

import json

import pytest

from password_strength_checker.checker import (
    POLICIES,
    estimate_entropy_bits,
    evaluate_password,
    exit_code_from_rating,
    has_keyboard_run,
    has_repeated_char_run,
    has_sequence,
    main,
    normalize_for_matching,
    rating_from_entropy,
)


class TestEntropy:
    def test_empty_password_is_zero(self):
        assert estimate_entropy_bits("") == 0.0

    def test_longer_is_stronger_with_same_character_pool(self):
        assert estimate_entropy_bits("abcdefghij") > estimate_entropy_bits("abcde")

    def test_more_character_types_increase_entropy(self):
        assert estimate_entropy_bits("Abcdefg1!") > estimate_entropy_bits("abcdefghi")

    def test_lowercase_only_matches_formula(self):
        # 26-character pool, 8 characters -> 8 * log2(26)
        assert estimate_entropy_bits("zxqvjkwp") == pytest.approx(37.6, abs=0.1)


class TestRatings:
    @pytest.mark.parametrize(
        ("bits", "label"),
        [
            (0, "VERY WEAK"),
            (34.9, "VERY WEAK"),
            (35, "WEAK"),
            (49.9, "WEAK"),
            (50, "MEDIUM"),
            (64.9, "MEDIUM"),
            (65, "STRONG"),
            (79.9, "STRONG"),
            (80, "VERY STRONG"),
        ],
    )
    def test_thresholds(self, bits, label):
        assert rating_from_entropy(bits) == label

    @pytest.mark.parametrize(
        ("rating", "code"),
        [("VERY WEAK", 3), ("WEAK", 2), ("MEDIUM", 1), ("STRONG", 0), ("VERY STRONG", 0)],
    )
    def test_exit_codes(self, rating, code):
        assert exit_code_from_rating(rating) == code

    def test_unknown_rating_defaults_to_failure_code(self):
        assert exit_code_from_rating("???") == 2


class TestPatternDetection:
    def test_repeated_characters(self):
        assert has_repeated_char_run("xaaay")
        assert not has_repeated_char_run("xaay")

    def test_ascending_and_descending_sequences(self):
        assert has_sequence("xx1234xx")
        assert has_sequence("xxdcbaxx")
        assert not has_sequence("x13579x")

    def test_keyboard_runs(self):
        assert has_keyboard_run("myqwertypass")
        assert has_keyboard_run("asdfghjk")
        assert not has_keyboard_run("correcthorse")

    def test_leetspeak_normalization(self):
        assert normalize_for_matching("P@ssw0rd") == "passw" + "ord"


class TestPolicies:
    def test_common_password_fails_every_policy(self):
        for policy in POLICIES.values():
            result = evaluate_password("password123", policy)
            assert not result.policy_pass
            assert any("common" in issue.lower() for issue in result.issues)

    def test_leetspeak_variant_of_common_password_is_caught(self):
        result = evaluate_password("P@ssw0rd", POLICIES["basic"])
        assert not result.policy_pass

    def test_short_password_fails_length(self):
        result = evaluate_password("Ab1!", POLICIES["nist"])
        assert any("short" in issue.lower() for issue in result.issues)

    def test_long_passphrase_passes_nist(self):
        result = evaluate_password("correct horse battery staple", POLICIES["nist"])
        assert result.policy_pass
        assert result.issues == []

    def test_strict_requires_all_character_classes(self):
        result = evaluate_password("alllowercaseletterslong", POLICIES["strict"])
        assert not result.policy_pass
        joined = " ".join(result.issues).lower()
        assert "mixed case" in joined
        assert "digit" in joined
        assert "symbol" in joined

    def test_strict_accepts_strong_password(self):
        result = evaluate_password("Tr1cky-Quartz-Lantern-93!", POLICIES["strict"])
        assert result.policy_pass

    def test_leading_space_triggers_suggestion(self):
        result = evaluate_password(" correct horse battery staple", POLICIES["nist"])
        assert any("spaces" in tip.lower() for tip in result.improvements)


class TestCli:
    def test_json_output_is_valid_and_complete(self, capsys):
        code = main(["-p", "correct horse battery staple", "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["policy"] == "nist"
        assert payload["policy_pass"] is True
        assert set(payload) >= {"length", "entropy_bits", "rating", "issues", "improvements"}
        assert code == payload["exit_code"]

    def test_policy_failure_returns_exit_code_two(self, capsys):
        assert main(["-p", "123456"]) == 2
        assert "FAIL" in capsys.readouterr().out

    def test_show_policy_prints_rules_and_exits_zero(self, capsys):
        assert main(["--policy", "strict", "--show-policy"]) == 0
        out = capsys.readouterr().out
        assert "min length: 14" in out
        assert "requires a symbol" in out

    def test_interactive_prompt(self, monkeypatch, capsys):
        monkeypatch.setattr("builtins.input", lambda _prompt: "correct horse battery staple")
        assert main([]) == 0
        assert "PASS" in capsys.readouterr().out

    def test_invalid_policy_is_rejected(self):
        with pytest.raises(SystemExit):
            main(["-p", "x", "--policy", "bogus"])
