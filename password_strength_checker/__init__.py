"""Password strength checker: entropy scoring, pattern detection, policy presets."""

from .checker import POLICIES, Policy, Result, evaluate_password

__all__ = ["POLICIES", "Policy", "Result", "evaluate_password"]
__version__ = "0.1.0"
