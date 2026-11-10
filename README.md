# 🔐 Password Security Analyzer

A Python password strength checker that evaluates passwords using **entropy analysis**, **pattern detection**, and **NIST-style policy presets**, with a CLI, JSON output, and meaningful exit codes for use in scripts.

![CI](https://github.com/23rob/password-strength-checker/actions/workflows/ci.yml/badge.svg)

---

## 🚀 Features

- 🔢 **Entropy-based strength scoring**
- 📏 **Minimum length enforcement**
- 🔠 Detects **uppercase, lowercase, numbers, and special characters**
- 🔁 **Weak pattern detection**
  - Repeated characters
  - Keyboard-style sequences
  - Common password structures
- 🏛️ **NIST-style policy validation**
- 💻 **Interactive CLI mode**
- ⚙️ **Command-line argument support**
- 📦 **JSON output (automation & tooling ready)**
- 🧪 Clear feedback with **prioritized improvement suggestions**

---

## 🧠 Strength Ratings

Passwords are evaluated and rated as:

- VERY WEAK
- WEAK
- MEDIUM
- STRONG
- VERY STRONG

Policy results:
- ✅ **PASS**
- ❌ **FAIL**

---

## 🛠 Technologies Used

- Python 3
- Standard Python libraries (`argparse`, `json`, `re`, `math`)
- Git & GitHub

---

## ▶️ How to Run

```bash
git clone https://github.com/23rob/password-strength-checker.git
cd password-strength-checker
pip install .
```

### Interactive mode
```bash
password-check
```

### Command-line mode
```bash
password-check -p "correct horse battery staple"           # default policy: nist
password-check -p "hunter2" --policy strict                # basic | nist | strict
password-check -p "correct horse battery staple" --json    # machine-readable
password-check --policy strict --show-policy               # print the rules and exit
python -m password_strength_checker -p "example"           # without installing the script
```

Passing `-p` puts the password in your shell history and process list. Use interactive mode for real passwords.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Passes the policy and rated STRONG or VERY STRONG |
| 1 | Passes the policy, rated MEDIUM |
| 2 | Fails the policy, or passes it but is rated WEAK |
| 3 | Passes the policy but is rated VERY WEAK (only possible with a very lenient policy) |

---

## 🧪 Development

```bash
pip install -e ".[dev]"
pytest --cov=password_strength_checker
ruff check .
```

35 tests cover entropy math, rating thresholds, each pattern detector, all three policies, and the CLI (JSON output, exit codes, interactive mode). CI runs on Python 3.9, 3.11, and 3.12.

---

## ⚠️ Limitations

- Entropy is estimated as `length x log2(character pool)`. That is a rough upper bound, not a measure of how guessable a password is. It overrates predictable passwords such as `Summer2024!`.
- The common-password list is a short built-in starter list, not a real breached-password corpus. For production use, check candidates against a service such as Have I Been Pwned's k-anonymity API.
- The policy presets are NIST-inspired (favor length, block common passwords, allow passphrases) and are not a compliance implementation of NIST SP 800-63B.

---

## 📄 License

MIT
