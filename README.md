# 🔐 Password Strength Checker

A professional, Python-based password strength checker that evaluates passwords using **entropy analysis**, **pattern detection**, and **NIST-style security policies**.  
Designed for **cybersecurity portfolios**, **internships**, and **automation-friendly CLI usage**.

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

### 1️⃣ Interactive Mode
```bash
python projects/password_checker.py
