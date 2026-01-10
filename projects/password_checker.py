password = input("Enter a password: ")

score = 0

# 1) Length check
if len(password) >= 8:
    score += 1

# 2) Contains a number
if any(char.isdigit() for char in password):
    score += 1

# 3) Contains an uppercase letter
if any(char.isupper() for char in password):
    score += 1

# 4) Contains a special character
specials = "!@#$%^&*()"
if any(char in specials for char in password):
    score += 1

# Result
if score <= 1:
    print("Very weak password")
elif score == 2:
    print("Weak password")
elif score == 3:
    print("Good password")
else:
    print("Strong password")