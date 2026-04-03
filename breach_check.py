import requests
import hashlib

def check_strength(password):
    issues = []
    score = 0
    
    if len(password) < 8:
        issues.append("too short - use at least 8 characters")
    else:
        score += 1
        
    if not any(c.isupper() for c in password):
        issues.append("no uppercase letters")
    else:
        score += 1
        
    if not any(c.islower() for c in password):
        issues.append("no lowercase letters")
    else:
        score += 1
        
    if not any(c.isdigit() for c in password):
        issues.append("no numbers")
    else:
        score += 1
        
    if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        issues.append("no special characters")
    else:
        score += 1

    ratings = {
        1: "Very Weak",
        2: "Weak",
        3: "Fair",
        4: "Strong",
        5: "Very Strong"
    }
    
    print(f"Password Strength: {score}/5 — {ratings[score]}")
    
    if issues:
        print("Issues:", ", ".join(issues))

def check_password(password):
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    
    response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
    
    for line in response.text.splitlines():
        hash_suffix, count = line.split(":")
        if hash_suffix == suffix:
            print(f"WARNING: This password was found in {count} data breaches!")
            return
    
    print("Good news: This password hasn't been found in any breaches.")

while True:
    password = input("\nEnter a password to check (or type 'quit' to exit): ")
    
    if password == "quit":
        print("Goodbye! Stay safe online.")
        break
    
    check_strength(password)
    check_password(password)