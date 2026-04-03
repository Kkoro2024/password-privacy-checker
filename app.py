from flask import Flask, request, jsonify, render_template
import hashlib
import requests

app = Flask(__name__)

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

    ratings = {1: "Very Weak", 2: "Weak", 3: "Fair", 4: "Strong", 5: "Very Strong"}
    return {"score": score, "rating": ratings[score], "issues": issues}

def check_breach(password):
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
    for line in response.text.splitlines():
        hash_suffix, count = line.split(":")
        if hash_suffix == suffix:
            return {"breached": True, "count": int(count)}
    return {"breached": False, "count": 0}

@app.route("/check", methods=["POST"])
def check():
    password = request.json.get("password")
    strength = check_strength(password)
    breach = check_breach(password)
    return jsonify({"strength": strength, "breach": breach})

@app.route("/")
def home():
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)