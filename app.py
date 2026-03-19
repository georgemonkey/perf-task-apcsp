from flask import Flask, request, jsonify
import random
import string

app = Flask(__name__)

def generate_password(length=12, use_upper=True, use_numbers=True, use_symbols=True):
    charset = string.ascii_lowercase
    if use_upper:
        charset += string.ascii_uppercase
    if use_numbers:
        charset += string.digits
    if use_symbols:
        charset += "!@#$%^&*()_+-=[]{}|;:',.<>/?`~"
    return ''.join(random.choice(charset) for _ in range(length))

@app.route("/generate", methods=["POST"])
def generate():
    data = request.get_json()
    length = int(data.get("length", 12))
    use_upper = data.get("uppercase", True)
    use_numbers = data.get("numbers", True)
    use_symbols = data.get("symbols", True)
    password = generate_password(length, use_upper, use_numbers, use_symbols)
    return jsonify({"password": password})

# Only run locally
if __name__ == "__main__":
    app.run()