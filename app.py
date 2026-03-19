from flask import Flask, request, jsonify, send_from_directory
import random, string, os

app = Flask(__name__, static_folder="frontend")

@app.route("/generate", methods=["POST"])
def generate():
    data = request.get_json()
    length = int(data.get("length", 12))
    use_upper = data.get("uppercase", True)
    use_numbers = data.get("numbers", True)
    use_symbols = data.get("symbols", True)

    charset = string.ascii_lowercase
    if use_upper: charset += string.ascii_uppercase
    if use_numbers: charset += string.digits
    if use_symbols: charset += "!@#$%^&*()_+-=[]{}|;:',.<>/?`~"

    password = ''.join(random.choice(charset) for _ in range(length))
    return jsonify({"password": password})

@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve_frontend(path):
    if path != "" and os.path.exists(os.path.join("frontend", path)):
        return send_from_directory("frontend", path)
    else:
        return send_from_directory("frontend", "index.html")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)