import csv, hashlib, hmac, math, os, re, secrets, string, urllib.request, urllib.error
from flask import Flask, request, jsonify, send_from_directory

app = Flask(__name__, static_folder="static")

# ── common password list ──────────────────────────────────────────────────────

def load_common(path):
    if not os.path.isfile(path):
        return set()
    with open(path, newline="", encoding="utf-8", errors="ignore") as f:
        return {row[0].strip() for row in csv.reader(f) if row}

_here = os.path.dirname(os.path.abspath(__file__))
COMMON = load_common(os.path.join(_here, "commonpwds.csv"))

def is_common(pw):
    return pw in COMMON or pw.lower() in COMMON

# ── strength ──────────────────────────────────────────────────────────────────

def strength(pw):
    n = len(pw)
    has = {
        "upper":  bool(re.search(r'[A-Z]', pw)),
        "lower":  bool(re.search(r'[a-z]', pw)),
        "digit":  bool(re.search(r'\d', pw)),
        "symbol": bool(re.search(r'[^A-Za-z0-9]', pw)),
    }
    score = (3 if n >= 16 else 2 if n >= 12 else 1 if n >= 8 else 0) + sum(has.values())
    if re.search(r'(.)\1{2,}', pw): score -= 1
    if re.search(r'(012|123|234|345|456|567|678|789|abc|bcd)', pw.lower()): score -= 1
    score = max(0, min(score, 10))

    pool = sum([has["lower"]*26, has["upper"]*26, has["digit"]*10, has["symbol"]*32]) or 1
    entropy = round(n * math.log2(pool))

    label = "strong" if score >= 8 else "moderate" if score >= 5 else "weak"
    tips = []
    if n < 12:            tips.append("use 12+ characters")
    if not has["upper"]:  tips.append("add uppercase letters")
    if not has["lower"]:  tips.append("add lowercase letters")
    if not has["digit"]:  tips.append("add numbers")
    if not has["symbol"]: tips.append("add symbols (!@#$...)")
    if re.search(r'(.)\1{2,}', pw): tips.append("avoid repeated characters")
    if re.search(r'(012|123|234|345|456|567|678|789|abc|bcd)', pw.lower()): tips.append("avoid sequential patterns")

    return {"score": score, "label": label, "entropy": entropy, "tips": tips, "checks": has, "length": n}

# ── hibp check ────────────────────────────────────────────────────────────────

def check_hibp(pw):
    sha1 = hashlib.sha1(pw.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    req = urllib.request.Request(
        f"https://api.pwnedpasswords.com/range/{prefix}",
        headers={"User-Agent": "passguard/2.0"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            for line in resp.read().decode().splitlines():
                h, n = line.split(":")
                if hmac.compare_digest(h, suffix):
                    return int(n)
        return 0
    except Exception:
        return None

# ── generator ─────────────────────────────────────────────────────────────────

WORDS = [
    "amber","blaze","cedar","delta","ember","frost","gleam","haven",
    "ivory","jumbo","karma","lunar","maple","nexus","orbit","polar",
    "quartz","river","storm","twist","ultra","vault","whale","xenon",
    "yacht","zesty","brave","coral","dream","eagle","flame","grape",
]

def gen_password(length=20, upper=True, digits=True, symbols=True, no_ambiguous=False):
    pool = string.ascii_lowercase
    if upper:        pool += string.ascii_uppercase
    if digits:       pool += string.digits
    if symbols:      pool += "!@#$%^&*()-_=+"
    if no_ambiguous: pool = pool.translate(str.maketrans("", "", "0Ol1I"))

    required = [secrets.choice(string.ascii_lowercase)]
    if upper:   required.append(secrets.choice(string.ascii_uppercase))
    if digits:  required.append(secrets.choice(string.digits))
    if symbols: required.append(secrets.choice("!@#$%^&*"))

    rest = [secrets.choice(pool) for _ in range(length - len(required))]
    combined = required + rest
    secrets.SystemRandom().shuffle(combined)
    return "".join(combined)

def gen_passphrase(n=4):
    words = [secrets.choice(WORDS) for _ in range(n)]
    sep = secrets.choice(["-", ".", "_"])
    return sep.join(words) + str(secrets.randbelow(900) + 100) + secrets.choice("!@#$")

# ── routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory("static", "index.html")

@app.route("/api/check", methods=["POST"])
def api_check():
    pw = request.json.get("password", "")
    if not pw:
        return jsonify({"error": "no password provided"}), 400

    s = strength(pw)
    common = is_common(pw) if COMMON else None
    hibp = check_hibp(pw)

    return jsonify({
        "strength": s,
        "common": common,
        "common_list_size": len(COMMON),
        "hibp_count": hibp,   # None = network error, 0 = clean, N = breached
    })

@app.route("/api/generate", methods=["POST"])
def api_generate():
    data = request.json or {}
    mode = data.get("mode", "random")

    if mode == "passphrase":
        n = int(data.get("words", 4))
        results = [gen_passphrase(n) for _ in range(5)]
    else:
        length     = int(data.get("length", 20))
        upper      = bool(data.get("upper", True))
        digits     = bool(data.get("digits", True))
        symbols    = bool(data.get("symbols", True))
        no_ambig   = bool(data.get("no_ambiguous", False))
        count      = int(data.get("count", 5))
        results = [gen_password(length, upper, digits, symbols, no_ambig) for _ in range(count)]

    return jsonify({
        "passwords": [{"value": p, "strength": strength(p)} for p in results]
    })

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 3030))
    app.run(host="0.0.0.0", port=port)

