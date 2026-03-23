
import csv, hashlib, hmac, math, os, re, secrets, string, sys, urllib.request, urllib.error, getpass

# ── colors ────────────────────────────────────────────────────────────────────

R = "\033[0m"
BOLD = "\033[1m"
RED  = "\033[91m"
GRN  = "\033[92m"
YLW  = "\033[93m"
CYN  = "\033[96m"
GRY  = "\033[90m"

def r(s): return f"{RED}{s}{R}"
def g(s): return f"{GRN}{s}{R}"
def y(s): return f"{YLW}{s}{R}"
def c(s): return f"{CYN}{s}{R}"
def gr(s): return f"{GRY}{s}{R}"
def b(s): return f"{BOLD}{s}{R}"

# ── common password list ──────────────────────────────────────────────────────

def load_common(path):
    if not os.path.isfile(path):
        return set()
    with open(path, newline="", encoding="utf-8", errors="ignore") as f:
        return {row[0].strip() for row in csv.reader(f) if row}

_here = os.path.dirname(os.path.abspath(__file__))
COMMON = load_common(os.path.join(_here, "commonpwds.csv")) or \
         load_common(os.path.join(os.getcwd(), "commonpwds.csv"))

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
    entropy = n * math.log2(pool)

    label = g("strong") if score >= 8 else y("moderate") if score >= 5 else r("weak")
    tips = []
    if n < 12:            tips.append("use 12+ characters")
    if not has["upper"]:  tips.append("add uppercase letters")
    if not has["lower"]:  tips.append("add lowercase letters")
    if not has["digit"]:  tips.append("add numbers")
    if not has["symbol"]: tips.append("add symbols")

    return score, label, entropy, tips

def show_strength(pw):
    score, label, entropy, tips = strength(pw)
    bar = "█" * int(score * 2) + "░" * (20 - int(score * 2))
    print(f"\n  strength  {bar}  {label}")
    print(f"  entropy   {c(f'{entropy:.0f} bits')}  ·  length {c(str(len(pw)))}")
    if tips:
        print(f"\n  {y('tips:')}")
        for t in tips:
            print(f"    → {t}")

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
    except urllib.error.URLError as e:
        print(f"\n  {y('network error:')} {e.reason}")
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
    if upper:   pool += string.ascii_uppercase
    if digits:  pool += string.digits
    if symbols: pool += "!@#$%^&*()-_=+"
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

# ── helpers ───────────────────────────────────────────────────────────────────

def ask(prompt, default=None):
    hint = f" [{default}]" if default is not None else ""
    return input(f"  {prompt}{gr(hint)}: ").strip() or default

def ask_yn(prompt, default=True):
    raw = ask(prompt, "Y/n" if default else "y/N").lower()
    if raw in ("y/n", "y", "yes"): return True if raw != "y/n" else default
    return raw in ("y", "yes")

def ask_int(prompt, default, lo, hi):
    while True:
        raw = ask(prompt, str(default))
        try:
            v = int(raw)
            if lo <= v <= hi: return v
        except (ValueError, TypeError):
            pass
        print(f"  {y(f'enter a number between {lo} and {hi}')}")

def div(): print(f"\n  {gr('─' * 50)}")

# ── flows ─────────────────────────────────────────────────────────────────────

def flow_check():
    src = f"local list ({len(COMMON):,}) + hibp" if COMMON else "hibp only"
    print(f"\n  {b('check password')}  {gr('· ' + src)}")
    print(f"  {gr('only a 5-char sha1 prefix is sent to hibp — password never leaves your machine')}\n")

    pw = getpass.getpass("  password: ")
    if not pw:
        print(f"  {y('no password entered')}")
        return

    show_strength(pw)
    print()

    if COMMON:
        if is_common(pw):
            print(f"  {r('✗  in local common-password list — change this immediately')}")
        else:
            print(f"  {g('✓  not in local common-password list')}  {gr(f'({len(COMMON):,} checked)')}")

    print(f"\n  {gr('querying hibp...')}")
    count = check_hibp(pw)
    if count is None:
        print(f"  {y('could not reach hibp — check your connection')}")
    elif count == 0:
        print(f"  {g('✓  not found in any known breach')}  {gr('(haveibeenpwned)')}")
    else:
        print(f"  {r(f'✗  found {count:,} times in known breaches')}  {gr('(haveibeenpwned)')}")
    div()


def flow_generate():
    print(f"\n  {b('generate password')}\n")
    mode = ask("type: 1 random  2 passphrase", "1")

    if mode == "2":
        n = ask_int("word count", 4, 3, 8)
        print(f"\n  {gr('passphrases:')}\n")
        for i in range(5):
            pp = gen_passphrase(n)
            _, label, entropy, _ = strength(pp)
            print(f"  {c(str(i+1))}.  {b(pp)}  {gr('·')}  {label}  {gr(str(int(entropy)) + ' bits')}")
    else:
        length   = ask_int("length", 20, 8, 128)
        upper    = ask_yn("uppercase", True)
        digits   = ask_yn("numbers", True)
        symbols  = ask_yn("symbols", True)
        no_ambig = ask_yn("exclude ambiguous chars (0,O,l,1,I)", False)
        count    = ask_int("how many", 5, 1, 20)
        print(f"\n  {gr('passwords:')}\n")
        for i in range(count):
            pw = gen_password(length, upper, digits, symbols, no_ambig)
            _, label, entropy, _ = strength(pw)
            print(f"  {c(str(i+1))}.  {b(pw)}  {gr('·')}  {label}  {gr(str(int(entropy)) + ' bits')}")

    print()
    if ask_yn("check one against hibp?", False):
        pw = input("  paste password: ").strip()
        if pw:
            count = check_hibp(pw)
            if count is None:
                print(f"  {y('could not reach hibp')}")
            elif count == 0:
                print(f"  {g('✓  not found in any known breach')}")
            else:
                print(f"  {r(f'✗  found {count:,} times in known breaches')}")
    div()


def flow_analyze():
    print(f"\n  {b('analyze strength')}\n")
    pw = getpass.getpass("  password: ")
    if not pw:
        print(f"  {y('no password entered')}")
        return
    show_strength(pw)
    if COMMON:
        print()
        if is_common(pw):
            print(f"  {r('✗  in local common-password list')}")
        else:
            print(f"  {g('✓  not in local common-password list')}  {gr(f'({len(COMMON):,} checked)')}")
    div()

# ── main ──────────────────────────────────────────────────────────────────────

def main():
    print(f"\n  {b('passguard')}  {gr('· password leak checker & generator')}")
    if COMMON:
        print(f"  {gr(f'loaded {len(COMMON):,} common passwords')}")
    else:
        print(f"  {y('commonpwds.csv not found — local check disabled')}")

    while True:
        print(f"\n  {c('1')} check leaks   {c('2')} generate   {c('3')} analyze   {c('q')} quit\n")
        choice = input("  → ").strip().lower()
        if   choice == "1": flow_check()
        elif choice == "2": flow_generate()
        elif choice == "3": flow_analyze()
        elif choice in ("q", "quit", "exit"):
            print(f"\n  {gr('bye.')}\n")
            sys.exit(0)
        else:
            print(f"  {y('enter 1, 2, 3, or q')}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {gr('bye.')}\n")
        sys.exit(0)