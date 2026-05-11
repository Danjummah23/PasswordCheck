"""
Password vulnerability checker.
Checks for weak patterns and breach exposure via Have I Been Pwned API.
"""

import argparse
import getpass
import hashlib
import json
import math
import os
import re
import secrets
import string
import sys
import urllib.request
from dataclasses import dataclass, field

# Enable ANSI color codes on Windows
if sys.platform == "win32":
    os.system("")

# ── Constants ─────────────────────────────────────────────────────────────────

KEYBOARD_ROWS = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
]

KEYBOARD_WALKS: list[str] = []
for _row in KEYBOARD_ROWS:
    for _length in range(3, len(_row) + 1):
        for _i in range(len(_row) - _length + 1):
            _seg = _row[_i : _i + _length]
            KEYBOARD_WALKS.append(_seg)
            KEYBOARD_WALKS.append(_seg[::-1])

LEET_MAP = {"@": "a", "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "$": "s", "!": "i"}

GUESSES_PER_SECOND = 10_000_000_000  # 10 billion (high-end GPU cracking fast hashes)

COMMON_WORDS = {
    # Generic weak words
    "password", "passwd", "pass", "secret", "login", "access", "welcome",
    "admin", "root", "user", "guest", "test", "demo", "temp", "default",
    "master", "letmein", "qwerty", "azerty", "changeme",
    # Emotions / relationships
    "love", "hate", "baby", "honey", "angel", "sweet", "cute", "dear",
    "babe", "lover", "heart", "kisses",
    # Animals
    "tiger", "lion", "eagle", "wolf", "bear", "shark", "snake", "horse",
    "panther", "falcon", "cobra", "viper", "kitten", "puppy", "bunny",
    # Colors
    "black", "white", "blue", "green", "yellow", "purple", "orange", "pink",
    "silver", "golden", "crimson", "scarlet",
    # Nature / weather
    "thunder", "lightning", "storm", "ocean", "river", "mountain", "forest",
    "desert", "valley", "cloud", "rainbow", "sunset", "sunrise", "flower",
    # Common first names
    "james", "john", "michael", "david", "robert", "william", "richard",
    "thomas", "charles", "george", "daniel", "matthew", "andrew", "joshua",
    "jennifer", "jessica", "ashley", "amanda", "melissa", "nicole",
    "elizabeth", "sarah", "emily", "emma", "olivia", "sophia", "taylor",
    # Pop culture / games
    "batman", "superman", "spiderman", "ironman", "captain", "marvel",
    "minecraft", "pokemon", "zelda", "mario", "sonic", "naruto", "anime",
    "gamer", "gaming", "player", "level", "hacker",
    # Tech / internet
    "internet", "network", "cyber", "matrix", "system", "computer",
    "laptop", "server", "digital", "online", "password",
    # Sports / hobbies
    "football", "soccer", "basketball", "baseball", "tennis", "cricket",
    "hockey", "volleyball", "swimming", "running", "fitness",
    # Food / drinks
    "coffee", "pizza", "burger", "cookie", "chocolate", "vanilla",
    "strawberry", "mango",
    # Brands
    "google", "amazon", "microsoft", "facebook", "twitter",
    "instagram", "netflix", "spotify", "youtube",
    # Adjectives / power words
    "cool", "super", "ultra", "mega", "alpha", "omega", "delta", "sigma",
    "ninja", "warrior", "hero", "king", "queen", "prince", "princess",
    "champion", "legend", "ghost", "phantom", "shadow", "dark", "light",
    "power", "force", "energy", "freedom", "justice", "glory", "victory",
    "infinity", "eternal", "immortal", "invincible",
    # Seasons / time
    "summer", "winter", "spring", "autumn", "monday", "friday",
    "january", "december", "forever", "always",
}

SCORE_ORDER = ["VERY WEAK", "WEAK", "FAIR", "GOOD", "STRONG"]

# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class CheckResult:
    name: str
    passed: bool
    message: str
    severity: str  # "critical", "warning", "info"


@dataclass
class PasswordReport:
    password: str
    checks: list[CheckResult] = field(default_factory=list)
    entropy_bits: float = 0.0
    crack_time: str = ""
    suggestion: str = ""

    @property
    def critical_count(self) -> int:
        return sum(1 for c in self.checks if not c.passed and c.severity == "critical")

    @property
    def warning_count(self) -> int:
        return sum(1 for c in self.checks if not c.passed and c.severity == "warning")

    @property
    def score(self) -> str:
        if self.critical_count >= 2:
            return "VERY WEAK"
        if self.critical_count == 1:
            return "WEAK"
        if self.warning_count >= 2:
            return "FAIR"
        if self.warning_count == 1:
            return "GOOD"
        return "STRONG"


# ── Entropy & crack time ──────────────────────────────────────────────────────

def _charset_size(password: str) -> int:
    size = 0
    if re.search(r"[a-z]", password): size += 26
    if re.search(r"[A-Z]", password): size += 26
    if re.search(r"\d", password):    size += 10
    if re.search(r"[^A-Za-z0-9]", password): size += 32
    return max(size, 1)


def _format_crack_time(seconds: float) -> str:
    if seconds < 1:           return "instantly"
    if seconds < 60:          return f"{seconds:.0f} second(s)"
    if seconds < 3_600:       return f"{seconds / 60:.0f} minute(s)"
    if seconds < 86_400:      return f"{seconds / 3_600:.1f} hour(s)"
    if seconds < 86_400 * 30: return f"{seconds / 86_400:.0f} day(s)"
    if seconds < 86_400 * 365:       return f"{seconds / (86_400 * 30):.0f} month(s)"
    if seconds < 86_400 * 365 * 1_000:     return f"{seconds / (86_400 * 365):.0f} year(s)"
    if seconds < 86_400 * 365 * 1_000_000: return f"{seconds / (86_400 * 365 * 1_000):.0f}K years"
    return "millions of years+"


def _compute_entropy(password: str) -> tuple[float, str]:
    cs = _charset_size(password)
    bits = len(password) * math.log2(cs)
    if bits > 512:
        return bits, "millions of years+"
    secs = (2.0 ** bits) / (2.0 * GUESSES_PER_SECOND)
    return bits, _format_crack_time(secs)


# ── Pattern checks ────────────────────────────────────────────────────────────

def _normalize_leet(password: str) -> str:
    return "".join(LEET_MAP.get(c, c) for c in password.lower())


def check_length(password: str) -> CheckResult:
    n = len(password)
    if n < 8:
        return CheckResult("Length", False, f"Too short ({n} chars, minimum 8)", "critical")
    if n < 12:
        return CheckResult("Length", False, f"Short ({n} chars, recommended 12+)", "warning")
    return CheckResult("Length", True, f"Acceptable length ({n} chars)", "info")


def check_character_variety(password: str) -> CheckResult:
    has_upper   = bool(re.search(r"[A-Z]", password))
    has_lower   = bool(re.search(r"[a-z]", password))
    has_digit   = bool(re.search(r"\d", password))
    has_special = bool(re.search(r"[^A-Za-z0-9]", password))
    count = sum([has_upper, has_lower, has_digit, has_special])
    missing = [
        label for flag, label in [
            (has_upper,   "uppercase"),
            (has_lower,   "lowercase"),
            (has_digit,   "digits"),
            (has_special, "special characters"),
        ] if not flag
    ]
    if count < 3:
        return CheckResult(
            "Character variety", False,
            f"Missing: {', '.join(missing)}",
            "warning" if count == 2 else "critical",
        )
    return CheckResult("Character variety", True, "Good character variety", "info")


def check_keyboard_walk(password: str) -> CheckResult:
    lower = password.lower()
    for walk in KEYBOARD_WALKS:
        if walk in lower:
            return CheckResult(
                "Keyboard walk", False,
                f"Contains keyboard sequence '{walk}'",
                "critical",
            )
    return CheckResult("Keyboard walk", True, "No keyboard walk patterns found", "info")


def check_repeated_chars(password: str) -> CheckResult:
    m = re.search(r"(.)\1{2,}", password)
    if m:
        return CheckResult(
            "Repeated chars", False,
            f"Contains repeated character '{m.group(1)}' x{len(m.group(0))}",
            "warning",
        )
    return CheckResult("Repeated chars", True, "No excessive character repetition", "info")


def check_sequential_numbers(password: str) -> CheckResult:
    for i in range(len(password) - 2):
        a, b, c = password[i : i + 3]
        if a.isdigit() and b.isdigit() and c.isdigit():
            if int(b) - int(a) == int(c) - int(b) == 1:
                return CheckResult(
                    "Sequential numbers", False,
                    f"Contains sequential number run '{a}{b}{c}...'",
                    "warning",
                )
    return CheckResult("Sequential numbers", True, "No sequential number patterns", "info")


def check_date_patterns(password: str) -> CheckResult:
    patterns = [
        (r"\b(19|20)\d{2}\b",                              "4-digit year"),
        (r"\b(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\b",    "MMDD pattern"),
        (r"\b(0[1-9]|[12]\d|3[01])(0[1-9]|1[0-2])\b",    "DDMM pattern"),
        (r"\b\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\b", "YYMMDD pattern"),
    ]
    for pattern, description in patterns:
        if re.search(pattern, password):
            return CheckResult(
                "Date pattern", False,
                f"Contains a {description} — dates are easy to guess",
                "warning",
            )
    return CheckResult("Date pattern", True, "No obvious date patterns", "info")


def check_leet_speak(password: str) -> CheckResult:
    if not any(c in password for c in LEET_MAP):
        return CheckResult("Leet speak", True, "No leet substitutions detected", "info")
    normalized = _normalize_leet(password)
    weak_roots = [
        "password", "admin", "letmein", "login", "welcome",
        "hello", "secret", "master", "dragon", "monkey", "shadow",
    ]
    for word in weak_roots:
        if word in normalized:
            return CheckResult(
                "Leet speak", False,
                f"Leet substitution of weak word detected ('{word}' variant)",
                "critical",
            )
    return CheckResult("Leet speak", True, "Leet substitutions present but no trivial word found", "info")


def check_dictionary_words(password: str) -> CheckResult:
    lower      = password.lower()
    normalized = _normalize_leet(password)
    for word in COMMON_WORDS:
        if len(word) >= 4 and (word in lower or word in normalized):
            return CheckResult(
                "Dictionary word", False,
                f"Contains common word '{word}' - vulnerable to dictionary attacks",
                "warning",
            )
    return CheckResult("Dictionary word", True, "No common dictionary words found", "info")


def check_personal_info(password: str, personal: dict) -> CheckResult:
    lower = password.lower()
    for key, value in personal.items():
        v = str(value).strip().lower()
        if len(v) >= 3 and v in lower:
            return CheckResult(
                "Personal info", False,
                f"Password contains your {key} — trivial to guess",
                "critical",
            )
    return CheckResult("Personal info", True, "No personal info detected", "info")


# ── Have I Been Pwned ─────────────────────────────────────────────────────────

def check_hibp(password: str) -> CheckResult:
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "PasswordChecker/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read().decode("utf-8")
    except Exception as exc:
        return CheckResult("HIBP breach check", True, f"Could not reach HIBP API: {exc}", "info")
    for line in body.splitlines():
        hash_suffix, count = line.split(":")
        if hash_suffix == suffix:
            return CheckResult(
                "HIBP breach check", False,
                f"Found in {int(count):,} known data breach(es)!",
                "critical",
            )
    return CheckResult("HIBP breach check", True, "Not found in known breaches", "info")


# ── Password suggestion ───────────────────────────────────────────────────────

def suggest_password(length: int = 18) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_=+"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c.isupper() for c in pw)
            and any(c.islower() for c in pw)
            and any(c.isdigit() for c in pw)
            and any(c in "!@#$%^&*-_=+" for c in pw)
        ):
            return pw


# ── Runner ────────────────────────────────────────────────────────────────────

ALL_CHECKS = [
    check_length,
    check_character_variety,
    check_keyboard_walk,
    check_repeated_chars,
    check_sequential_numbers,
    check_date_patterns,
    check_leet_speak,
    check_dictionary_words,
]


def analyse(
    password: str,
    skip_hibp: bool = False,
    personal: dict | None = None,
) -> PasswordReport:
    report = PasswordReport(password=password)
    for fn in ALL_CHECKS:
        report.checks.append(fn(password))
    if personal:
        report.checks.append(check_personal_info(password, personal))
    if not skip_hibp:
        report.checks.append(check_hibp(password))
    report.entropy_bits, report.crack_time = _compute_entropy(password)
    report.suggestion = suggest_password()
    return report


# ── Display ───────────────────────────────────────────────────────────────────

SEVERITY_LABEL = {"critical": "CRITICAL", "warning": "WARNING ", "info": "OK      "}
SCORE_COLOR = {
    "VERY WEAK": "\033[91m",
    "WEAK":      "\033[91m",
    "FAIR":      "\033[93m",
    "GOOD":      "\033[92m",
    "STRONG":    "\033[92m",
}
RESET = "\033[0m"
SEP   = "-" * 56


def print_report(report: PasswordReport, show_password: bool = False) -> None:
    print(f"\n{SEP}")
    if show_password:
        print(f"  Password  : {report.password}")
    score = report.score
    print(f"  Score     : {SCORE_COLOR.get(score, '')}{score}{RESET}")
    print(f"  Entropy   : {report.entropy_bits:.1f} bits")
    print(f"  Crack time: {report.crack_time}  (at 10B guesses/sec)")
    print(SEP)
    for c in report.checks:
        status = "OK      " if c.passed else SEVERITY_LABEL[c.severity]
        marker = "+" if c.passed else "x"
        print(f"  {marker} [{status}] {c.name}: {c.message}")
    print(SEP)
    print(f"  Critical issues : {report.critical_count}")
    print(f"  Warnings        : {report.warning_count}")
    if report.critical_count > 0 or report.warning_count > 0:
        print(f"  Suggestion      : {report.suggestion}")
    print(SEP + "\n")


def print_report_json(report: PasswordReport, show_password: bool = False) -> None:
    data: dict = {
        "score":          report.score,
        "entropy_bits":   round(report.entropy_bits, 2),
        "crack_time":     report.crack_time,
        "critical_count": report.critical_count,
        "warning_count":  report.warning_count,
        "suggestion":     report.suggestion if (report.critical_count or report.warning_count) else None,
        "checks": [
            {"name": c.name, "passed": c.passed, "severity": c.severity, "message": c.message}
            for c in report.checks
        ],
    }
    if show_password:
        data["password"] = report.password
    print(json.dumps(data, indent=2))


# ── CLI ───────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="password_check",
        description="Check a password for vulnerabilities and breach exposure.",
    )
    parser.add_argument(
        "password", nargs="?",
        help="Password to check. Omit to enter interactive mode.",
    )
    parser.add_argument(
        "--no-hibp", action="store_true",
        help="Skip the Have I Been Pwned breach check (offline mode).",
    )
    parser.add_argument(
        "--show-password", action="store_true",
        help="Print the password in the report (disabled by default).",
    )
    parser.add_argument(
        "--personal", action="store_true",
        help="Prompt for name, username, and birth year to check against the password.",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output results as JSON.",
    )
    parser.add_argument(
        "--min-score",
        choices=SCORE_ORDER,
        metavar="LEVEL",
        help=f"Exit with code 1 if the score is below LEVEL. Choices: {', '.join(SCORE_ORDER)}",
    )
    parser.add_argument(
        "--batch", metavar="FILE",
        help="Check each password on a line in FILE and print a summary.",
    )
    return parser


def _collect_personal_info() -> dict:
    print("  Enter personal info to check against (press Enter to skip):")
    name      = input("    Name       : ").strip()
    username  = input("    Username   : ").strip()
    birthyear = input("    Birth year : ").strip()
    print()
    return {"name": name, "username": username, "birth year": birthyear}


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    min_score_index = SCORE_ORDER.index(args.min_score) if args.min_score else None

    # ── Batch mode ────────────────────────────────────────────────────────────
    if args.batch:
        try:
            with open(args.batch, encoding="utf-8") as fh:
                passwords = [line.rstrip("\n") for line in fh if line.strip()]
        except OSError as exc:
            sys.exit(f"Cannot open file: {exc}")
        print(f"Checking {len(passwords)} password(s)...\n")
        tally = {s: 0 for s in SCORE_ORDER}
        worst = len(SCORE_ORDER) - 1
        for pw in passwords:
            report = analyse(pw, skip_hibp=args.no_hibp)
            tally[report.score] += 1
            worst = min(worst, SCORE_ORDER.index(report.score))
            masked = pw[:1] + "*" * (len(pw) - 1) if not args.show_password else pw
            print(f"  {masked:<30} -> {report.score}")
        print("\nSummary:")
        for score, count in tally.items():
            if count:
                print(f"  {score:<10} {count}")
        if min_score_index is not None and worst < min_score_index:
            sys.exit(1)
        return

    # ── Collect personal info once (reused in interactive loop) ──────────────
    personal: dict | None = None
    if args.personal:
        personal = _collect_personal_info()

    # ── Direct mode ───────────────────────────────────────────────────────────
    if args.password:
        report = analyse(args.password, skip_hibp=args.no_hibp, personal=personal)
        if args.json:
            print_report_json(report, show_password=args.show_password)
        else:
            print_report(report, show_password=args.show_password)
        if min_score_index is not None and SCORE_ORDER.index(report.score) < min_score_index:
            sys.exit(1)
        return

    # ── Interactive loop ──────────────────────────────────────────────────────
    print("Password Vulnerability Checker  (type 'quit' or press Ctrl+C to exit)")
    print(SEP)
    worst = len(SCORE_ORDER) - 1
    while True:
        try:
            password = getpass.getpass("Enter password: ")
        except (KeyboardInterrupt, EOFError):
            print("\nBye.")
            break
        if password.lower() in ("quit", "exit", "q"):
            print("Bye.")
            break
        if not password:
            print("  (no input, try again)\n")
            continue
        report = analyse(password, skip_hibp=args.no_hibp, personal=personal)
        worst = min(worst, SCORE_ORDER.index(report.score))
        if args.json:
            print_report_json(report, show_password=args.show_password)
        else:
            print_report(report, show_password=args.show_password)
    if min_score_index is not None and worst < min_score_index:
        sys.exit(1)


if __name__ == "__main__":
    main()
