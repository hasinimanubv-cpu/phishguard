"""Offline phishing indicator rules. Submitted URLs are inspected as text only."""
import re
from urllib.parse import urlparse

URL_RE = re.compile(r"https?://[^\s<>\"']+", re.I)
URGENT = re.compile(r"\b(urgent|immediately|within \d+ hours?|suspended|locked|limited time|act now|final warning|avoid (?:account )?closure|expire[sd]? today)\b", re.I)
CREDENTIAL = re.compile(r"\b(password|passcode|login|sign[ -]?in|verify (?:your )?(?:account|identity)|social security|bank details|card number|one[ -]?time code|otp|security code)\b", re.I)
OTHER = re.compile(r"\b(prize|winner|claim your reward|gift card|wire transfer|keep this secret|enable macros|unexpected attachment|scan this qr)\b", re.I)
SHORTENER = re.compile(r"(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|cutt\.ly|ow\.ly|buff\.ly)$", re.I)
BRANDS = {"example bank": "examplebank.invalid", "northstar": "northstar.invalid", "contoso": "contoso.invalid", "fabrikam": "fabrikam.invalid"}
WEIGHTS = {"U": 0.25, "S": 0.20, "C": 0.20, "L": 0.15, "D": 0.10, "P": 0.10}


def _clean_url(value: str) -> str:
    value = value.strip().strip("<>")
    return value if not value or re.match(r"^https?://", value, re.I) else "https://" + value


def _host(value: str) -> str:
    try:
        return (urlparse(_clean_url(value)).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def detect_indicators(message: str = "", url: str | None = None, sender: str | None = None) -> tuple[dict, list[dict]]:
    """Return six binary factor flags and explainable indicators."""
    content = message or ""
    urls = [m.rstrip(".,);]}") for m in URL_RE.findall(content)]
    if url and url.strip():
        urls.append(_clean_url(url))
    factors = {key: 0 for key in WEIGHTS}
    indicators: list[dict] = []

    def add(code, factor, label, evidence, explanation):
        if factors[factor]:
            return
        factors[factor] = 1
        indicators.append({"code": code, "factor": factor, "label": label,
                           "severity": "high" if WEIGHTS[factor] >= .20 else "medium",
                           "evidence": evidence[:180], "explanation": explanation})

    for raw in urls:
        host = _host(raw)
        try:
            parsed = urlparse(_clean_url(raw))
            risky = ("@" in parsed.netloc or host.startswith("xn--") or ".xn--" in host or
                     bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host)))
        except ValueError:
            risky = False
        if risky:
            add("suspicious_url", "U", "Suspicious URL detected", raw,
                "The URL uses an IP address, punycode, or user-info syntax that can obscure its destination.")
            break
        if host and SHORTENER.search(host):
            add("shortened_url", "U", "Shortened URL detected", raw,
                "A link shortener obscures the final destination. Check the destination independently.")
            break

    sender_host = _host(sender or "") if sender and "@" in sender else (sender.lower().split("@")[-1] if sender and "@" in sender else "")
    claimed_brand = next(((name, domain) for name, domain in BRANDS.items() if name in content.lower()), None)
    sender_mismatch = bool(sender_host and claimed_brand and not (sender_host == claimed_brand[1] or sender_host.endswith("." + claimed_brand[1])))
    free_mail = bool(sender_host and re.search(r"(^|\.)(gmail\.com|yahoo\.com|outlook\.com|hotmail\.com)$", sender_host))
    if sender_mismatch or (free_mail and claimed_brand):
        add("suspicious_sender", "S", "Suspicious sender pattern detected", sender or sender_host,
            "The sender domain does not match the fictional organization named in the message.")

    match = CREDENTIAL.search(content)
    if match:
        add("credential_request", "C", "Credential request detected", match.group(0),
            "The message refers to passwords, sign-in details, or a one-time/security code.")
    match = URGENT.search(content)
    if match:
        add("urgent_language", "L", "Urgent or threatening language detected", match.group(0),
            "Pressure or threats can push a recipient to act before checking the request.")
    match = OTHER.search(content)
    if match:
        add("other_phishing_cue", "P", "Other common phishing indicator detected", match.group(0),
            "This phrase is commonly used in deceptive prize, payment, secrecy, or attachment lures.")

    for raw in urls:
        host = _host(raw)
        if not host:
            continue
        brand = next(((name, domain) for name, domain in BRANDS.items() if name.replace(" ", "") in host.replace("-", "").replace(".", "")), None)
        labels = host.split(".")
        malformed = (host.startswith("xn--") or ".xn--" in host or len(labels) > 4 or
                     bool(re.search(r"\d{1,3}(?:\.\d{1,3}){3}", host)))
        impersonation = bool(brand and host != brand[1] and not host.endswith("." + brand[1]))
        if malformed or impersonation:
            add("domain_anomaly", "D", "Domain anomaly detected", host,
                "The domain has an unusual structure or resembles a fictional brand without using its expected domain.")
            break
    return factors, indicators
