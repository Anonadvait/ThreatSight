import re
from urllib.parse import urlparse
from rapidfuzz import fuzz


def extract_domain(url):
    if "://" not in url:
        url = "http://" + url

    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    if domain.startswith("www."):
        domain = domain[4:]

    return domain


def normalize_text(text):
    replacements = str.maketrans({
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "@": "a",
        "$": "s"
    })
    text = text.lower().translate(replacements)
    return re.sub(r"[^a-z0-9]", "", text)


def check_url(url):
    score = 0
    reasons = []

    suspicious_words = [
        "login",
        "verify",
        "secure",
        "update",
        "bank",
        "paypal"
    ]

    domain = extract_domain(url)
    normalized_domain = normalize_text(domain)
    normalized_url = normalize_text(url)

    whitelist = [
        "google.com",
        "github.com",
        "microsoft.com",
        "amazon.com",
        "facebook.com",
        "instagram.com"
    ]

    if domain in whitelist:
        return 0, ["Trusted domain found in whitelist"]

    for word in suspicious_words:
        if word in normalized_url:
            score += 15
            reasons.append(f"Contains suspicious word: {word}")

    if len(url) > 50:
        score += 10
        reasons.append("URL is unusually long")

    ip_pattern = r"\d+\.\d+\.\d+\.\d+"
    if re.search(ip_pattern, url):
        score += 25
        reasons.append("Uses IP address instead of domain")

    known_brands = [
        "paypal",
        "google",
        "microsoft",
        "amazon",
        "facebook",
        "instagram"
    ]

    for brand in known_brands:
        brand_normalized = normalize_text(brand)

        if brand_normalized in normalized_domain and domain != f"{brand}.com":
            score += 30
            reasons.append(f"Possible impersonation of {brand}")

        similarity = fuzz.partial_ratio(normalized_domain, brand_normalized)

        if similarity >= 80 and domain != f"{brand}.com":
            score += 20
            reasons.append(f"Looks similar to {brand} ({similarity}% match)")

    return score, reasons