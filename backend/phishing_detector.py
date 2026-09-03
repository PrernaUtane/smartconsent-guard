# phishing_detector.py
# Enhanced heuristic engine – with registrable domain matching for false positive prevention

import re
from urllib.parse import urlparse

# ✅ Legitimate domains that should never be flagged as phishing
# These are registrable domains (e.g., "amazon.com" matches "www.amazon.com" via registrable domain matching)
LEGITIMATE_DOMAINS = {
    "amazon.com", "paypal.com", "google.com", "github.com",
    "microsoft.com", "apple.com", "facebook.com", "netflix.com",
    "spotify.com", "twitter.com", "instagram.com", "linkedin.com",
    "yahoo.com", "ebay.com", "walmart.com", "target.com",
    "bestbuy.com", "adobe.com", "whatsapp.com", "youtube.com",
    "wikipedia.org", "reddit.com", "stackoverflow.com", "medium.com"
}

# Legitimate brands (for typosquatting and impersonation)
BRANDS = [
    "google", "paypal", "amazon", "apple", "microsoft", "facebook",
    "twitter", "instagram", "whatsapp", "netflix", "spotify", "github",
    "linkedin", "yahoo", "ebay", "walmart", "target", "bestbuy", "adobe"
]

# Common scam/store keywords that phishers use in domains
SCAM_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm", "billing", "signin",
    "bet", "win", "bonus", "free", "shop", "store", "click", "promo", "offer", "gift",
    "claim", "reward", "prize", "cash", "money", "pay", "wallet", "crypto", "bitcoin"
]

# High-risk free hosting platforms (higher penalty)
HIGH_RISK_HOSTING = [
    '.pages.dev', '.web.app', '.firebaseapp.com', '.workers.dev',
    '.github.io', '.netlify.app', '.vercel.app', '.herokuapp.com'
]

# Suspicious TLDs and DDNS
SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.cc', '.pw', '.gq', '.ooo',
    '.icu', '.download', '.click', '.stream', '.live', '.work', '.date',
    '.buzz', '.men', '.loan', '.win', '.bid', '.trade', '.webcam', '.science',
    '.party', '.review', '.accountant', '.faith', '.racing', '.country',
    '.ddns.net', '.no-ip.org', '.duckdns.org', '.dynu.net', '.freeddns.org',
    '.hopto.org', '.zapto.org', '.sytes.net', '.myftp.org',
    '.bit.ly', '.tinyurl.com', '.shorturl.at', '.is.gd', '.tiny.cc',
    # Free hosting subdomains (duplicated for safety)
    '.pages.dev', '.web.app', '.firebaseapp.com', '.workers.dev',
    '.github.io', '.netlify.app', '.vercel.app', '.herokuapp.com'
]

def detect(url):
    """
    Analyze a URL for phishing indicators.
    
    Returns:
        dict: {
            "is_phishing": bool,
            "risk_score": int (0-100),
            "reasons": list[str]
        }
    """
    risk_score = 0
    reasons = []

    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path.split('/')[0]
    path = parsed.path
    scheme = parsed.scheme
    domain_lower = domain.lower()

    # ✅ Extract registrable domain (e.g., "amazon.com" from "www.amazon.com")
    def get_registrable_domain(domain_lower):
        parts = domain_lower.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])  # Last two parts: example.com
        return domain_lower

    registrable_domain = get_registrable_domain(domain_lower)

    # ✅ Skip phishing checks for legitimate domains (including subdomains)
    if registrable_domain in LEGITIMATE_DOMAINS:
        return {
            "is_phishing": False,
            "risk_score": 0,
            "reasons": ["Legitimate domain"]
        }

    # ----- 1. HIGH-RISK FREE HOSTING (e.g., .pages.dev) -----
    is_high_risk_hosting = False
    for hr in HIGH_RISK_HOSTING:
        if domain.endswith(hr):
            risk_score += 40
            reasons.append(f"Free hosting platform ({hr}) commonly used for phishing")
            is_high_risk_hosting = True
            break

    # ----- 2. Suspicious TLD / DDNS (only if not already caught above) -----
    if not is_high_risk_hosting:
        for sus in SUSPICIOUS_TLDS:
            if domain.endswith(sus):
                risk_score += 30
                reasons.append(f"Suspicious domain/TLD ({sus})")
                break

    # ----- 3. Brand impersonation + scam keywords -----
    found_terms = []
    # Check brands
    for brand in BRANDS:
        if brand in domain_lower:
            found_terms.append(brand)
        # Typosquatting (replace common substitutions)
        elif brand in domain_lower.replace('0', 'o').replace('1', 'i').replace('4', 'a'):
            found_terms.append(brand)
    # Check scam keywords
    for kw in SCAM_KEYWORDS:
        if kw in domain_lower or kw in path.lower():
            found_terms.append(kw)

    if found_terms:
        risk_score += 30
        reasons.append(f"Brand/scam keyword impersonation ({', '.join(found_terms[:3])})")

    # ----- 4. Unusually long domain -----
    domain_part = domain.split('.')[0]
    if len(domain_part) > 30:
        risk_score += 10
        reasons.append(f"Unusually long domain ({len(domain_part)} chars)")

    # ----- 5. Excessive hyphens -----
    if domain.count('-') > 2:
        risk_score += 15
        reasons.append(f"Excessive hyphens ({domain.count('-')} hyphens)")

    # ----- 6. Raw IP address -----
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    if re.search(ip_pattern, domain):
        risk_score += 25
        reasons.append("Raw IP address used instead of domain")

    # ----- 7. HTTP on sensitive pages -----
    if scheme == 'http' and any(kw in (domain_lower + path.lower()) for kw in ['login','verify','secure','bank','paypal']):
        risk_score += 10
        reasons.append("HTTP (not HTTPS) on sensitive page")

    # ----- 8. Suspicious path segments -----
    suspicious_paths = ['cgi-bin', 'cgi-ent', 'ssl', 'login', 'secure', 'verify', 'account', 'update', 'confirm']
    for sp in suspicious_paths:
        if sp in path.lower():
            risk_score += 10
            reasons.append(f"Suspicious path segment ({sp})")
            break

    # ----- 9. Numeric-heavy domain -----
    domain_alpha = re.sub(r'[^a-zA-Z]', '', domain_part)
    if len(domain_alpha) / max(len(domain_part), 1) < 0.6 and len(domain_part) > 5:
        risk_score += 10
        reasons.append("Domain contains excessive numbers (likely generated)")

    # Cap at 100
    risk_score = min(risk_score, 100)

    return {
        "is_phishing": risk_score > 60,
        "risk_score": risk_score,
        "reasons": reasons
    }