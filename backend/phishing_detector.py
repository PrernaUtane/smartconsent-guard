# phishing_detector.py
# Purpose: Detect phishing URLs using heuristic rules
# Author: Member B (Chandsi Turkar)
# Input: URL string
# Output: {is_phishing, risk_score, reasons}

import re
from urllib.parse import urlparse

def detect(url):
    """
    Analyze a URL and return phishing risk assessment.
    
    Args:
        url (str): The URL to analyze (e.g., "https://paypal-login.tk")
    
    Returns:
        dict: {
            "is_phishing": bool,
            "risk_score": int (0-100),
            "reasons": list of strings
        }
    """
    
    # Initialize variables
    risk_score = 0
    reasons = []
    
    # --- RULE 1: Suspicious Top-Level Domains (TLDs) ---
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', 
                       '.cc', '.pw', '.gq', '.ooo', '.icu', '.download', 
                       '.click', '.stream', '.live', '.work', '.date']
    for tld in suspicious_tlds:
        if url.lower().endswith(tld):
            risk_score += 30
            reasons.append(f"Suspicious TLD ({tld})")
            break
    
    # --- RULE 2: Brand Keyword Impersonation ---
    brand_keywords = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 
                      'facebook', 'bank', 'login', 'verify', 'secure', 
                      'signin', 'account', 'update', 'confirm', 'billing']
    found_brands = []
    for brand in brand_keywords:
        if brand in url.lower():
            found_brands.append(brand)
    if found_brands:
        risk_score += 30
        reasons.append(f"Brand impersonation detected ({', '.join(found_brands[:3])})")
    
    # --- RULE 3: Unusually Long Domain ---
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path.split('/')[0]
    if len(domain) > 30:
        risk_score += 10
        reasons.append(f"Unusually long domain ({len(domain)} chars)")
    
    # --- RULE 4: Excessive Hyphens ---
    if domain.count('-') > 2:
        risk_score += 15
        reasons.append(f"Excessive hyphens ({domain.count('-')} hyphens)")
    
    # --- RULE 5: Raw IP Address ---
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    if re.search(ip_pattern, domain):
        risk_score += 25
        reasons.append("Raw IP address used instead of domain")
    
    # --- RULE 6: HTTP on Sensitive Pages ---
    if url.startswith('http://') and any(keyword in url.lower() for keyword in ['login', 'verify', 'secure', 'bank', 'paypal']):
        risk_score += 10
        reasons.append("HTTP (not HTTPS) on sensitive page")
    
    # Ensure score doesn't exceed 100
    risk_score = min(risk_score, 100)
    
    return {
        "is_phishing": risk_score > 60,
        "risk_score": risk_score,
        "reasons": reasons
    }