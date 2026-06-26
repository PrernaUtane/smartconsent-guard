# test_phishing.py
# Purpose: Test the phishing detection engine

from phishing_detector import detect

# List of test URLs
test_urls = [
    "http://paypal-login-secure.tk",      # Should be PHISHING
    "https://www.google.com",             # Should be SAFE
    "http://amazon-verify-update.ml",     # Should be PHISHING
    "https://github.com",                 # Should be SAFE
    "http://192.168.1.1/login",           # Should be PHISHING
    "https://paypal.com",                 # Should be SAFE
    "http://secure-bank-login.xyz",       # Should be PHISHING
]

print("=" * 60)
print("PHISHING DETECTION TEST RESULTS")
print("=" * 60)

for url in test_urls:
    result = detect(url)
    status = "⚠️ PHISHING" if result['is_phishing'] else "✅ SAFE"
    print(f"\nURL: {url}")
    print(f"  Status: {status}")
    print(f"  Risk Score: {result['risk_score']}/100")
    if result['reasons']:
        print(f"  Reasons:")
        for reason in result['reasons']:
            print(f"    - {reason}")