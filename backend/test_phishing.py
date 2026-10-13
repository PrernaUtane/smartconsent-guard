import sys

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

from phishing_detector import detect


# Synthetic suspicious patterns and legitimate control URLs.
# These test labels are NOT confirmed real-world phishing URLs.
test_cases = [
    # 1–15: Suspicious brand impersonation patterns
    ("http://paypal-login-secure.tk", True),
    ("http://amazon-verify-update.ml", True),
    ("http://google-account-verify.xyz", True),
    ("http://apple-id-confirm.top", True),
    ("http://microsoft-login-secure.click", True),
    ("http://facebook-account-update.xyz", True),
    ("http://netflix-billing-confirm.top", True),
    ("http://instagram-login-verify.xyz", True),
    ("http://whatsapp-account-secure.click", True),
    ("http://github-login-verify.xyz", True),
    ("http://linkedin-account-update.top", True),
    ("http://yahoo-mail-secure.xyz", True),
    ("http://ebay-payment-verify.click", True),
    ("http://walmart-reward-claim.xyz", True),
    ("http://spotify-premium-free.top", True),

    # 16–25: Suspicious TLD and scam keywords
    ("http://secure-bank-login.xyz", True),
    ("http://account-verify.top", True),
    ("http://claim-your-prize.click", True),
    ("http://free-bitcoin-bonus.xyz", True),
    ("http://wallet-secure-update.top", True),
    ("http://billing-confirmation.loan", True),
    ("http://gift-reward-claim.win", True),
    ("http://crypto-wallet-verify.icu", True),
    ("http://signin-account-update.click", True),
    ("http://secure-payment-confirm.xyz", True),

    # 26–35: Suspicious hosting, long domains, and hyphens
    ("http://paypal-login.pages.dev", True),
    ("http://amazon-verify.web.app", True),
    ("http://google-secure.netlify.app", True),
    ("http://account-verify.vercel.app", True),
    ("http://secure-login.github.io", True),
    ("http://very-long-account-verification-login-security-check.example.com", True),
    ("http://paypal-login-account-verify.example.com", True),
    ("http://192.168.1.10/login", True),
    ("http://secure-login-verify.example.xyz", True),
    ("http://account-update-confirm.example.top", True),

    # 36–50: Existing legitimate control URLs
    ("https://example.com", False),
    ("https://www.google.com", False),
    ("https://www.github.com", False),
    ("https://www.paypal.com", False),
    ("https://www.amazon.com", False),
    ("https://www.microsoft.com", False),
    ("https://www.apple.com", False),
    ("https://www.wikipedia.org", False),
    ("https://www.linkedin.com", False),
    ("https://www.netflix.com", False),
    ("https://www.mozilla.org", False),
    ("https://www.python.org", False),
    ("https://www.nytimes.com", False),
    ("https://www.bbc.com", False),
    ("https://www.stackoverflow.com", False),

    # 51–60: Legitimate URLs with security-related paths
    ("https://www.google.com/account", False),
    ("https://github.com/login", False),
    ("https://www.paypal.com/signin", False),
    ("https://www.microsoft.com/security", False),
    ("https://www.amazon.com/gp/account", False),
    ("https://www.wikipedia.org/wiki/Security", False),
    ("https://www.linkedin.com/login", False),
    ("https://www.mozilla.org/en-US/security/", False),
    ("https://www.python.org/account/", False),
    ("https://stackoverflow.com/questions", False),
]


tp = fp = tn = fn = 0

print("=" * 75)
print("SMARTCONSENT GUARD - PHISHING DETECTOR EVALUATION")
print("=" * 75)

for index, (url, expected_phishing) in enumerate(test_cases, start=1):
    result = detect(url)
    predicted_phishing = result["is_phishing"]

    if expected_phishing and predicted_phishing:
        tp += 1
        outcome = "PASS - suspicious pattern detected"
    elif not expected_phishing and not predicted_phishing:
        tn += 1
        outcome = "PASS - legitimate control not flagged"
    elif predicted_phishing:
        fp += 1
        outcome = "FAIL - false positive"
    else:
        fn += 1
        outcome = "FAIL - suspicious pattern missed"

    print(f"\nTest {index}: {url}")
    expected_label = "PHISHING PATTERN" if expected_phishing else "SAFE"
    predicted_label = "PHISHING" if predicted_phishing else "SAFE"
    print(f"  Expected: {expected_label}")
    print(f"  Predicted: {predicted_label}")
    print(f"  Risk score: {result['risk_score']}/100")
    print(f"  Result: {outcome}")

    for reason in result["reasons"]:
        print(f"    - {reason}")


total = len(test_cases)
correct = tp + tn

precision = tp / (tp + fp) if (tp + fp) else 0
recall = tp / (tp + fn) if (tp + fn) else 0
false_positive_rate = fp / (fp + tn) if (fp + tn) else 0
accuracy = correct / total if total else 0

print("\n" + "=" * 75)
print("SUMMARY")
print("=" * 75)
print(f"Total tests: {total}")
print(f"Passed: {correct}")
print(f"Failed: {total - correct}")
print(f"True positives: {tp}")
print(f"False positives: {fp}")
print(f"True negatives: {tn}")
print(f"False negatives: {fn}")
print(f"Accuracy: {accuracy:.2%}")
print(f"Precision: {precision:.2%}")
print(f"Recall: {recall:.2%}")
print(f"False-positive rate: {false_positive_rate:.2%}")
print("=" * 75)
