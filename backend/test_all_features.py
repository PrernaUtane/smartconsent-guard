import sys
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8')

import requests
import json

from qa_service import answer_policy_question, detect_dark_patterns, check_domain_breach
from phishing_detector import detect
from policy_analyzer import analyze
from risk_engine import compute

sample_terms = """
Welcome to OurService. By using our site, you agree that your subscription will automatically renew every month 
and your card will be charged recurring monthly fees of $29.99 unless cancelled at least 48 hours prior to renewal.
We may sell or monetize your personal data, browsing telemetry, and contact details with advertising partners and data brokers.
Any dispute or controversy arising out of this agreement shall be settled exclusively by binding arbitration. 
You waive your right to a jury trial or to participate in any class action lawsuit against the company.
The service is provided 'as-is' and 'as-available', and the company disclaims all warranties and shall not be liable for any damages.
You may request deletion of your account by contacting privacy@ourservice.com.
"""

print("=== 1. TESTING DARK PATTERNS DETECTOR ===")
dark_res = detect_dark_patterns(sample_terms)
print(f"Overall Threat: {dark_res['overall_threat']}")
print(f"Traps Detected: {dark_res['count']}")
for p in dark_res['patterns']:
    print(f" - [{p['severity']}] {p['name']}: {p['trap_warning'][:60]}...")

print("\n=== 2. TESTING AI POLICY Q&A ===")
for q in ["Do you sell my data?", "Can I cancel or is there auto-renewal?", "Can I sue you in court?", "Can I delete my account?"]:
    ans = answer_policy_question(sample_terms, q)
    print(f"\nQ: {q}")
    print(f"A ({ans['topic']}): {ans['answer'][:120]}...")

print("\n=== 3. TESTING BREACH INTELLIGENCE ===")
b_res = check_domain_breach("yahoo.com", "test@example.com")
print(f"Domain: {b_res['domain']}")
print(f"Security Score: {b_res['security_score']}/100")
print(f"Status: {b_res['status_message']}")
print(f"Email advice: {b_res['email_advice']}")

print("\n=== 4. TESTING RISK ENGINE INTEGRATION ===")
clauses = analyze(sample_terms)
risk_calc = compute(clauses)
print(f"Clauses found: {len(clauses)}")
print(f"Risk Index: {risk_calc['ri_score']}/100 ({risk_calc['level']})")

print("\nALL FEATURE TESTS COMPLETED SUCCESSFULLY!")
