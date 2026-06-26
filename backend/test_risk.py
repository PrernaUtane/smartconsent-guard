# test_risk.py
# Purpose: Test the risk engine

from risk_engine import compute

print("=" * 60)
print("RISK INDEX TEST RESULTS")
print("=" * 60)

# Test Case 1: High Privacy Risk
print("\n--- Test Case 1: High Privacy Risk ---")
clauses = [{"type": "Data Selling", "confidence": 0.9}]
result = compute(clauses)
print(f"  RI Score: {result['ri_score']}/100")
print(f"  Level: {result['level']}")
print(f"  Explanation: {result['explanation'][:80]}...")

# Test Case 2: High Legal Risk
print("\n--- Test Case 2: High Legal Risk ---")
clauses = [{"type": "Arbitration", "confidence": 0.85}]
result = compute(clauses)
print(f"  RI Score: {result['ri_score']}/100")
print(f"  Level: {result['level']}")
print(f"  Explanation: {result['explanation'][:80]}...")

# Test Case 3: Mixed Risks
print("\n--- Test Case 3: Mixed Risks ---")
clauses = [
    {"type": "Data Selling", "confidence": 0.8},
    {"type": "Auto-Renewing", "confidence": 0.9},
    {"type": "Liability Waiver", "confidence": 0.7}
]
result = compute(clauses)
print(f"  RI Score: {result['ri_score']}/100")
print(f"  Level: {result['level']}")
print(f"  Explanation: {result['explanation'][:80]}...")

# Test Case 4: Multiple Privacy Clauses
print("\n--- Test Case 4: Multiple Privacy Clauses ---")
clauses = [
    {"type": "Data Selling", "confidence": 0.9},
    {"type": "Behavioral Tracking", "confidence": 0.8},
    {"type": "Location Tracking", "confidence": 0.7}
]
result = compute(clauses)
print(f"  RI Score: {result['ri_score']}/100")
print(f"  Level: {result['level']}")
print(f"  Explanation: {result['explanation'][:80]}...")

# Test Case 5: No Risks
print("\n--- Test Case 5: No Risks ---")
clauses = []
result = compute(clauses)
print(f"  RI Score: {result['ri_score']}/100")
print(f"  Level: {result['level']}")
print(f"  Explanation: {result['explanation']}")