# policy_analyzer.py
# SmartConsent Guard - Terms & Conditions Analysis Engine
# Member C: This is your complete file. Copy this exactly.

import re
from typing import List, Dict, Any

# ============================================================
# 1. KEYWORD MAP - The detection dictionary
# 7 clause types × 5-6 trigger keywords each
# ============================================================

KEYWORD_MAP: Dict[str, List[str]] = {
    "Data Selling": [
        "sell", "sold", "selling", "share", "sharing", "shared",
        "third-party", "third party", "advertisers", "marketing partners",
        "data brokers", "broker", "monetize", "monetization"
    ],
    
    "Behavioral Tracking": [
        "track", "tracking", "tracked", "cookie", "cookies",
        "profile", "profiling", "behavioral", "behavior",
        "targeted ads", "targeted advertising", "retargeting",
        "browsing history", "clickstream"
    ],
    
    "Location Tracking": [
        "gps", "location", "geolocation", "geo-location",
        "coordinates", "latitude", "longitude",
        "physical location", "precise location", "device location"
    ],
    
    "Auto-Renewing Subscriptions": [
        "auto-renew", "auto renew", "automatic renew",
        "subscription", "recurring", "recurring billing",
        "billing cycle", "renew automatically",
        "automatic renewal", "continuous service"
    ],
    
    "Arbitration Clause": [
        "arbitration", "arbitrate", "arbitrator",
        "waive right", "class action", "class-action",
        "dispute resolution", "binding arbitration",
        "waive your right to sue", "mandatory arbitration"
    ],
    
    "Liability Waiver": [
        "waive", "waiver", "liability", "liable",
        "not responsible", "no responsibility",
        "as is", "as-is", "no warranty", "no guarantee",
        "limited liability", "disclaim", "disclaimer",
        "use at your own risk"
    ],
    
    "Broad Data Sharing": [
        "affiliates", "subsidiaries", "partners",
        "third party", "third parties", "third-party",
        "share with", "transfer to", "provide to",
        "disclose to", "passed to", "passed on to"
    ]
}

# ============================================================
# 2. KEYWORD VALIDATION - Prevent false positives
# ============================================================

# Words that should NOT trigger a clause (common words)
STOP_WORDS = {
    "share", "track", "cookie", "service", "policy", "terms",
    "use", "user", "site", "website", "app", "application"
}

def _is_valid_match(chunk: str, keyword: str, clause_type: str) -> bool:
    """
    Validates if a keyword match is legitimate.
    Prevents false positives like "share" in "shareholder".
    """
    # Don't flag if keyword is a stop word (only if it appears alone)
    if keyword in STOP_WORDS:
        # Check if the word appears as a separate word (not part of another word)
        pattern = r'\b' + re.escape(keyword) + r'\b'
        if not re.search(pattern, chunk, re.IGNORECASE):
            return False
    
    # For "third-party" or "third party" - ensure it's not "third party service" (generic)
    if keyword in ["third-party", "third party", "third parties"]:
        # Check if it's followed by words indicating data sharing
        if re.search(r'third[-\s]party\s+(?:service|provider|company)', chunk, re.IGNORECASE):
            return True
        # If it's just "third party" without context, be cautious
        if not re.search(r'third[-\s]party\s+(?:data|share|sell|transfer|advertiser)', chunk, re.IGNORECASE):
            return True  # Still flag it - better safe than sorry
    
    return True

# ============================================================
# 3. CHUNKING - Split text for processing
# ============================================================

def _chunk_text(text: str, chunk_size: int = 500, overlap: int = 50) -> List[str]:
    """
    Splits text into overlapping chunks.
    
    Args:
        text: The input text
        chunk_size: Size of each chunk in characters
        overlap: Overlap between chunks (ensures no clause is split)
    
    Returns:
        List of text chunks
    """
    if len(text) <= chunk_size:
        return [text]
    
    chunks = []
    step = chunk_size - overlap
    
    for i in range(0, len(text), step):
        chunk = text[i:i + chunk_size]
        if len(chunk) < 50:  # Skip tiny chunks
            continue
        chunks.append(chunk)
        
        # If we've reached the end, break
        if i + chunk_size >= len(text):
            break
    
    return chunks

# ============================================================
# 4. CLASSIFICATION - Check each chunk for keywords
# ============================================================

def _classify_chunk(chunk: str) -> List[str]:
    """
    Checks a single chunk against the keyword map.
    Returns a list of detected clause types.
    """
    detected = []
    chunk_lower = chunk.lower()
    
    for clause_type, keywords in KEYWORD_MAP.items():
        for keyword in keywords:
            # Check if keyword exists in chunk
            if keyword in chunk_lower:
                # Validate the match
                if _is_valid_match(chunk_lower, keyword, clause_type):
                    detected.append(clause_type)
                    break  # Only add each clause once per chunk
    
    return detected

# ============================================================
# 5. MAIN FUNCTION - Analyze the policy text
# ============================================================

def analyze(text: str) -> List[Dict[str, Any]]:
    """
    Main entry point for policy analysis.
    
    Args:
        text: Raw policy text (max 8000 characters)
    
    Returns:
        List of detected clauses: [{"type": "Data Selling", "confidence": 1.0}, ...]
    """
    # --- 5.1: Input Validation ---
    if not text or not text.strip():
        return []
    
    # Clean the text
    text = re.sub(r'\s+', ' ', text).strip()
    
    # Minimum length check - must be at least 50 chars to be a real policy
    if len(text) < 50:
        return []
    
    # --- 5.2: Truncate to 8000 characters ---
    if len(text) > 8000:
        text = text[:8000]
    
    # --- 5.3: Chunk the text ---
    chunks = _chunk_text(text)
    
    # --- 5.4: Classify each chunk (Max-Pooling) ---
    found_clauses = {}  # clause_type -> confidence
    
    for chunk in chunks:
        detected = _classify_chunk(chunk)
        for clause in detected:
            # If found in ANY chunk, mark with 1.0
            # This is MAX-POOLING - if any chunk has it, the whole document is flagged
            found_clauses[clause] = 1.0
    
    # --- 5.5: Convert to list format ---
    result = []
    for clause_type, confidence in found_clauses.items():
        result.append({
            "type": clause_type,
            "confidence": confidence
        })
    
    return result

# ============================================================
# 6. OPTIONAL: Zero-Shot NLI (Upgrade Path)
# ============================================================
# Uncomment this section to enable AI-based classification
# Requires: pip install transformers torch

"""
try:
    from transformers import pipeline
    
    _NLI_MODEL = None
    
    def _load_nli_model():
        global _NLI_MODEL
        if _NLI_MODEL is None:
            _NLI_MODEL = pipeline(
                "zero-shot-classification",
                model="cross-encoder/nli-distilroberta-base",
                device=-1  # Use CPU
            )
        return _NLI_MODEL
    
    def _classify_chunk_nli(chunk: str) -> List[str]:
        # Returns clauses detected using zero-shot NLI
        candidate_labels = list(KEYWORD_MAP.keys())
        hypothesis_template = "This text contains a {} clause."
        
        try:
            model = _load_nli_model()
            result = model(
                chunk,
                candidate_labels=candidate_labels,
                hypothesis_template=hypothesis_template,
                multi_label=True
            )
            
            detected = []
            for label, score in zip(result["labels"], result["scores"]):
                if score > 0.55:  # Confidence threshold
                    detected.append(label)
            
            return detected
        except Exception:
            # Fallback to keyword classification
            return _classify_chunk(chunk)
    
    # Override the classification function if NLI is available
    _classify_chunk = _classify_chunk_nli
    print("[policy_analyzer] NLI model loaded successfully (Upgrade Mode)")
    
except ImportError:
    print("[policy_analyzer] NLI dependencies not installed. Using Keyword Fallback.")
except Exception as e:
    print(f"[policy_analyzer] NLI initialization failed: {e}. Using Keyword Fallback.")
"""

# ============================================================
# 7. TESTING - Run this file directly to test
# ============================================================

if __name__ == "__main__":
    # Test cases for each clause type
    test_texts = [
        ("We may sell your personal data to third-party advertisers.", ["Data Selling", "Broad Data Sharing"]),
        ("Your browsing behavior is tracked using cookies.", ["Behavioral Tracking"]),
        ("We collect your GPS location to provide localized services.", ["Location Tracking"]),
        ("Your subscription will auto-renew annually.", ["Auto-Renewing Subscriptions"]),
        ("Any disputes shall be resolved by binding arbitration.", ["Arbitration Clause"]),
        ("The service is provided 'as is' with no warranties.", ["Liability Waiver"]),
        ("We share your information with our affiliates.", ["Broad Data Sharing"]),
    ]
    
    print("=" * 60)
    print("Testing Policy Analyzer Engine")
    print("=" * 60)
    
    for text, expected in test_texts:
        result = analyze(text)
        detected_types = [r["type"] for r in result]
        
        print(f"\nText: {text[:50]}...")
        print(f"Expected: {expected}")
        print(f"Detected: {detected_types}")
        print(f"Match: {'✅ PASS' if set(expected) == set(detected_types) else '❌ FAIL'}")
        
        # Show full result
        for clause in result:
            print(f"  → {clause['type']}: confidence {clause['confidence']}")
    
    print("\n" + "=" * 60)
    print("Test Complete")
    print("=" * 60)
