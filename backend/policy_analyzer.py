# policy_analyzer.py
# SmartConsent Guard - Terms & Conditions Analysis Engine
# NLI-First Class-Based Approach

import re
from typing import List, Dict, Any

# ============================================================
# 1. KEYWORD MAP - Detection dictionary
# ============================================================

KEYWORD_MAP: Dict[str, List[str]] = {
    "Data Selling": [
        "sell", "sold", "selling", "share", "sharing", "shared",
        "third-party", "third party", "advertisers", "marketing partners",
        "data brokers", "broker", "monetize", "monetization",
        "trade", "commercialize", "rent", "license", "disclose",
        "disclosing", "transferred to", "passed to"
    ],
    
    "Behavioral Tracking": [
        "track", "tracking", "tracked", "cookie", "cookies",
        "profile", "profiling", "behavioral", "behavior",
        "targeted ads", "targeted advertising", "retargeting",
        "browsing history", "clickstream", "interest-based",
        "session replay", "fingerprinting", "device fingerprint",
        "online activity", "browsing data", "web behavior",
        "user activity", "page views", "session data",
        "interaction data", "usage data", "analytics",
        "marketing cookies", "advertising cookies"
    ],
    
    "Location Tracking": [
        "gps", "location", "geolocation", "geo-location",
        "coordinates", "latitude", "longitude",
        "physical location", "precise location", "device location",
        "real-time location", "approximate location",
        "where you are", "position", "proximity"
    ],
    
    "Auto-Renewing Subscriptions": [
        "auto-renew", "auto renew", "automatic renew",
        "subscription", "recurring", "recurring billing",
        "billing cycle", "renew automatically",
        "automatic renewal", "continuous service",
        "rollover", "evergreen", "perpetual",
        "monthly charge", "annual charge", "recurring payment",
        "renewal", "renews", "renewed", "subscription fee",
        "billing period", "auto-charge", "auto payment",
        "recurring fee", "membership fee"
    ],
    
    "Arbitration Clause": [
        "arbitration", "arbitrate", "arbitrator",
        "waive right", "class action", "class-action",
        "dispute resolution", "binding arbitration",
        "waive your right to sue", "mandatory arbitration",
        "alternative dispute resolution", "adr",
        "small claims", "mediation"
    ],
    
    "Liability Waiver": [
        "waive", "waiver", "liability", "liable",
        "not responsible", "no responsibility",
        "as is", "as-is", "no warranty", "no guarantee",
        "limited liability", "disclaim", "disclaimer",
        "use at your own risk", "hold harmless",
        "indemnify", "limitation of liability",
        "assume risk", "accept risk", "without liability",
        "disclaims all", "excludes liability", "no liability",
        "relieves", "releases", "absolves"
    ],
    
    "Broad Data Sharing": [
        "affiliates", "subsidiaries", "partners",
        "third party", "third parties", "third-party",
        "share with", "transfer to", "provide to",
        "disclose to", "passed to", "passed on to",
        "service providers", "vendors", "suppliers",
        "business partners", "shared with",
        "passed along", "given to", "provided to",
        "made available to", "accessible to",
        "shared among", "distributed to",
        "consolidated with", "combined with"
    ]
}


# ============================================================
# 2. CONTEXT-AWARE VALIDATION
# ============================================================

NEGATION_WORDS = {
    "do not", "don't", "does not", "doesn't", "will not",
    "won't", "shall not", "shan't", "never", "no", "not",
    "explicitly exclude", "expressly exclude"
}

DISCLAIMER_WORDS = {
    "to the extent", "except", "excluding", "subject to",
    "unless", "only if", "solely", "strictly"
}


def _has_negation(text: str, keyword: str, window: int = 50) -> bool:
    keyword_pos = text.lower().find(keyword)
    if keyword_pos == -1:
        return False
    start = max(0, keyword_pos - window)
    end = min(len(text), keyword_pos + window)
    surrounding = text[start:end].lower()
    for neg in NEGATION_WORDS:
        if neg in surrounding:
            return True
    return False


def _has_disclaimer(text: str, keyword: str, window: int = 40) -> bool:
    keyword_pos = text.lower().find(keyword)
    if keyword_pos == -1:
        return False
    start = max(0, keyword_pos - window)
    surrounding = text[start:keyword_pos].lower()
    for dis in DISCLAIMER_WORDS:
        if dis in surrounding:
            return True
    return False


def _is_valid_match(chunk: str, keyword: str, clause_type: str) -> bool:
    chunk_lower = chunk.lower()
    keyword_lower = keyword.lower()
    
    if _has_negation(chunk_lower, keyword_lower):
        return False
    if _has_disclaimer(chunk_lower, keyword_lower):
        return False
    
    stop_words = {"share", "track", "cookie", "service", "policy", "terms"}
    if keyword_lower in stop_words:
        pattern = r'\b' + re.escape(keyword_lower) + r'\b'
        if not re.search(pattern, chunk_lower):
            return False
    
    if keyword_lower in ["third-party", "third party", "third parties"]:
        if re.search(r'third[-\s]party\s+(?:service|provider|company)', chunk_lower):
            data_words = ["data", "share", "sell", "transfer", "advertiser", "marketing"]
            for dw in data_words:
                if dw in chunk_lower:
                    return True
            return True
        return True
    
    if keyword_lower in ["sell", "selling", "sold"]:
        data_words = ["data", "information", "personal", "privacy"]
        for dw in data_words:
            if dw in chunk_lower:
                return True
        return False
    
    return True


def _chunk_text(text: str, chunk_size: int = 500, overlap: int = 50) -> List[str]:
    if len(text) <= chunk_size:
        return [text]
    chunks = []
    step = chunk_size - overlap
    for i in range(0, len(text), step):
        chunk = text[i:i + chunk_size]
        if len(chunk) < 50:
            continue
        chunks.append(chunk)
        if i + chunk_size >= len(text):
            break
    return chunks


def _classify_keywords(chunk: str) -> List[str]:
    """Keyword-based classification (fallback)."""
    detected = []
    chunk_lower = chunk.lower()
    for clause_type, keywords in KEYWORD_MAP.items():
        for keyword in keywords:
            if keyword in chunk_lower:
                if _is_valid_match(chunk_lower, keyword, clause_type):
                    detected.append(clause_type)
                    break
    return detected


# ============================================================
# 3. POLICY ANALYZER CLASS – NLI-First
# ============================================================

class PolicyAnalyzer:
    """Policy analyzer with NLI-first classification."""
    
    def __init__(self):
        self.use_nli = False
        self.nli_model = None
        self._init_nli()
    
    def _init_nli(self):
        """Try to load the NLI model."""
        try:
            from transformers import pipeline
            self.nli_model = pipeline(
                "zero-shot-classification",
                model="cross-encoder/nli-distilroberta-base",
                device=-1
            )
            self.use_nli = True
            print("[policy_analyzer] NLI model loaded successfully (Upgrade Mode)")
        except ImportError:
            print("[policy_analyzer] NLI dependencies not installed. Using Keyword Fallback.")
        except Exception as e:
            print(f"[policy_analyzer] NLI initialization failed: {e}. Using Keyword Fallback.")
    
    def _classify_nli(self, chunk: str) -> List[str]:
        """Classify using NLI."""
        if not self.use_nli or self.nli_model is None:
            return _classify_keywords(chunk)
        
        try:
            candidate_labels = list(KEYWORD_MAP.keys())
            result = self.nli_model(
                chunk,
                candidate_labels=candidate_labels,
                hypothesis_template="This text contains a {} clause.",
                multi_label=True
            )
            detected = []
            for label, score in zip(result["labels"], result["scores"]):
                if score > 0.55:
                    detected.append(label)
            return detected
        except Exception as e:
            print(f"[NLI] Error: {e}. Using keyword fallback.")
            return _classify_keywords(chunk)
    
    def analyze(self, text: str) -> List[Dict[str, Any]]:
        """Main entry point for policy analysis."""
        if not text or not text.strip():
            return []
        
        text = re.sub(r'\s+', ' ', text).strip()
        if len(text) < 50:
            return []
        if len(text) > 8000:
            text = text[:8000]
        
        chunks = _chunk_text(text)
        found_clauses = {}
        
        for chunk in chunks:
            detected = self._classify_nli(chunk)
            for clause in detected:
                found_clauses[clause] = 1.0
        
        result = []
        for clause_type, confidence in found_clauses.items():
            result.append({
                "type": clause_type,
                "confidence": confidence
            })
        
        return result


# ============================================================
# 4. CONVENIENCE FUNCTION (for backward compatibility)
# ============================================================

_analyzer = PolicyAnalyzer()

def analyze(text: str) -> List[Dict[str, Any]]:
    """Convenience function for analyze() – uses the class."""
    return _analyzer.analyze(text)


# ============================================================
# 5. TESTING
# ============================================================

if __name__ == "__main__":
    test_texts = [
        ("We may sell your personal data to third-party advertisers.", ["Data Selling", "Broad Data Sharing"]),
        ("We do not sell your personal data to anyone.", []),
        ("Your browsing behavior is tracked using cookies.", ["Behavioral Tracking"]),
        ("We collect your GPS location to provide localized services.", ["Location Tracking"]),
        ("Your subscription will auto-renew annually.", ["Auto-Renewing Subscriptions"]),
        ("Any disputes shall be resolved by binding arbitration.", ["Arbitration Clause"]),
        ("The service is provided 'as is' with no warranties.", ["Liability Waiver"]),
        ("We share your information with our affiliates.", ["Broad Data Sharing"]),
        ("We are not responsible for any data loss.", []),
        ("We are not liable for any damages.", []),
    ]
    
    print("=" * 60)
    print("Testing Policy Analyzer Engine (NLI-First Class-Based)")
    print("=" * 60)
    
    # Create an instance
    analyzer = PolicyAnalyzer()
    
    for text, expected in test_texts:
        result = analyzer.analyze(text)
        detected_types = [r["type"] for r in result]
        
        print(f"\n📝 Text: {text[:60]}...")
        print(f"   Expected: {expected}")
        print(f"   Detected: {detected_types}")
        print(f"   Match: {'✅ PASS' if set(expected) == set(detected_types) else '❌ FAIL'}")
        for clause in result:
            print(f"     → {clause['type']}: confidence {clause['confidence']}")
    
    print("\n" + "=" * 60)
    print("Test Complete")
    print("=" * 60)