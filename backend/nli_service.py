# nli_service.py
# Enhanced NLI microservice for SmartConsent Guard
# Includes: More Clause Types + Severity + Sentiment + Privacy Score + Categorization + Summary

import re
from typing import List, Dict, Any

# ============================================================
# 1. ENHANCED KEYWORD MAP – 12 Clause Types
# ============================================================

KEYWORD_MAP = {
    # ----- Privacy Violations -----
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
        "online activity", "browsing data", "web behavior"
    ],
    "Location Tracking": [
        "gps", "location", "geolocation", "geo-location",
        "coordinates", "latitude", "longitude",
        "physical location", "precise location", "device location",
        "real-time location", "approximate location",
        "where you are", "position", "proximity"
    ],
    "Broad Data Sharing": [
        "affiliates", "subsidiaries", "partners",
        "third party", "third parties", "third-party",
        "share with", "transfer to", "provide to",
        "disclose to", "passed to", "passed on to",
        "service providers", "vendors", "suppliers",
        "business partners", "shared with"
    ],
    
    # ----- Legal Traps -----
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
        "assume risk", "accept risk", "without liability"
    ],
    
    # ----- Financial Risks -----
    "Auto-Renewing Subscriptions": [
        "auto-renew", "auto renew", "automatic renew",
        "subscription", "recurring", "recurring billing",
        "billing cycle", "renew automatically",
        "automatic renewal", "continuous service",
        "rollover", "evergreen", "perpetual",
        "monthly charge", "annual charge", "recurring payment"
    ],
    
    # ----- NEW: Data Retention -----
    "Data Retention": [
        "retain", "retains", "retention", "keep", "keeps",
        "store", "stored", "storage", "duration", "period",
        "time period", "hold", "held", "archive", "archived",
        "keep your data", "store your data"
    ],
    
    # ----- NEW: User Rights -----
    "User Rights": [
        "right to delete", "right to access", "right to correct",
        "data portability", "right to object", "right to opt out",
        "right to withdraw consent", "withdraw consent",
        "request deletion", "access request", "opt out", "opt-out",
        "object to processing", "rights under", "california rights"
    ],
    
    # ----- NEW: Security Measures -----
    "Security Measures": [
        "encryption", "encrypted", "security", "secure",
        "protect", "protects", "protection", "safeguard",
        "breach", "data breach", "incident response",
        "access control", "authentication", "authorization",
        "vulnerability", "security measures", "security practices"
    ],
    
    # ----- NEW: Third-Party Processing -----
    "Third-Party Processing": [
        "processor", "data controller", "sub-processor",
        "vendor", "vendors", "third party service",
        "service provider", "outsource", "outsourced",
        "process on our behalf", "data processing agreement"
    ],
    
    # ----- NEW: International Transfer -----
    "International Transfer": [
        "transfer abroad", "outside country", "international data",
        "cross-border", "cross border", "data transfer",
        "countries outside", "foreign country", "overseas",
        "standard contractual clauses", "privacy shield"
    ]
}

# ============================================================
# 2. CLAUSE CATEGORIES – Group clauses by type
# ============================================================

CLAUSE_CATEGORIES = {
    "Privacy Violations": ["Data Selling", "Behavioral Tracking", "Location Tracking", "Broad Data Sharing"],
    "Legal Traps": ["Arbitration Clause", "Liability Waiver"],
    "Financial Risks": ["Auto-Renewing Subscriptions"],
    "Data Governance": ["Data Retention", "User Rights", "Security Measures"],
    "Data Processing": ["Third-Party Processing", "International Transfer"]
}

# ============================================================
# 3. CLAUSE SEVERITY – Risk level for each clause
# ============================================================

CLAUSE_SEVERITY = {
    "Data Selling": "CRITICAL",
    "Behavioral Tracking": "HIGH",
    "Location Tracking": "HIGH",
    "Broad Data Sharing": "HIGH",
    "Arbitration Clause": "MEDIUM",
    "Liability Waiver": "MEDIUM",
    "Auto-Renewing Subscriptions": "MEDIUM",
    "Data Retention": "LOW",
    "User Rights": "LOW",
    "Security Measures": "LOW",
    "Third-Party Processing": "MEDIUM",
    "International Transfer": "MEDIUM"
}

# ============================================================
# 4. SEVERITY COLORS – For UI display
# ============================================================

SEVERITY_COLORS = {
    "CRITICAL": "#e17055",
    "HIGH": "#fdcb6e",
    "MEDIUM": "#fdcb6e",
    "LOW": "#00b894"
}

SEVERITY_ICONS = {
    "CRITICAL": "🔴",
    "HIGH": "🟡",
    "MEDIUM": "🟠",
    "LOW": "🟢"
}

# ============================================================
# 5. Context-Aware Validation
# ============================================================

NEGATION_WORDS = {
    "do not", "don't", "does not", "doesn't", "will not",
    "won't", "shall not", "shan't", "never", "no", "not"
}

DISCLAIMER_WORDS = {
    "to the extent", "except", "excluding", "subject to",
    "unless", "only if", "solely", "strictly"
}

def _has_negation(text: str, keyword: str, window: int = 50) -> bool:
    """Check if a negation word appears near the keyword."""
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
    """Check if a disclaimer word appears near the keyword."""
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
    """Validate if a keyword match is legitimate."""
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
    
    return True

# ============================================================
# 6. SENTIMENT ANALYSIS
# ============================================================

def analyze_sentiment(text: str) -> str:
    """
    Analyze the tone of the policy text.
    Returns: "User-Friendly", "Neutral", or "User-Hostile"
    """
    positive_words = [
        "right", "choice", "control", "transparent", "protect",
        "clear", "simple", "easy", "understand", "respect",
        "privacy", "consent", "opt-out", "opt out", "withdraw",
        "right to delete", "right to access", "portability"
    ]
    negative_words = [
        "waive", "liability", "disclaim", "terminate",
        "without notice", "sole discretion", "irrevocable",
        "binding", "mandatory", "forced", "obligated",
        "unilateral", "binding arbitration", "class action waiver"
    ]
    
    pos_count = sum(1 for word in positive_words if word in text.lower())
    neg_count = sum(1 for word in negative_words if word in text.lower())
    
    if neg_count > pos_count * 2:
        return "User-Hostile"
    elif pos_count > neg_count * 2:
        return "User-Friendly"
    else:
        return "Neutral"

# ============================================================
# 7. PRIVACY SCORE
# ============================================================

def calculate_privacy_score(clauses: List[Dict]) -> int:
    """
    Calculate a separate privacy score (0-100).
    Higher score = better privacy.
    """
    score = 100
    deductions = {
        "Data Selling": 25,
        "Behavioral Tracking": 20,
        "Location Tracking": 20,
        "Broad Data Sharing": 15,
        "Auto-Renewing Subscriptions": 10,
        "Arbitration Clause": 10,
        "Liability Waiver": 10,
        "Data Retention": 5,
        "Third-Party Processing": 5,
        "International Transfer": 5
    }
    
    for clause in clauses:
        clause_type = clause.get("type", "")
        if clause_type in deductions:
            score -= deductions[clause_type]
    
    return max(0, min(100, score))

# ============================================================
# 8. PLAIN ENGLISH SUMMARY
# ============================================================

def generate_summary(clauses: List[Dict]) -> str:
    """
    Generate a plain English summary of detected clauses.
    """
    if not clauses:
        return "✅ This policy appears to be safe. No major risks detected."
    
    critical_clauses = [
        c["type"] for c in clauses 
        if CLAUSE_SEVERITY.get(c["type"]) in ["CRITICAL", "HIGH"]
    ]
    medium_clauses = [
        c["type"] for c in clauses 
        if CLAUSE_SEVERITY.get(c["type"]) == "MEDIUM"
    ]
    
    total = len(clauses)
    
    if critical_clauses:
        return f"⚠️ This policy contains {total} risky clause(s), including {', '.join(critical_clauses[:3])}. Your privacy may be at significant risk."
    elif medium_clauses:
        return f"📋 This policy contains {total} clause(s) that may require your attention: {', '.join(medium_clauses[:3])}."
    else:
        return f"ℹ️ This policy contains {total} low-risk clause(s). Review the details below."

# ============================================================
# 9. NLI SERVICE CLASS
# ============================================================

class NLIService:
    def __init__(self):
        self.use_nli = False
        self.classifier = None
        try:
            from transformers import pipeline
            self.classifier = pipeline(
                "zero-shot-classification",
                model="cross-encoder/nli-distilroberta-base",
                device=-1
            )
            self.use_nli = True
            print("[NLI Service] NLI model loaded successfully")
        except Exception as e:
            print(f"[NLI Service] NLI initialization failed: {e}")
    
    def analyze(self, text: str) -> Dict[str, Any]:
        """
        Analyze text and return enhanced results.
        
        Returns:
            {
                "clauses": [{"type": str, "confidence": float, "severity": str}],
                "method": str,
                "sentiment": str,
                "privacy_score": int,
                "categories": dict,
                "summary": str
            }
        """
        if not text or not text.strip():
            return self._empty_result()
        
        text = re.sub(r'\s+', ' ', text).strip()
        if len(text) < 50:
            return self._empty_result()
        
        chunks = self._chunk_text(text)
        
        # Use NLI if available, otherwise use keywords
        if self.use_nli and self.classifier:
            clauses = self._analyze_nli(chunks)
            method = "nli"
        else:
            clauses = self._analyze_keywords(chunks)
            method = "keyword"
        
        # Add severity to each clause
        for clause in clauses:
            clause["severity"] = CLAUSE_SEVERITY.get(clause["type"], "LOW")
            clause["icon"] = SEVERITY_ICONS.get(clause["severity"], "🟢")
            clause["color"] = SEVERITY_COLORS.get(clause["severity"], "#00b894")
        
        # Calculate enhanced metrics
        privacy_score = calculate_privacy_score(clauses)
        sentiment = analyze_sentiment(text)
        summary = generate_summary(clauses)
        categories = self._categorize_clauses(clauses)
        
        return {
            "clauses": clauses,
            "method": method,
            "sentiment": sentiment,
            "privacy_score": privacy_score,
            "categories": categories,
            "summary": summary
        }
    
    def _empty_result(self) -> Dict[str, Any]:
        return {
            "clauses": [],
            "method": "none",
            "sentiment": "Neutral",
            "privacy_score": 100,
            "categories": {},
            "summary": "No policy text to analyze."
        }
    
    def _categorize_clauses(self, clauses: List[Dict]) -> Dict[str, List[str]]:
        """Group clauses by category."""
        result = {}
        for category, clause_types in CLAUSE_CATEGORIES.items():
            found = [c["type"] for c in clauses if c["type"] in clause_types]
            if found:
                result[category] = found
        return result
    
    def _chunk_text(self, text: str, chunk_size: int = 500, overlap: int = 50) -> List[str]:
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
    
    def _analyze_keywords(self, chunks: List[str]) -> List[Dict[str, Any]]:
        found = {}
        for chunk in chunks:
            chunk_lower = chunk.lower()
            for clause_type, keywords in KEYWORD_MAP.items():
                for keyword in keywords:
                    if keyword in chunk_lower and _is_valid_match(chunk_lower, keyword, clause_type):
                        found[clause_type] = 1.0
                        break
        return [{"type": k, "confidence": v} for k, v in found.items()]
    
    def _analyze_nli(self, chunks: List[str]) -> List[Dict[str, Any]]:
        if not self.classifier:
            return self._analyze_keywords(chunks)
        
        found = {}
        candidate_labels = list(KEYWORD_MAP.keys())
        
        for chunk in chunks:
            try:
                result = self.classifier(
                    chunk,
                    candidate_labels=candidate_labels,
                    hypothesis_template="This text contains a {} clause.",
                    multi_label=True
                )
                for label, score in zip(result["labels"], result["scores"]):
                    if score > 0.55:
                        found[label] = max(found.get(label, 0), score)
            except Exception as e:
                print(f"[NLI] Error on chunk: {e}")
                chunk_lower = chunk.lower()
                for clause_type, keywords in KEYWORD_MAP.items():
                    for keyword in keywords:
                        if keyword in chunk_lower and _is_valid_match(chunk_lower, keyword, clause_type):
                            found[clause_type] = 1.0
                            break
        
        return [{"type": k, "confidence": round(v, 2)} for k, v in found.items()]

# ============================================================
# 10. SINGLETON AND CONVENIENCE FUNCTIONS
# ============================================================

_nli_service = None

def get_nli_service():
    global _nli_service
    if _nli_service is None:
        _nli_service = NLIService()
    return _nli_service

def analyze_with_nli(text: str) -> Dict[str, Any]:
    """Convenience function – returns enhanced results."""
    service = get_nli_service()
    return service.analyze(text)

# ============================================================
# 11. TESTING
# ============================================================

if __name__ == "__main__":
    print("=" * 60)
    print("Testing Enhanced NLI Service")
    print("=" * 60)
    
    test_text = """
    We sell your data to advertisers. We track your browsing behavior.
    We collect your GPS location. Your subscription auto-renews.
    Any disputes go to arbitration. The service is provided as-is.
    We share data with our affiliates.
    """
    
    service = NLIService()
    result = service.analyze(test_text)
    
    print(f"\n📊 Detected: {len(result['clauses'])} clauses")
    print(f"📋 Method: {result['method']}")
    print(f"💬 Sentiment: {result['sentiment']}")
    print(f"🔒 Privacy Score: {result['privacy_score']}/100")
    print(f"\n📝 Summary: {result['summary']}")
    
    print("\n📋 Clauses:")
    for clause in result['clauses']:
        print(f"  {clause['icon']} {clause['type']}: {clause['confidence']*100:.0f}% ({clause['severity']})")
    
    print("\n📂 Categories:")
    for category, items in result['categories'].items():
        print(f"  {category}: {', '.join(items)}")
    
    print("\n" + "=" * 60)
    print("Test Complete")
    print("=" * 60)