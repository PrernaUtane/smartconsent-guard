# nli_service.py
# Optimized NLI microservice for SmartConsent Guard
# Uses smaller model for faster loading, with keyword fallback

import re
import sys
from typing import List, Dict, Any

# ============================================================
# 1. KEYWORD MAP – 12 Clause Types
# ============================================================

KEYWORD_MAP = {
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
    "Auto-Renewing Subscriptions": [
        "auto-renew", "auto renew", "automatic renew",
        "subscription", "recurring", "recurring billing",
        "billing cycle", "renew automatically",
        "automatic renewal", "continuous service",
        "rollover", "evergreen", "perpetual",
        "monthly charge", "annual charge", "recurring payment"
    ],
    "Data Retention": [
        "retain", "retains", "retention", "keep", "keeps",
        "store", "stored", "storage", "duration", "period",
        "time period", "hold", "held", "archive", "archived",
        "keep your data", "store your data"
    ],
    "User Rights": [
        "right to delete", "right to access", "right to correct",
        "data portability", "right to object", "right to opt out",
        "right to withdraw consent", "withdraw consent",
        "request deletion", "access request", "opt out", "opt-out",
        "object to processing", "rights under", "california rights"
    ],
    "Security Measures": [
        "encryption", "encrypted", "security", "secure",
        "protect", "protects", "protection", "safeguard",
        "breach", "data breach", "incident response",
        "access control", "authentication", "authorization",
        "vulnerability", "security measures", "security practices"
    ],
    "Third-Party Processing": [
        "processor", "data controller", "sub-processor",
        "vendor", "vendors", "third party service",
        "service provider", "outsource", "outsourced",
        "process on our behalf", "data processing agreement"
    ],
    "International Transfer": [
        "transfer abroad", "outside country", "international data",
        "cross-border", "cross border", "data transfer",
        "countries outside", "foreign country", "overseas",
        "standard contractual clauses", "privacy shield"
    ]
}

# ============================================================
# 2. CONFIGURATION
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

CLAUSE_CATEGORIES = {
    "Privacy Violations": ["Data Selling", "Behavioral Tracking", "Location Tracking", "Broad Data Sharing"],
    "Legal Traps": ["Arbitration Clause", "Liability Waiver"],
    "Financial Risks": ["Auto-Renewing Subscriptions"],
    "Data Governance": ["Data Retention", "User Rights", "Security Measures"],
    "Data Processing": ["Third-Party Processing", "International Transfer"]
}

SEVERITY_ICONS = {
    "CRITICAL": "🔴",
    "HIGH": "🟡",
    "MEDIUM": "🟠",
    "LOW": "🟢"
}

SEVERITY_COLORS = {
    "CRITICAL": "#e17055",
    "HIGH": "#ffa502",
    "MEDIUM": "#fdcb6e",
    "LOW": "#00b894"
}

NEGATION_WORDS = {
    "do not", "don't", "does not", "doesn't", "will not",
    "won't", "shall not", "shan't", "never", "no", "not"
}

DISCLAIMER_WORDS = {
    "to the extent", "except", "excluding", "subject to",
    "unless", "only if", "solely", "strictly"
}

# ============================================================
# 3. UTILITY FUNCTIONS
# ============================================================

def _has_negation(text: str, keyword: str, window: int = 50) -> bool:
    pos = text.lower().find(keyword)
    if pos == -1:
        return False
    start = max(0, pos - window)
    end = min(len(text), pos + window)
    surrounding = text[start:end].lower()
    return any(neg in surrounding for neg in NEGATION_WORDS)

def _has_disclaimer(text: str, keyword: str, window: int = 40) -> bool:
    pos = text.lower().find(keyword)
    if pos == -1:
        return False
    start = max(0, pos - window)
    surrounding = text[start:pos].lower()
    return any(dis in surrounding for dis in DISCLAIMER_WORDS)

def _is_valid_match(chunk: str, keyword: str, clause_type: str) -> bool:
    chunk_lower = chunk.lower()
    kw = keyword.lower()
    
    if _has_negation(chunk_lower, kw):
        return False
    if _has_disclaimer(chunk_lower, kw):
        return False
    
    # Only flag whole words for common terms
    stop_words = {"share", "track", "cookie", "service", "policy", "terms"}
    if kw in stop_words:
        pattern = r'\b' + re.escape(kw) + r'\b'
        return bool(re.search(pattern, chunk_lower))
    
    return True

def _chunk_text(text: str, chunk_size: int = 400, overlap: int = 50) -> List[str]:
    """Split text into overlapping chunks."""
    if len(text) <= chunk_size:
        return [text]
    chunks = []
    step = chunk_size - overlap
    for i in range(0, len(text), step):
        chunk = text[i:i + chunk_size]
        if len(chunk) >= 50:
            chunks.append(chunk)
        if i + chunk_size >= len(text):
            break
    return chunks

def _categorize_clauses(clauses: List[Dict]) -> Dict[str, List[str]]:
    """Group clauses by category."""
    result = {}
    for category, clause_types in CLAUSE_CATEGORIES.items():
        found = [c["type"] for c in clauses if c["type"] in clause_types]
        if found:
            result[category] = found
    return result

def analyze_sentiment(text: str) -> str:
    """Analyze policy tone."""
    positive = ["right", "choice", "control", "transparent", "protect", "privacy", "consent", "opt-out"]
    negative = ["waive", "liability", "disclaim", "terminate", "without notice", "binding", "mandatory"]
    
    pos_count = sum(1 for w in positive if w in text.lower())
    neg_count = sum(1 for w in negative if w in text.lower())
    
    if neg_count > pos_count * 2:
        return "User-Hostile"
    elif pos_count > neg_count * 2:
        return "User-Friendly"
    return "Neutral"

def calculate_privacy_score(clauses: List[Dict]) -> int:
    """Calculate privacy score (0-100)."""
    deductions = {
        "Data Selling": 25, "Behavioral Tracking": 20, "Location Tracking": 20,
        "Broad Data Sharing": 15, "Auto-Renewing Subscriptions": 10,
        "Arbitration Clause": 10, "Liability Waiver": 10,
        "Data Retention": 5, "Third-Party Processing": 5, "International Transfer": 5
    }
    score = 100
    for clause in clauses:
        score -= deductions.get(clause.get("type", ""), 0)
    return max(0, min(100, score))

def generate_summary(clauses: List[Dict]) -> str:
    """Generate plain English summary."""
    if not clauses:
        return "✅ This policy appears to be safe. No major risks detected."
    
    critical = [c["type"] for c in clauses if CLAUSE_SEVERITY.get(c["type"]) in ["CRITICAL", "HIGH"]]
    medium = [c["type"] for c in clauses if CLAUSE_SEVERITY.get(c["type"]) == "MEDIUM"]
    total = len(clauses)
    
    if critical:
        return f"⚠️ This policy contains {total} risky clause(s), including {', '.join(critical[:3])}. Your privacy may be at significant risk."
    elif medium:
        return f"📋 This policy contains {total} clause(s) that may require your attention: {', '.join(medium[:3])}."
    return f"ℹ️ This policy contains {total} low-risk clause(s). Review the details below."

# ============================================================
# 4. NLI SERVICE
# ============================================================

class NLIService:
    def __init__(self):
        self.use_nli = False
        self.classifier = None
        self._load_model()
    
    def _load_model(self):
        """Load the NLI model with fallback."""
        print(f"[NLI Service] Python: {sys.executable}")
        print("[NLI Service] Loading NLI model...")
        
        try:
            from transformers import pipeline
            self.classifier = pipeline(
                "zero-shot-classification",
                model="typeform/distilbert-base-uncased-mnli",  # ✅ Smaller model (250MB)
                device=-1
            )
            self.use_nli = True
            print("[NLI Service] ✅ NLI model loaded successfully")
        except ImportError as e:
            print(f"[NLI Service] ❌ ImportError: {e}")
            print("[NLI Service] Run: pip install transformers torch")
        except Exception as e:
            print(f"[NLI Service] ❌ Error: {e}")
            print("[NLI Service] Falling back to keyword-only mode")
    
    def analyze(self, text: str) -> Dict[str, Any]:
        """Main entry point."""
        if not text or len(text.strip()) < 50:
            return self._empty_result()
        
        text = re.sub(r'\s+', ' ', text).strip()
        chunks = _chunk_text(text)
        
        # Use NLI if available
        if self.use_nli and self.classifier:
            clauses = self._analyze_with_nli(chunks)
            method = "nli"
        else:
            clauses = self._analyze_with_keywords(chunks)
            method = "keyword"
        
        # Add metadata
        for c in clauses:
            c["severity"] = CLAUSE_SEVERITY.get(c["type"], "LOW")
            c["icon"] = SEVERITY_ICONS.get(c["severity"], "🟢")
            c["color"] = SEVERITY_COLORS.get(c["severity"], "#00b894")
        
        return {
            "clauses": clauses,
            "method": method,
            "sentiment": analyze_sentiment(text),
            "privacy_score": calculate_privacy_score(clauses),
            "categories": _categorize_clauses(clauses),
            "summary": generate_summary(clauses)
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
    
    def _analyze_with_keywords(self, chunks: List[str]) -> List[Dict[str, Any]]:
        """Keyword-based analysis with hit-count confidence."""
        hits = {}
        for chunk in chunks:
            chunk_lower = chunk.lower()
            for clause_type, keywords in KEYWORD_MAP.items():
                for kw in keywords:
                    if kw in chunk_lower and _is_valid_match(chunk_lower, kw, clause_type):
                        hits[clause_type] = hits.get(clause_type, 0) + 1
        
        results = []
        for clause_type, count in hits.items():
            confidence = min(0.5 + (count * 0.03), 0.92)  # Range: 0.53 - 0.92
            results.append({"type": clause_type, "confidence": round(confidence, 2)})
        return results
    
    def _analyze_with_nli(self, chunks: List[str]) -> List[Dict[str, Any]]:
        """NLI-based analysis with real confidence scores."""
        if not self.classifier:
            return self._analyze_with_keywords(chunks)
        
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
                print(f"[NLI] Chunk error: {e}")
                # Fallback to keywords for this chunk
                chunk_lower = chunk.lower()
                for clause_type, keywords in KEYWORD_MAP.items():
                    for kw in keywords:
                        if kw in chunk_lower and _is_valid_match(chunk_lower, kw, clause_type):
                            found[clause_type] = 1.0
                            break
        
        return [{"type": k, "confidence": round(v, 2)} for k, v in found.items()]

# ============================================================
# 5. SINGLETON
# ============================================================

_nli_service = None

def get_nli_service():
    global _nli_service
    if _nli_service is None:
        _nli_service = NLIService()
    return _nli_service

def analyze_with_nli(text: str) -> Dict[str, Any]:
    return get_nli_service().analyze(text)

# ============================================================
# 6. TESTING
# ============================================================

if __name__ == "__main__":
    print("=" * 60)
    print("Testing Optimized NLI Service")
    print("=" * 60)
    
    test_text = """
    We sell your data to advertisers. We track your browsing behavior.
    We collect your GPS location. Your subscription auto-renews.
    Any disputes go to arbitration. The service is provided as-is.
    We share data with our affiliates.
    """
    
    service = NLIService()
    result = service.analyze(test_text)
    
    print(f"\n📊 Method: {result['method']}")
    print(f"📋 Clauses: {len(result['clauses'])}")
    for c in result['clauses']:
        print(f"  {c['icon']} {c['type']}: {c['confidence']*100:.0f}%")
    print(f"\n📝 Summary: {result['summary']}")
    print("=" * 60)