# policy_analyzer.py
# Member C – Legal Text Engineer
# SmartConsent | Group 11 | YCCE | Prof. Nilesh U. Sambhe

import re
from transformers import pipeline

# ─────────────────────────────────────────────────────────────
# CLAUSE DEFINITIONS
# Each clause has: keywords, regex patterns, severity level
# ─────────────────────────────────────────────────────────────
CLAUSE_CONFIG = {
    "Data Selling": {
        "severity": "HIGH",
        "keywords": [
            "sell", "sold", "selling", "share", "shared", "sharing",
            "third-party", "third party", "advertisers", "brokers",
            "monetize", "resell", "disclose to partners", "data sale",
            "commercially exploit"
        ],
        "patterns": [
            r"sell(ing)?\s+your\s+(personal\s+)?data",
            r"shar(e|ing)\s+(your\s+)?(data|information)\s+with\s+third",
            r"third.party\s+(advertis|broker|partner)",
        ]
    },
    "Behavioral Tracking": {
        "severity": "HIGH",
        "keywords": [
            "track", "tracking", "cookie", "cookies", "profile",
            "profiling", "behavioral", "targeted ads", "ad targeting",
            "browsing history", "clickstream", "user behavior",
            "analytics", "fingerprint", "retargeting"
        ],
        "patterns": [
            r"track(ing)?\s+your\s+(browsing|behavior|activity)",
            r"build(ing)?\s+a\s+profile",
            r"target(ed)?\s+advert",
            r"cookie(s)?\s+(to\s+)?(track|monitor|collect)",
        ]
    },
    "Location Tracking": {
        "severity": "HIGH",
        "keywords": [
            "gps", "location", "geolocation", "coordinates",
            "latitude", "longitude", "whereabouts", "precise location",
            "real-time location", "location data", "location services",
            "location history", "device location"
        ],
        "patterns": [
            r"collect(ing)?\s+(your\s+)?(gps|location|geolocation)",
            r"(precise|real.time)\s+location",
            r"location\s+(data|information|history)",
        ]
    },
    "Auto-Renewing Subscriptions": {
        "severity": "MEDIUM",
        "keywords": [
            "auto-renew", "auto renew", "automatically renew",
            "subscription", "recurring", "billing cycle",
            "automatically charged", "renewal", "continuous subscription",
            "automatically billed", "until cancelled", "until you cancel",
            "opt out", "cancel anytime"
        ],
        "patterns": [
            r"auto(matically)?.renew(al|ing)?",
            r"automatically\s+(charge|bill|renew)",
            r"recurring\s+(charge|billing|payment|fee)",
            r"until\s+(you\s+)?cancel",
        ]
    },
    "Arbitration Clause": {
        "severity": "HIGH",
        "keywords": [
            "arbitration", "waive right", "class action", "dispute",
            "binding arbitration", "waiver", "tribunal",
            "settle disputes", "mandatory arbitration",
            "individual basis", "no jury trial", "arbitrator",
            "dispute resolution", "claims must be"
        ],
        "patterns": [
            r"binding\s+arbitration",
            r"waiv(e|ing)\s+(your\s+)?right\s+to\s+(a\s+)?class",
            r"class\s+action\s+waiver",
            r"mandatory\s+arbitration",
            r"disputes?\s+(shall|must|will)\s+be\s+(resolved|settled)\s+by",
        ]
    },
    "Liability Waiver": {
        "severity": "MEDIUM",
        "keywords": [
            "waive", "liability", "as is", "as-is", "no warranty",
            "not liable", "disclaim", "limitation of liability",
            "without warranty", "no guarantees", "to the fullest extent",
            "not responsible", "exclude liability", "consequential damages",
            "indirect damages", "incidental damages"
        ],
        "patterns": [
            r"as.is(\s+basis)?",
            r"(no|without)\s+warrant(y|ies)",
            r"not\s+(be\s+)?liable\s+for",
            r"limit(ation)?\s+of\s+liability",
            r"disclaim(s|er)?\s+(all\s+)?(liability|warrant)",
            r"to\s+the\s+fullest\s+extent\s+permitted",
        ]
    },
    "Broad Data Sharing": {
        "severity": "MEDIUM",
        "keywords": [
            "affiliates", "partners", "third party", "transfer",
            "disclose", "disclosed", "subsidiaries", "service providers",
            "business partners", "contractors", "vendors",
            "associated companies", "related entities",
            "successor company", "merger", "acquisition"
        ],
        "patterns": [
            r"shar(e|ing)\s+(data|information)\s+with\s+(our\s+)?(partner|affiliate|subsidiar)",
            r"transfer(ring)?\s+(your\s+)?(data|information)\s+to",
            r"disclose\s+(to|your\s+data\s+to)\s+(our\s+)?(partner|affiliate|third)",
            r"(merger|acquisition|sale)\s+of\s+(our\s+)?business",
        ]
    },
}

CLAUSE_LABELS = list(CLAUSE_CONFIG.keys())

# ─────────────────────────────────────────────────────────────
# MODEL CACHE — loads LegalBERT only once per session
# ─────────────────────────────────────────────────────────────
_legalbert_pipeline = None

def _get_legalbert():
    global _legalbert_pipeline
    if _legalbert_pipeline is None:
        print("[policy_analyzer] Loading LegalBERT model (first time only)...")
        _legalbert_pipeline = pipeline(
            "zero-shot-classification",
            model="nlpaueb/legal-bert-base-uncased"
        )
        print("[policy_analyzer] LegalBERT loaded successfully.")
    return _legalbert_pipeline

# ─────────────────────────────────────────────────────────────
# SMART CHUNKING — splits on sentence boundaries
# ─────────────────────────────────────────────────────────────
def _chunk_text(text: str, chunk_size: int = 500) -> list:
    """
    Splits text into ~500 char chunks at sentence boundaries.
    Avoids cutting a sentence in half for better classification.
    """
    sentences = re.split(r'(?<=[.!?])\s+', text.strip())
    chunks = []
    current = ""

    for sentence in sentences:
        if len(current) + len(sentence) <= chunk_size:
            current += " " + sentence
        else:
            if current.strip():
                chunks.append(current.strip())
            current = sentence

    if current.strip():
        chunks.append(current.strip())

    # Safety fallback: if no sentence boundaries found
    if not chunks:
        chunks = [text[i:i + chunk_size] for i in range(0, len(text), chunk_size)]

    return chunks

# ─────────────────────────────────────────────────────────────
# FALLBACK: Enhanced Keyword + Regex classifier
# ─────────────────────────────────────────────────────────────
def _keyword_classify(chunks: list) -> list:
    """
    Keyword + regex based fallback.
    Confidence scales with number of keyword/pattern hits:
      1 hit  → 0.60
      2 hits → 0.80
      3+ hits → 1.00
    """
    hit_counts = {label: 0 for label in CLAUSE_LABELS}

    for chunk in chunks:
        chunk_lower = chunk.lower()
        for clause_type, config in CLAUSE_CONFIG.items():
            # Keyword matching
            for kw in config["keywords"]:
                if kw in chunk_lower:
                    hit_counts[clause_type] += 1
                    break  # one keyword hit per chunk per clause

            # Regex pattern matching
            for pattern in config["patterns"]:
                if re.search(pattern, chunk_lower):
                    hit_counts[clause_type] += 1
                    break  # one pattern hit per chunk per clause

    results = []
    for clause_type, hits in hit_counts.items():
        if hits == 0:
            continue
        elif hits == 1:
            confidence = 0.60
        elif hits == 2:
            confidence = 0.80
        else:
            confidence = 1.00

        results.append({
            "type": clause_type,
            "confidence": confidence,
            "severity": CLAUSE_CONFIG[clause_type]["severity"],
            "method": "keyword"
        })

    return sorted(results, key=lambda x: x["confidence"], reverse=True)

# ─────────────────────────────────────────────────────────────
# PRIMARY: LegalBERT zero-shot classifier
# ─────────────────────────────────────────────────────────────
def _legalbert_classify(chunks: list) -> list:
    """
    Uses LegalBERT with zero-shot classification.
    Applies max-pooling across all chunks per clause.
    Only returns clauses with confidence > 0.50.
    """
    classifier = _get_legalbert()
    scores = {label: 0.0 for label in CLAUSE_LABELS}

    for chunk in chunks:
        if len(chunk.strip()) < 20:  # skip very short chunks
            continue
        result = classifier(chunk, candidate_labels=CLAUSE_LABELS)
        for label, score in zip(result["labels"], result["scores"]):
            if score > scores[label]:
                scores[label] = score

    results = []
    for label, score in scores.items():
        if score > 0.50:
            results.append({
                "type": label,
                "confidence": round(score, 2),
                "severity": CLAUSE_CONFIG[label]["severity"],
                "method": "legalbert"
            })

    return sorted(results, key=lambda x: x["confidence"], reverse=True)

# ─────────────────────────────────────────────────────────────
# HYBRID MERGE — combine LegalBERT + keyword results
# ─────────────────────────────────────────────────────────────
def _merge_results(legalbert_results: list, keyword_results: list) -> list:
    """
    Merges LegalBERT and keyword results.
    If both detect same clause → take higher confidence.
    If only keyword detects it → include if confidence >= 0.80.
    """
    merged = {}

    for item in legalbert_results:
        merged[item["type"]] = item

    for item in keyword_results:
        ctype = item["type"]
        if ctype not in merged:
            # Only add keyword-only results if highly confident
            if item["confidence"] >= 0.80:
                item["method"] = "keyword_only"
                merged[ctype] = item
        else:
            # Both detected — take higher confidence
            if item["confidence"] > merged[ctype]["confidence"]:
                merged[ctype]["confidence"] = item["confidence"]
                merged[ctype]["method"] = "hybrid"
            else:
                merged[ctype]["method"] = "hybrid"

    return sorted(merged.values(), key=lambda x: x["confidence"], reverse=True)

# ─────────────────────────────────────────────────────────────
# MAIN ENTRY POINT
# ─────────────────────────────────────────────────────────────
def analyze(text: str) -> list:
    """
    Main function called by Member A's /analyze-policy endpoint.

    Tries LegalBERT first, merges with keyword results for best accuracy.
    Falls back to keyword-only if LegalBERT is unavailable.

    Args:
        text (str): Raw T&C / legal text

    Returns:
        list: [{"type": str, "confidence": float, "severity": str, "method": str}, ...]
    """
    if not text or not text.strip():
        return []

    chunks = _chunk_text(text)
    print(f"[policy_analyzer] Processing {len(chunks)} chunks...")

    # Always run keyword engine (fast, no dependencies)
    keyword_results = _keyword_classify(chunks)

    try:
        # Try LegalBERT and merge with keyword results
        legalbert_results = _legalbert_classify(chunks)
        final_results = _merge_results(legalbert_results, keyword_results)
        print(f"[policy_analyzer] Hybrid detection: {len(final_results)} clauses found.")
        return final_results

    except Exception as e:
        print(f"[policy_analyzer] LegalBERT unavailable: {e}")
        print("[policy_analyzer] Using keyword engine only.")
        return keyword_results


# ─────────────────────────────────────────────────────────────
# QUICK TEST
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    sample_text = """
    We may share your personal data with third-party advertisers and our affiliates
    for marketing purposes. We use cookies to track your browsing behavior and build
    a profile for targeted ads. Your subscription will auto-renew each billing cycle
    unless you cancel. By using this service, you waive your right to a class action
    and agree to binding arbitration. We are not liable for any damages whatsoever.
    The service is provided on an as-is basis without any warranty. We may collect
    your GPS location and precise geolocation data at any time. We may disclose your
    information to our subsidiaries, business partners, and service providers.
    """

    print("=== SmartConsent Guard — Policy Analyzer Test ===\n")
    output = analyze(sample_text)

    print("\n=== DETECTED CLAUSES ===")
    for clause in output:
        print(f"  [{clause['severity']}] {clause['type']}")
        print(f"         Confidence: {clause['confidence']} | Method: {clause['method']}")