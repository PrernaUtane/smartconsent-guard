from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional

# ---------- Initialize FastAPI ----------
app = FastAPI(title="SmartConsent Guard API", version="1.0.0")

# ---------- CORS Configuration (CRITICAL for Chrome Extension) ----------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins (for development)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- Request/Response Models ----------
class URLRequest(BaseModel):
    url: str

class PolicyRequest(BaseModel):
    text: str

class CheckURLResponse(BaseModel):
    is_phishing: bool
    risk_score: int
    reasons: List[str]

class ClauseResult(BaseModel):
    type: str
    confidence: float

class AnalyzePolicyResponse(BaseModel):
    risk_score: int
    level: str  # LOW, MEDIUM, HIGH
    explanation: str
    clauses: List[ClauseResult]

# ---------- Endpoints ----------

@app.get("/health")
def health_check():
    """Simple health check to confirm the server is running."""
    return {"status": "ok", "version": "1.0.0"}

@app.post("/check-url", response_model=CheckURLResponse)
def check_url(request: URLRequest):
    """
    Analyzes a URL for phishing indicators.
    MEMBER 2: Replace the dummy logic below with your detect() function.
    """
    # --- DUMMY LOGIC (To be replaced by Member 2) ---
    # This is a placeholder so the frontend can start developing.
    # Member 2 will import phishing_detector and call detect(url).
    dummy_url = request.url.lower()
    if "paypal" in dummy_url or "login" in dummy_url or ".tk" in dummy_url:
        return CheckURLResponse(
            is_phishing=True,
            risk_score=85,
            reasons=["Suspicious TLD", "Brand impersonation detected"]
        )
    else:
        return CheckURLResponse(
            is_phishing=False,
            risk_score=5,
            reasons=["No risk factors detected"]
        )

@app.post("/analyze-policy", response_model=AnalyzePolicyResponse)
def analyze_policy(request: PolicyRequest):
    """
    Analyzes Terms & Conditions text for risky clauses.
    MEMBER 3 & 2: Replace dummy logic with actual policy analysis + risk engine.
    """
    # --- DUMMY LOGIC (To be replaced by Members 2 & 3) ---
    # Member 3 will call policy_analyzer.analyze() to get clauses.
    # Member 2 will call risk_engine.compute(clauses) to get the RI.
    
    dummy_text = request.text.lower()
    clauses = []
    
    if "sell" in dummy_text or "share" in dummy_text:
        clauses.append(ClauseResult(type="Data Selling", confidence=0.95))
    if "track" in dummy_text or "cookie" in dummy_text:
        clauses.append(ClauseResult(type="Behavioral Tracking", confidence=0.85))
    
    if clauses:
        return AnalyzePolicyResponse(
            risk_score=72,
            level="HIGH",
            explanation="Risky clauses found. Your data may be shared or tracked.",
            clauses=clauses
        )
    else:
        return AnalyzePolicyResponse(
            risk_score=15,
            level="LOW",
            explanation="No major risky clauses detected.",
            clauses=[]
        )