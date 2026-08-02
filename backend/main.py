# main.py
# Purpose: FastAPI server for SmartConsent Guard
# Author: Member A (Backend Integrator)
# Endpoints: /health, /check-url, /analyze-policy, /simplify-policy

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional

# Import Member B's modules
from phishing_detector import detect
from risk_engine import compute

# ✅ NEW: Import Member C's policy analyzer
from policy_analyzer import analyze

# Create FastAPI app
app = FastAPI(
    title="SmartConsent Guard API",
    description="AI-powered browser security system for phishing detection and T&C analysis",
    version="1.0.0"
)

# Configure CORS (allows Chrome extension to talk to this server)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins (for development)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Request/Response Models ---

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
    ri_score: int
    level: str
    explanation: str
    clauses: List[ClauseResult]

class HealthResponse(BaseModel):
    status: str
    version: str
    components: dict

# --- Endpoints ---

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """
    Health check endpoint to verify server is running.
    """
    return {
        "status": "ok",
        "version": "1.0.0",
        "components": {
            "phishing_detector": "loaded",
            "risk_engine": "loaded",
            "policy_analyzer": "loaded"  # ✅ Changed from "pending" to "loaded"
        }
    }

@app.post("/check-url", response_model=CheckURLResponse)
async def check_url(request: URLRequest):
    """
    Analyze a URL for phishing indicators.
    Uses Member B's detect() function.
    """
    result = detect(request.url)
    return {
        "is_phishing": result["is_phishing"],
        "risk_score": result["risk_score"],
        "reasons": result["reasons"]
    }

@app.post("/analyze-policy", response_model=AnalyzePolicyResponse)
async def analyze_policy(request: PolicyRequest):
    """
    Analyze Terms & Conditions text for risky clauses.
    ✅ Now uses Member C's policy_analyzer for real clause detection.
    """
    # ✅ REAL: Call Member C's analyze function
    clauses = analyze(request.text)
    
    # Call Member B's compute function with real clauses
    result = compute(clauses)
    
    return {
        "ri_score": result["ri_score"],
        "level": result["level"],
        "explanation": result["explanation"],
        "clauses": clauses  # ✅ Return real clauses instead of dummy
    }

# --- Optional: Root endpoint for welcome message ---
@app.get("/")
async def root():
    return {
        "message": "Welcome to SmartConsent Guard API",
        "docs": "/docs",
        "health": "/health"
    }