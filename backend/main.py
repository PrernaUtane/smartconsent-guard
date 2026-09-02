"""
main.py — SmartConsent Guard FastAPI backend server.

Endpoints:
    GET  /                            → Welcome message
    GET  /health                      → Server health check
    POST /check-url                   → Phishing / suspicious URL analysis
    POST /analyze-policy              → Terms & Conditions NLP risk analysis
    POST /analyze-policy-enhanced     → Enhanced T&C analysis with NLI (NEW)
    POST /check-google-safebrowsing   → Google Safe Browsing API check
    POST /check-virustotal            → VirusTotal API check (70+ vendors)
"""

import os
import logging
import time
from contextlib import asynccontextmanager
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

import requests
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl, field_validator

# Import functions directly (not classes)
from phishing_detector import detect
from policy_analyzer import analyze
from risk_engine import compute

# Try to import NLI service (optional)
try:
    from nli_service import analyze_with_nli
    NLI_AVAILABLE = True
    print("[main.py] NLI service loaded successfully")
except ImportError:
    NLI_AVAILABLE = False
    print("[main.py] NLI service not available. Using keyword fallback.")


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("smartconsent")


# ---------------------------------------------------------------------------
# App initialisation
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting SmartConsent Guard backend …")
    logger.info("PhishingDetector ready.")
    logger.info("PolicyAnalyzer ready.")
    logger.info(f"NLI Service: {'Available' if NLI_AVAILABLE else 'Not available'}")
    yield
    logger.info("Shutting down SmartConsent Guard backend.")


app = FastAPI(
    title="SmartConsent Guard API",
    description=(
        "AI-powered browser security backend. "
        "Detects phishing URLs and analyzes Terms & Conditions for risky clauses. "
        "Integrates Google Safe Browsing and VirusTotal for enhanced detection."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# Allow requests from the Chrome extension (chrome-extension://* origins)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class UrlRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def url_must_not_be_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("url must not be empty")
        return v.strip()


class PolicyRequest(BaseModel):
    text: str

    @field_validator("text")
    @classmethod
    def text_must_not_be_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("text must not be empty")
        return v.strip()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/")
async def root():
    """Welcome message with links to documentation."""
    return {
        "message": "Welcome to SmartConsent Guard API",
        "docs": "/docs",
        "health": "/health"
    }


@app.get("/health", tags=["system"])
def health_check():
    """Returns server status and loaded component info."""
    return {
        "status": "ok",
        "service": "SmartConsent Guard",
        "version": "1.0.0",
        "components": {
            "phishing_detector": True,
            "policy_analyzer": True,
            "nli_available": NLI_AVAILABLE,
            "nlp_model_loaded": False,
        },
    }


@app.post("/check-url", tags=["phishing"])
def check_url(request: UrlRequest):
    """
    Analyse a URL for phishing / suspicious domain patterns.

    Returns:
        is_phishing (bool), risk_score (0–100), reasons (list[str])
    """
    logger.info(f"Checking URL: {request.url}")
    result = detect(request.url)
    logger.info(
        f"URL check result — score={result['risk_score']}, "
        f"phishing={result['is_phishing']}"
    )
    return result


@app.post("/analyze-policy", tags=["policy"])
def analyze_policy(request: PolicyRequest):
    """
    Analyze Terms & Conditions / Privacy Policy text for risky clauses.
    Uses keyword-based detection (fast, offline).

    Returns:
        risk_score, level, clauses (with confidence), explanation
    """
    text_preview = request.text[:80].replace("\n", " ")
    logger.info(f"Analyzing policy text: '{text_preview}…'")

    # analyze() returns a list of clauses
    clauses = analyze(request.text)
    
    clause_count = len(clauses)
    logger.info(f"Policy analysis result — {clause_count} clauses detected")
    
    if clauses:
        result = compute(clauses)
        return {
            "ri_score": result["ri_score"],
            "level": result["level"],
            "explanation": result["explanation"],
            "clauses": clauses,
            "method": "keyword"
        }
    else:
        return {
            "ri_score": 0,
            "level": "LOW",
            "explanation": "No risky clauses detected in this policy.",
            "clauses": [],
            "method": "keyword"
        }


@app.post("/analyze-policy-enhanced", tags=["policy"])
def analyze_policy_enhanced(request: PolicyRequest):
    """
    Enhanced policy analysis using NLI (AI-powered) with keyword fallback.
    Returns clauses detected using NLI or keywords.

    Returns:
        risk_score, level, clauses (with confidence), explanation, method
    """
    text_preview = request.text[:80].replace("\n", " ")
    logger.info(f"Analyzing policy text (enhanced): '{text_preview}…'")

    try:
        if NLI_AVAILABLE:
            # Use NLI service - handle both list and dict return types
            nli_result = analyze_with_nli(request.text)
            if isinstance(nli_result, dict):
                clauses = nli_result.get("clauses", [])
            else:
                clauses = nli_result
            logger.info(f"NLI analysis complete — {len(clauses)} clauses detected")
        else:
            # Fallback to keyword analysis
            clauses = analyze(request.text)
            logger.info(f"Keyword analysis complete — {len(clauses)} clauses detected")
    except Exception as e:
        logger.error(f"Enhanced analysis error: {e}. Falling back to keywords.")
        clauses = analyze(request.text)
    
    clause_count = len(clauses)
    logger.info(f"Policy analysis result — {clause_count} clauses detected")
    
    if clauses:
        result = compute(clauses)
        return {
            "ri_score": result["ri_score"],
            "level": result["level"],
            "explanation": result["explanation"],
            "clauses": clauses,
            "method": "nli" if NLI_AVAILABLE else "keyword"
        }
    else:
        return {
            "ri_score": 0,
            "level": "LOW",
            "explanation": "No risky clauses detected in this policy.",
            "clauses": [],
            "method": "nli" if NLI_AVAILABLE else "keyword"
        }


# ---------------------------------------------------------------------------
# Google Safe Browsing API Endpoint
# ---------------------------------------------------------------------------

# ✅ Load API key from environment variable
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
if not GOOGLE_SAFE_BROWSING_API_KEY:
    logger.warning("Google Safe Browsing API key not set in .env file")


@app.post("/check-google-safebrowsing", tags=["phishing", "security"])
def check_google_safebrowsing(request: UrlRequest):
    """
    Check URL against Google Safe Browsing API.

    Returns whether Google flags it as malicious, along with threat type.

    Returns:
        url (str), is_malicious (bool), threat_type (str), message (str)
    """
    url = request.url
    api_key = GOOGLE_SAFE_BROWSING_API_KEY

    # If no API key is configured, return a clear message
    if not api_key:
        logger.warning("Google Safe Browsing API key not configured.")
        return {
            "url": url,
            "is_malicious": False,
            "threat_type": None,
            "message": "Google Safe Browsing API key not configured. Please set GOOGLE_SAFE_BROWSING_API_KEY in .env file."
        }

    # Google Safe Browsing API endpoint
    gsb_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"

    # Request payload
    payload = {
        "client": {
            "clientId": "smartconsent-guard",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        logger.info(f"Checking Google Safe Browsing for: {url}")
        response = requests.post(gsb_url, json=payload, timeout=15)

        if response.status_code == 200:
            data = response.json()
            # If there's a 'matches' field, Google flagged it
            if "matches" in data and data["matches"]:
                threat_type = data["matches"][0].get("threatType", "Unknown")
                logger.info(f"Google Safe Browsing flagged URL as: {threat_type}")
                return {
                    "url": url,
                    "is_malicious": True,
                    "threat_type": threat_type,
                    "message": f"Google Safe Browsing flagged this URL as {threat_type}"
                }
            else:
                logger.info("Google Safe Browsing did not flag this URL")
                return {
                    "url": url,
                    "is_malicious": False,
                    "threat_type": None,
                    "message": "Google Safe Browsing did not flag this URL"
                }
        elif response.status_code == 403:
            logger.error("Google Safe Browsing API key is invalid or has insufficient permissions.")
            return {
                "url": url,
                "is_malicious": False,
                "threat_type": None,
                "message": "API key invalid or has insufficient permissions. Please check your Google Cloud Console."
            }
        elif response.status_code == 429:
            logger.warning("Google Safe Browsing API rate limit exceeded.")
            return {
                "url": url,
                "is_malicious": False,
                "threat_type": None,
                "message": "Rate limit exceeded. Please try again later."
            }
        else:
            logger.error(f"Google Safe Browsing API error: {response.status_code}")
            return {
                "url": url,
                "is_malicious": False,
                "threat_type": None,
                "message": f"Google Safe Browsing API error: {response.status_code}"
            }
    except requests.exceptions.Timeout:
        logger.error("Google Safe Browsing API request timed out.")
        return {
            "url": url,
            "is_malicious": False,
            "threat_type": None,
            "message": "Request timed out. Please try again."
        }
    except requests.exceptions.ConnectionError:
        logger.error("Google Safe Browsing API connection error.")
        return {
            "url": url,
            "is_malicious": False,
            "threat_type": None,
            "message": "Connection error. Please check your internet connection."
        }
    except Exception as e:
        logger.error(f"Unexpected error in Google Safe Browsing check: {str(e)}")
        return {
            "url": url,
            "is_malicious": False,
            "threat_type": None,
            "message": f"Unexpected error: {str(e)}"
        }


# ---------------------------------------------------------------------------
# VirusTotal API Endpoint
# ---------------------------------------------------------------------------

# ✅ Load API key from environment variable
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
if not VIRUSTOTAL_API_KEY:
    logger.warning("VirusTotal API key not set in .env file")


@app.post("/check-virustotal", tags=["phishing", "security"])
def check_virustotal(request: UrlRequest):
    """
    Check URL against VirusTotal's 70+ security vendors.

    Returns whether any vendors flagged it as malicious, along with the count.

    Returns:
        url (str), is_malicious (bool), malicious_vendors (int),
        total_vendors (int), message (str)
    """
    url = request.url
    api_key = VIRUSTOTAL_API_KEY

    # If no API key is configured, return a clear message
    if not api_key:
        logger.warning("VirusTotal API key not configured.")
        return {
            "url": url,
            "is_malicious": False,
            "malicious_vendors": 0,
            "total_vendors": 0,
            "message": "VirusTotal API key not configured. Please set VIRUSTOTAL_API_KEY in .env file."
        }

    try:
        logger.info(f"Checking VirusTotal for: {url}")

        # --- Step 1: Submit URL for analysis ---
        scan_response = requests.post(
            'https://www.virustotal.com/api/v3/urls',
            headers={'x-apikey': api_key},
            data={'url': url},
            timeout=10
        )

        if scan_response.status_code != 200:
            logger.error(f"VirusTotal scan API error: {scan_response.status_code}")
            return {
                "url": url,
                "is_malicious": False,
                "malicious_vendors": 0,
                "total_vendors": 0,
                "message": f"VirusTotal API error: {scan_response.status_code}"
            }

        scan_data = scan_response.json()
        analysis_id = scan_data['data']['id']

        # --- Step 2: Wait a few seconds for results ---
        time.sleep(3)

        # --- Step 3: Get analysis results ---
        result_response = requests.get(
            f'https://www.virustotal.com/api/v3/analyses/{analysis_id}',
            headers={'x-apikey': api_key},
            timeout=10
        )

        if result_response.status_code != 200:
            logger.error(f"VirusTotal results API error: {result_response.status_code}")
            return {
                "url": url,
                "is_malicious": False,
                "malicious_vendors": 0,
                "total_vendors": 0,
                "message": f"VirusTotal results error: {result_response.status_code}"
            }

        result_data = result_response.json()
        stats = result_data['data']['attributes']['stats']

        malicious_count = stats.get('malicious', 0)
        suspicious_count = stats.get('suspicious', 0)
        harmless_count = stats.get('harmless', 0)
        undetected_count = stats.get('undetected', 0)

        total_vendors = malicious_count + suspicious_count + harmless_count + undetected_count
        is_malicious = malicious_count > 2  # Flag if more than 2 vendors say it's malicious

        logger.info(f"VirusTotal results: {malicious_count} malicious, {suspicious_count} suspicious out of {total_vendors} vendors")

        return {
            "url": url,
            "is_malicious": is_malicious,
            "malicious_vendors": malicious_count,
            "suspicious_vendors": suspicious_count,
            "total_vendors": total_vendors,
            "message": f"{malicious_count} out of {total_vendors} vendors flagged this URL as malicious"
        }

    except requests.exceptions.Timeout:
        logger.error("VirusTotal API request timed out.")
        return {
            "url": url,
            "is_malicious": False,
            "malicious_vendors": 0,
            "total_vendors": 0,
            "message": "Request timed out. Please try again."
        }
    except requests.exceptions.ConnectionError:
        logger.error("VirusTotal API connection error.")
        return {
            "url": url,
            "is_malicious": False,
            "malicious_vendors": 0,
            "total_vendors": 0,
            "message": "Connection error. Please check your internet connection."
        }
    except Exception as e:
        logger.error(f"Unexpected error in VirusTotal check: {str(e)}")
        return {
            "url": url,
            "is_malicious": False,
            "malicious_vendors": 0,
            "total_vendors": 0,
            "message": f"Unexpected error: {str(e)}"
        }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
        log_level="info",
    )