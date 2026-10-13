# SmartConsent Guard

**Automated Contractual Semantics for Online Platform**

A Chrome Extension (Manifest V3) with FastAPI backend that protects users from phishing websites and risky Terms & Conditions.

## Team
- Member 1 (Lead/Backend)
- Member 2 (Phishing & Risk)
- Member 3 (Policy Analysis)
- Member 4 (Extension & UI)

## Features
- **Phishing & Scam Protection**: Multi-layered detection (Heuristics, Google Safe Browsing, VirusTotal).
- **Modular Extension UI**:
  - **Overview**: Live circular SVG risk gauge ($RI = 0.5P + 0.3L + 0.2S$) & threat verdict.
  - **Plain-English Summary**: Privacy grade (A-F) scorecard and simplified TL;DR breakdowns.
  - **Cookie & Tracker Analyzer**: Live 1st-party vs 3rd-party cookie inspection with automated OneTrust/Cookiebot banner auto-decline and clear tracking cookies.
  - **Dark Patterns & Traps Detector**: Flags forced arbitration, auto-renewal traps, data monetization, roach motel cancellation, and liability disclaimers with in-page highlighting.
  - **AI Policy Q&A**: Interactive assistant answering user questions regarding privacy and contracts with direct excerpts.
  - **Breach Intelligence**: Domain reputation check and email leak lookup.
  - **History & PDF Export**: Audit log with one-click formal executive PDF compliance report generator.

## Folder Structure
- `/backend` – FastAPI server (Python)
  - `main.py` – API router & server endpoints
  - `qa_service.py` – AI Q&A, Dark Patterns & Breach Intelligence
  - `policy_analyzer.py` & `nli_service.py` – Contract semantic clause analysis
  - `risk_engine.py` – Multi-dimensional weighted risk indexing
  - `phishing_detector.py` – Heuristic & brand spoofing detection
- `/extension` – Chrome Extension (Manifest V3)
  - `popup/` – Modular multi-tab dark-mode extension interface
  - `content.js` – Policy extractor, auto-decline handler & in-page highlighter
  - `background.js` – Navigation interceptor & security service worker
  - `warning/` – Redirection interstitial warning screen

## How to Run
1. **Backend**: Double-click `start_server.bat` or run `uvicorn main:app --reload` inside `backend/`.
2. **Extension**: Open `chrome://extensions`, enable **Developer mode**, click **Load unpacked**, and select the `extension/` directory.
