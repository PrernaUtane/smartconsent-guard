# SmartConsent Guard
### Automated Contractual Semantics for Online Platforms

SmartConsent Guard is a Chrome Extension (Manifest V3) with a Python FastAPI backend designed to help users identify potentially suspicious websites and understand privacy risks in online Terms & Conditions.

## Key Features

- **Phishing Detection:** Uses URL heuristics and, where configured, external reputation services to identify potentially suspicious websites.
- **Risk Assessment:** Calculates a weighted risk index using the project's risk-scoring formula.
- **Privacy Policy Analysis:** Identifies potentially risky clauses, including data monetization, behavioral tracking, forced arbitration, and automatic renewal.
- **Plain-English Explanations:** Helps users understand complex policy language.
- **AI Policy Q&A:** Allows users to ask questions about analyzed policy text, if supported by the configured backend.
- **Browser Extension Interface:** Presents security and privacy findings through a Chrome Extension.
- **Risk History and Reports:** Supports reviewing previous assessments and generating reports where implemented.

## Technology Stack

- Python 3.11
- FastAPI
- JavaScript
- Chrome Extension Manifest V3
- NLP/NLI libraries used by the project

## Project Structure

```text
smartconsent-guard/
├── backend/
│   ├── main.py
│   ├── phishing_detector.py
│   ├── policy_analyzer.py
│   ├── nli_service.py
│   ├── qa_service.py
│   ├── risk_engine.py
│   └── requirements.txt
└── extension/
    ├── manifest.json
    ├── background.js
    ├── content.js
    ├── popup/
    └── warning/
```

## Getting Started

### 1. Start the backend

From the project root, activate the existing Python 3.11 environment:

```powershell
.\.venv311\Scripts\Activate.ps1
cd backend
python -m uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

The API documentation is available at:

http://127.0.0.1:8000/docs

### 2. Load the browser extension

1. Open `chrome://extensions/` in Chrome or `brave://extensions/` in Brave.
2. Enable **Developer mode**.
3. Select **Load unpacked**.
4. Choose the project's `extension` directory.
5. Open the extension and test its functionality with the backend running.

### 3. Testing

Run the existing backend test suites and record the actual results. Include phishing detection metrics such as accuracy, precision, recall, and false-positive rate when these have been measured.

## Risk Assessment

The project uses a weighted risk-index formula:

`RI = 0.5P + 0.3L + 0.2S`

Refer to the implementation to understand the definitions and scaling of each input.

## Limitations

- Heuristic phishing detection can produce false positives and false negatives.
- External reputation checks depend on the relevant service being configured and available.
- Policy analysis identifies potential privacy risks and does not replace legal advice.
- Features that depend on external APIs or browser permissions may require additional configuration.

## Future Improvements

- Expand phishing test coverage and improve evaluation metrics.
- Improve policy-analysis explanations.
- Refine extension usability and error handling.
- Expand privacy-risk reporting and history features.

## Team

- Member 1 — Lead / Backend
- Member 2 — Phishing Detection / Risk
- Member 3 — Policy Analysis
- Member 4 — Extension / UI
