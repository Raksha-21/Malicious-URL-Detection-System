# 🛡️ Malicious URL & Cyber Threat Detection System
## Final Project Documentation & Technical Overview

---

### 1. The Core Cybersecurity Problem
Phishing and malicious URL distribution remain the **#1 initial attack vector** for cyber threat actors worldwide. Modern cybercriminals employ sophisticated techniques to trick victims into revealing sensitive credentials, installing malware, or bypassing organizational security filters.

Key structural deception tactics used in malicious URLs include:
- **IP Address Host Masking**: Bypassing domain name registration by hosting phishing kits directly on raw IP addresses (e.g. `http://192.168.1.10/login`).
- **Brand Hijacking & Keyword Spoofing**: Infiltrating trusted brand names into subdomains or paths (e.g. `secure-paypal-login.xyz`).
- **Suspicious Top-Level Domains (TLDs)**: Utilizing low-cost, disposable TLDs frequently associated with automated phishing campaigns (`.top`, `.xyz`, `.tk`).
- **High Shannon Entropy**: Injecting randomized alpha-numeric strings into subdomains or paths to obfuscate real target destinations or evade simple string filters.
- **Obfuscated Query Parameters & Redirections**: Using `@` symbols or double slashes (`//`) within paths to trick legacy browser parsers into redirecting users to hostile servers.

---

### 2. Technology Stack & Rationale

| Layer | Technology | Selection Rationale |
|---|---|---|
| **Programming Language** | **Python 3.12** | Industry-standard language for cybersecurity analytics, offering robust string processing, regex pattern matching, and built-in URL parsing capabilities (`urllib.parse`). |
| **Frontend Framework** | **Streamlit** | Enables rapid development of dynamic, reactive web dashboards without JavaScript bloat. Provides clean state management (`st.session_state`) for real-time risk analysis. |
| **Visualization Engine** | **Plotly (`plotly.graph_objects`)** | Renders crisp, responsive vector gauges (`go.Indicator`) natively inside Streamlit. Eliminates fragile raw HTML/canvas injection bugs while guaranteeing accurate needle alignment. |
| **Parsing & Entropy Engine** | **`urllib.parse` + `math.log2`** | Performs exact RFC 3986 URL parsing and Shannon Entropy mathematical calculations ($H(X) = -\sum p(x) \log_2 p(x)$) without third-party runtime dependencies. |

---

### 3. System Architecture & Modular Design

The system strictly enforces a **Decoupled 2-Tier Architecture**:

```
 ┌─────────────────────────────────────────────────────────┐
 │                      USER INPUT                         │
 └────────────────────────────┬────────────────────────────┘
                              │
                              ▼
 ┌─────────────────────────────────────────────────────────┐
 │                  DETECTION ENGINE                       │
 │                    (detector.py)                        │
 ├─────────────────────────────────────────────────────────┤
 │ • RFC-compliant URL Normalization & Validation           │
 │ • Feature Extraction (Lengths, Special Chars, Entropy)  │
 │ • 15+ Heuristic Rules Engine (+1 to +3 points per rule) │
 │ • Deterministic Point Summation (Capped at 20)          │
 │ • Returns immutable JSON/Dict result                    │
 └────────────────────────────┬────────────────────────────┘
                              │
                              ▼
 ┌─────────────────────────────────────────────────────────┐
 │                  STREAMLIT DASHBOARD                    │
 │                       (app.py)                          │
 ├─────────────────────────────────────────────────────────┤
 │ • Prominent Severity Warning Banner                     │
 │ • Interactive Plotly Angular Risk Gauge                 │
 │ • Equal-Sized URL Structure Breakdown Cards             │
 │ • Triggered Risk Factors (+Points Breakdown)            │
 │ • Full Extracted Features Matrix                        │
 │ • Greenish Defensive Guidance Box                       │
 └────────────────────────────┴────────────────────────────┘
```

**Why Decoupling Matters**: `app.py` never computes scores independently. All mathematical calculations occur strictly inside `detector.py`. This guarantees complete data consistency across the gauge, summary cards, and risk factor badges.

---

### 4. Why This UI Design is Ideal & Complete

The dashboard was built following modern Security Operations Center (SOC) UI aesthetics:

1. **Dark SOC Obsidian Theme**: Provides high contrast, reducing visual fatigue while mimicking professional enterprise SOC interfaces (CrowdStrike, Splunk, Sentinel).
2. **Prominent Top Warning Banner**: Instantly delivers plain-language severity assessment (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) at first glance before diving into deep technical metrics.
3. **Precision Plotly Risk Gauge**: Visually presents the 0–20 risk score with color-coded threshold zones (Green, Yellow, Orange, Red) for instant risk interpretation.
4. **Equal-Sized URL Structure Cards**: Protocol, Domain/Host, Path, and Query Parameters are displayed in uniform 140px flex-cards with custom scrollable code blocks, maintaining clean alignment regardless of URL length.
5. **Transparent Scoring Breakdown**: Lists every triggered heuristic with its exact point contribution (`+1`, `+2`, `+3`), eliminating "black box" obscurity.
6. **Greenish Defensive Guidance Box**: Highlights actionable security recommendations with a soothing green accent border and subtle background tint.
7. **Preset Test Toolbar & Session History**: Allows examiners or users to perform one-click demonstrations across safe, suspicious, and critical phishing examples.

---

### 5. Why a Heuristic Rule-Based Approach is Sufficient

For this scope, a deterministic heuristic engine offers distinct advantages over complex Machine Learning (ML) models or cloud API dependencies:

- **100% Explainable & Transparent**: Every risk point is mapped directly to a human-auditable security rule. Unlike ML "black box" predictions, users can see *why* a URL is classified as malicious.
- **Zero Latency & Offline Capability**: Executes in **< 5 milliseconds** locally without requiring network round-trips to third-party reputation APIs.
- **100% Privacy & Data Security**: No URLs are transmitted over the internet or logged to external SaaS vendors (e.g. VirusTotal API), protecting sensitive enterprise internal links.
- **Zero Third-Party API Key Dependencies**: Operates independently without requiring subscription keys or rate-limited external services.

---

### 6. Quick Start & Execution

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Launch Streamlit app
streamlit run app.py
```

Then open `http://localhost:8501` in your web browser.
