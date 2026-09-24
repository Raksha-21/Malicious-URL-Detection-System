# 🛡️ Malicious URL & Cyber Threat Detection System
## Academic Project Report & Technical Documentation

---

### Abstract
The Malicious URL Detection System is an academic cybersecurity web application developed using Python and Streamlit to identify potential warning signs in website URLs. The user enters a URL into the web interface, and the system analyzes its characteristics locally using predefined heuristic rules. The analyzed features include URL length, dots, hyphens, special characters, HTTPS usage, IP address presence, the `@` symbol, and suspicious keywords such as `login`, `verify`, `account`, `update`, and `secure`. A point-based risk score is calculated based on the detected indicators, and the system displays a result along with the reasons and extracted features. The application does not fetch or execute submitted URLs. It is designed as an educational prototype to demonstrate explainable and lightweight URL-based threat analysis.

---

### 1. Problem Statement
Phishing and malicious links are commonly used by attackers to trick users into visiting fraudulent websites or sharing sensitive information. Such links may contain suspicious keywords, IP addresses, unusual structures, excessive special characters, or insecure HTTP connections. Ordinary users may not easily recognize these warning signs before opening a link. The problem addressed by this project is to provide a simple and explainable method for analyzing a URL locally without visiting or executing it, and to inform the user about possible cybersecurity risks.

---

### 2. Objectives
- To develop a web-based tool for analyzing website URLs using Python and Streamlit.
- To extract important structural characteristics from a submitted URL.
- To identify common warning indicators such as IP addresses, missing HTTPS, the `@` symbol, and suspicious keywords.
- To calculate a point-based heuristic risk score based on detected indicators.
- To display understandable warning reasons and extracted URL features.
- To ensure that the submitted URL is analyzed locally without fetching or executing it.

---

### 3. Main Features
- **URL Input**: Allows the user to enter a website URL for analysis.
- **URL Normalization and Validation**: Adds `http://` when a protocol is not provided and performs basic structural validation.
- **Feature Extraction**: Extracts structural and statistical characteristics such as URL length, hostname length, path length, dots, hyphens, slashes, special characters, Shannon entropy, HTTPS usage, IP address presence, `@` symbol, suspicious keywords, suspicious TLDs, and double slashes in the path.
- **Heuristic Scoring**: Applies predefined rule-based conditions and assigns points to detected warning indicators (Maximum score = 20).
- **Risk Classification**: Classifies analyzed URLs into four risk levels: **LOW**, **MEDIUM**, **HIGH**, and **CRITICAL**.
- **Risk Explanation**: Displays specific indicators contributing to the risk score along with point contributions.
- **URL Structure Breakdown**: Displays uniform, equal-sized cards for Protocol, Hostname, Path, and Query parameters (with sensitive query parameters masked).
- **Detailed Feature Display**: Presents all extracted URL features in a structured table.
- **Scan History**: Maintains session-based scan logs including timestamp, score, severity, and result.
- **Risk Visualization**: Displays a Plotly vector angular gauge and high-impact warning banner.
- **Local Analysis**: Analyzes submitted URLs locally without opening, fetching, or executing destination websites.
- **Responsive Interface**: Cybersecurity Dark SOC Obsidian and Light Minimal themes designed for laptop and desktop screens.

---

### 4. System Requirements

| Requirement | Specification |
|---|---|
| **Operating System** | Windows / Linux / macOS |
| **Programming Language** | Python 3.10 or above |
| **Framework** | Streamlit |
| **Libraries** | `re`, `urllib.parse`, `math`, `streamlit`, `plotly`, `pandas` |
| **Development Tool** | Visual Studio Code / Any Python IDE |
| **Execution Command** | `python -m streamlit run app.py` |

---

### 5. System Architecture
The system follows a lightweight 2-tier Python web application architecture. The application uses Streamlit for the user interface (`app.py`) and a separate detection engine module (`detector.py`).

#### System Flow:
1. User enters a URL through the Streamlit interface.
2. The system normalizes the URL (adds `http://` if missing protocol).
3. The URL structure is checked for basic validity.
4. The detector extracts structural and statistical features.
5. Predefined heuristic rules are evaluated against extracted features.
6. A point-based risk score (0–20) is computed and mapped to a severity level.
7. Results, warnings, Plotly gauge, structure breakdown, and features are displayed.

```
 User Input ──► Streamlit UI ──► URL Normalizer & Validator
                                        │
                                        ▼
                             Feature Extractor (detector.py)
                                        │
                                        ▼
                             Heuristic Rules Evaluator
                                        │
                                        ▼
                             Score & Severity Calculation
                                        │
                                        ▼
                             Streamlit SOC Dashboard Display
```

---

### 6. Actual Functionalities and Test Results

#### 6.1 Sample Test Matrix
| Input | Observed Result | Explanation |
|---|---|---|
| `https://chatgpt.com/c/example` | **Risk Score: 0 (LOW)** | HTTPS enabled, clean domain, no heuristic warning rules triggered. |
| `http://192.168.1.100/login` | **Risk Score: 6 (HIGH)** | Raw IP host (+3), missing HTTPS (+1), suspicious keyword `login` (+2). |
| `http://example.com` | **Risk Score: 1 (LOW)** | Analyzed correctly; missing HTTPS (+1) detected. |
| `http://paypal-verify-login.top/account` | **Risk Score: 7 (CRITICAL)** | Suspicious TLD `.top` (+2), keywords `paypal`, `verify`, `login` (+3), missing HTTPS (+1), long URL (+1). |

---

### 7. Functional Testing Matrix

| Test Case | Input / Action | Expected Result | Status |
|---|---|---|---|
| **Empty Input** | Click Analyze without entering a URL | Display input warning | **Passed** |
| **Normal HTTPS URL** | `https://chatgpt.com/c/example` | Low score (0/20), green gauge | **Passed** |
| **HTTP URL** | `http://example.com` | Detect missing HTTPS (+1 point) | **Passed** |
| **IP Address URL** | `http://192.168.1.100/login` | Detect IP address host (+3) & `login` (+2) | **Passed** |
| **Suspicious Keyword** | URL containing `login` / `verify` | Add keyword points & display badges | **Passed** |
| **`@` Symbol URL** | URL containing `@` symbol | Detect `@` symbol warning (+2 points) | **Passed** |
| **Missing Protocol** | Enter `example.com` without protocol | Automatically prepends `http://` | **Passed** |
| **Feature Display** | Analyze valid URL | Render full feature table & breakdown | **Passed** |

---

### 8. Limitations
- Uses predefined heuristic rules rather than a trained machine-learning model.
- Risk score is a point-based indicator (0–20), not a statistical probability or accuracy percentage.
- May produce false positives or false negatives on complex URLs.
- Does not query live threat-intelligence APIs (e.g., VirusTotal).
- Does not inspect destination website content or execute JavaScript/payloads.
- Low-risk result does not guarantee safety, and suspicious result does not prove malicious intent.

---

### 9. Future Scope
- Implement Machine Learning classification algorithms (e.g. Random Forest, XGBoost) trained on phishing datasets.
- Expand rule database for URL shorteners (`bit.ly`, `tinyurl`) and typosquatting detection.
- Add external threat-intelligence API integration (e.g. VirusTotal, PhishTank) as an optional online lookup mode.
- Export scan reports to PDF / CSV formats.

---

### 10. Conclusion
The Malicious URL Detection System was successfully implemented as a Python and Streamlit-based cybersecurity prototype. The system analyzes URL characteristics using heuristic rules, calculates a point-based risk score, and displays understandable warning reasons and extracted features. The application is safe by design because it analyzes URLs locally without fetching or executing them. It serves as an explainable, lightweight, and effective educational prototype for cybersecurity threat analysis.
