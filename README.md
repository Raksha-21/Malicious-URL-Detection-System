# 🛡️ Malicious URL & Cyber Threat Detection System

A heuristic-based, rule-driven URL security analysis dashboard built with **Python 3.12 + Streamlit + Plotly**. 

> 📌 **Comprehensive Project Documentation**: For the full project writeup covering problem statement, tech stack, architectural rationale, UI design decisions, and scope justification, see [PROJECT_DOCUMENTATION.md](file:///c:/Users/RAKSHA/Downloads/url_detector/PROJECT_DOCUMENTATION.md).

---

## 1. Quick Start

```bash
# Install required dependencies
pip install -r requirements.txt

# Run the Streamlit SOC Dashboard
streamlit run app.py
```

Then open `http://localhost:8501` in your browser.

---

## 2. Project File Structure

| File | Purpose |
|---|---|
| [`PROJECT_DOCUMENTATION.md`](file:///c:/Users/RAKSHA/Downloads/url_detector/PROJECT_DOCUMENTATION.md) | **Full Final Project Writeup & Viva Guide** (Problem background, tech stack rationale, UI design decisions, and heuristic scope justification). |
| [`detector.py`](file:///c:/Users/RAKSHA/Downloads/url_detector/detector.py) | **Pure Detection Engine**. Extracts URL structural features, computes Shannon Entropy, and calculates heuristic risk scores (0–20) with exact point breakdowns. |
| [`app.py`](file:///c:/Users/RAKSHA/Downloads/url_detector/app.py) | **Streamlit SOC Dashboard UI**. Renders the high-visibility warning banner, Plotly gauge, equal-sized structure cards, risk factors breakdown, and defensive guidance. |
| [`requirements.txt`](file:///c:/Users/RAKSHA/Downloads/url_detector/requirements.txt) | Python dependency manifest (`streamlit`, `plotly`, `pandas`). |

---

## 3. Core Features & Capabilities

- 🛡️ **Plain-Language Warning Banner**: High-impact top banner providing immediate threat level severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- 📊 **Precision Plotly Risk Gauge**: Renders an interactive, vector-based 0–20 indicator with color-coded risk bands.
- 🧩 **Equal-Sized URL Structure Breakdown**: Pixel-aligned uniform cards for Protocol, Host, Path, and Query parameters with custom scrollable code blocks.
- ⚠️ **Transparent Rule Attribution**: Every triggered heuristic displays its exact point contribution (`+1`, `+2`, `+3`).
- 🟢 **Defensive Action Guidance**: Clear actionable recommendations with a green accent border and subtle highlight tint.
- 🧪 **Quick-Test Presets & Session History**: One-click demo toolbar and session scan tracker.

---

## 4. Scope & Educational Context

This project is a self-contained, rule-based cybersecurity tool. It intentionally does **not** rely on external APIs (e.g. VirusTotal), machine learning models, or database backends. This guarantees:
1. **100% Deterministic & Explainable Output**
2. **Zero Third-Party Latency (< 5ms analysis time)**
3. **100% Privacy with No External URL Leakage**
