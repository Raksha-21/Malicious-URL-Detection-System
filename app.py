"""
app.py
------
Malicious URL & Cyber Threat Detection System
Heuristic-based URL security analysis dashboard (Streamlit + Plotly).

Run with:
    streamlit run app.py
"""

import streamlit as st
import plotly.graph_objects as go
from datetime import datetime

from detector import detect_url

# ==========================================================================
# PAGE CONFIG
# ==========================================================================
st.set_page_config(
    page_title="Malicious URL & Cyber Threat Detection System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ==========================================================================
# THEME DEFINITIONS
# ==========================================================================
THEMES = {
    "Dark SOC Obsidian": {
        "bg": "#0b0e14",
        "card": "#141a24",
        "card_border": "#232b3a",
        "text": "#e6e9ef",
        "muted": "#8b93a7",
        "accent": "#22d3ee",
        "mono_bg": "#0f1420",
        "low": "#22c55e",
        "medium": "#eab308",
        "high": "#f97316",
        "critical": "#ef4444",
        "plot_bg": "#141a24",
    },
    "Light Minimal": {
        "bg": "#f5f7fa",
        "card": "#ffffff",
        "card_border": "#e2e8f0",
        "text": "#1a202c",
        "muted": "#64748b",
        "accent": "#0891b2",
        "mono_bg": "#f1f5f9",
        "low": "#16a34a",
        "medium": "#ca8a04",
        "high": "#ea580c",
        "critical": "#dc2626",
        "plot_bg": "#ffffff",
    },
}

SEVERITY_KEY = {"LOW": "low", "MEDIUM": "medium", "HIGH": "high", "CRITICAL": "critical"}

# ==========================================================================
# SESSION STATE INIT
# ==========================================================================
if "theme_name" not in st.session_state:
    st.session_state.theme_name = "Dark SOC Obsidian"
if "history" not in st.session_state:
    st.session_state.history = []  # list of dicts, most recent first
if "url_input" not in st.session_state:
    st.session_state.url_input = ""
if "last_result" not in st.session_state:
    st.session_state.last_result = None
if "prev_score" not in st.session_state:
    st.session_state.prev_score = 0

PRESETS = {
    "🟢 Safe Demo": "https://www.wikipedia.org/",
    "🌿 Normal Demo": "https://github.com/login?redirect=/home",
    "🟡 Phishing Demo": "http://secure-verify-account-update.top/login/confirm",
    "🔴 Critical / IP Phish Demo": "http://192.168.10.55/paypal/secure/login/verify@confirm-account.tk//redirect?token=9f8s7d6f5s",
}


def apply_preset(url):
    st.session_state.url_input = url


# ==========================================================================
# CSS INJECTION
# ==========================================================================
def inject_css(t):
    st.markdown(
        f"""
        <style>
        .stApp {{
            background-color: {t['bg']};
            color: {t['text']};
        }}
        section[data-testid="stSidebar"] {{
            background-color: {t['card']};
            border-right: 1px solid {t['card_border']};
        }}
        .soc-card {{
            background-color: {t['card']};
            border: 1px solid {t['card_border']};
            border-radius: 14px;
            padding: 18px 20px;
            margin-bottom: 14px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.15);
        }}
        .struct-card {{
            background-color: {t['card']};
            border: 1px solid {t['card_border']};
            border-radius: 14px;
            padding: 16px 18px;
            margin-bottom: 14px;
            height: 140px;
            display: flex;
            flex-direction: column;
            box-shadow: 0 1px 3px rgba(0,0,0,0.15);
            box-sizing: border-box;
        }}
        .struct-mono {{
            font-family: 'Courier New', Courier, monospace;
            background-color: {t['mono_bg']};
            border: 1px solid {t['card_border']};
            border-radius: 8px;
            padding: 8px 12px;
            font-size: 13px;
            color: {t['text']};
            word-break: break-all;
            flex: 1;
            overflow-y: auto;
            margin-top: 4px;
        }}
        .struct-mono::-webkit-scrollbar {{
            width: 4px;
        }}
        .struct-mono::-webkit-scrollbar-thumb {{
            background: {t['card_border']};
            border-radius: 4px;
        }}
        .soc-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 6px 2px 18px 2px;
            border-bottom: 1px solid {t['card_border']};
            margin-bottom: 18px;
        }}
        .soc-title {{
            font-size: 26px;
            font-weight: 700;
            color: {t['text']};
            margin: 0;
        }}
        .soc-subtitle {{
            font-size: 14px;
            color: {t['muted']};
            margin-top: 4px;
        }}
        .soc-status {{
            font-size: 13px;
            font-weight: 600;
            color: {t['low']};
            background-color: {t['bg']};
            border: 1px solid {t['card_border']};
            padding: 6px 14px;
            border-radius: 999px;
        }}
        .mono {{
            font-family: 'Courier New', Courier, monospace;
            background-color: {t['mono_bg']};
            border: 1px solid {t['card_border']};
            border-radius: 8px;
            padding: 10px 14px;
            font-size: 14px;
            color: {t['text']};
            word-break: break-all;
        }}
        .badge {{
            display: inline-block;
            font-family: 'Courier New', Courier, monospace;
            font-size: 13px;
            padding: 6px 12px;
            border-radius: 8px;
            margin: 4px 6px 4px 0;
            border: 1px solid {t['card_border']};
        }}
        .section-label {{
            font-size: 12px;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            color: {t['muted']};
            margin-bottom: 6px;
            font-weight: 600;
        }}
        .metric-value {{
            font-family: 'Courier New', Courier, monospace;
            font-size: clamp(16px, 2.4vw, 24px);
            font-weight: 700;
            white-space: normal;
            overflow-wrap: break-word;
            word-break: break-word;
            line-height: 1.25;
        }}
        .summary-card {{
            min-height: 92px;
            display: flex;
            flex-direction: column;
            justify-content: center;
        }}
        .disclaimer {{
            font-size: 12.5px;
            color: {t['muted']};
            border-top: 1px solid {t['card_border']};
            padding-top: 14px;
            margin-top: 10px;
            line-height: 1.5;
        }}
        div.stButton > button {{
            border-radius: 10px;
            border: 1px solid {t['card_border']};
            font-weight: 600;
        }}
        thead tr th {{
            background-color: {t['mono_bg']} !important;
        }}
        </style>
        """,
        unsafe_allow_html=True,
    )


def sev_color(t, severity):
    return t[SEVERITY_KEY.get(severity, "low")]


# ==========================================================================
# SIDEBAR
# ==========================================================================
def render_sidebar(t):
    with st.sidebar:
        st.markdown("### ⚙️ Configuration")

        st.session_state.theme_name = st.selectbox(
            "Theme",
            list(THEMES.keys()),
            index=list(THEMES.keys()).index(st.session_state.theme_name),
        )

        st.markdown("---")
        st.markdown("### 🧪 Quick Test Presets")
        st.caption("Populates the URL field only — click Analyze Target to scan.")
        for label, url in PRESETS.items():
            if st.button(label, use_container_width=True, key=f"preset_{label}"):
                apply_preset(url)

        st.markdown("---")
        st.markdown("### 🕒 Recent Scan History")

        if not st.session_state.history:
            st.caption("No scans yet this session.")
        else:
            for item in st.session_state.history[:10]:
                color = sev_color(t, item["severity"])
                st.markdown(
                    f"""
                    <div class="soc-card" style="padding:10px 12px; margin-bottom:8px;">
                        <div style="font-size:11px; color:{t['muted']};">{item['time']}</div>
                        <div class="mono" style="font-size:12px; padding:6px 8px; margin:4px 0;">{item['url'][:48]}{'…' if len(item['url'])>48 else ''}</div>
                        <div style="display:flex; justify-content:space-between; font-size:12px;">
                            <span style="color:{color}; font-weight:700;">{item['severity']}</span>
                            <span style="font-family:monospace; color:{t['text']};">{item['score']}/20</span>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            if st.button("🗑️ Clear History", use_container_width=True):
                st.session_state.history = []
                st.rerun()


# ==========================================================================
# GAUGE (Plotly — safe, no raw SVG/canvas exposure)
# ==========================================================================
def render_gauge(t, score, severity, prev_score):
    zones = [
        (0, 2, t["low"]),
        (2, 4, t["medium"]),
        (4, 6, t["high"]),
        (6, 20, t["critical"]),
    ]

    fig = go.Figure()

    fig.add_trace(
        go.Indicator(
            mode="gauge+number",
            value=score,
            number={
                "font": {"size": 40, "color": t["text"], "family": "Courier New"},
                "suffix": " / 20",
            },
            domain={"x": [0, 1], "y": [0, 1]},
            gauge={
                "shape": "angular",
                "axis": {
                    "range": [0, 20],
                    "tickvals": [0, 5, 10, 15, 20],
                    "tickcolor": t["muted"],
                    "tickfont": {"color": t["muted"], "size": 13},
                },
                "bar": {"color": sev_color(t, severity), "thickness": 0.28},
                "bgcolor": t["plot_bg"],
                "borderwidth": 0,
                "steps": [
                    {"range": [z[0], z[1]], "color": z[2] + "33"} for z in zones
                ],
                "threshold": {
                    "line": {"color": sev_color(t, severity), "width": 3},
                    "thickness": 0.9,
                    "value": score,
                },
            },
        )
    )

    fig.update_layout(
        paper_bgcolor=t["plot_bg"],
        plot_bgcolor=t["plot_bg"],
        font={"color": t["text"]},
        margin=dict(l=30, r=30, t=20, b=10),
        height=240,
    )

    st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})


# ==========================================================================
# MAIN PAGE SECTIONS
# ==========================================================================
def render_header(t):
    st.markdown(
        f"""
        <div class="soc-header">
            <div>
                <p class="soc-title">🛡️ Malicious URL &amp; Cyber Threat Detection System</p>
                <p class="soc-subtitle">Heuristic-based URL security analysis</p>
            </div>
            <div class="soc-status">🟢 System Operational</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_analyzer_input(t):
    st.markdown("### 🌐 URL Security Analyzer")
    st.markdown(
        f"<p style='color:{t['muted']}; font-size:14px;'>"
        "A heuristic-based URL security analyzer that evaluates URL structure, "
        "character patterns, entropy, domain characteristics, and potential "
        "phishing indicators."
        "</p>",
        unsafe_allow_html=True,
    )

    col1, col2 = st.columns([5, 1])
    with col1:
        st.text_input(
            "Target URL",
            key="url_input",
            placeholder="https://example.com/login",
            label_visibility="collapsed",
        )
    with col2:
        analyze_clicked = st.button("⚡ Analyze Target", use_container_width=True, type="primary")

    return analyze_clicked


def render_risk_summary(t, result):
    score = result["score"]
    max_score = result["max_score"]
    severity = result["severity"]
    outcome = result["result"]
    color = sev_color(t, severity)

    c1, c2, c3 = st.columns(3, gap="small")
    with c1:
        st.markdown(
            f"""<div class="soc-card summary-card">
                    <div class="section-label">Risk Score</div>
                    <div class="metric-value" style="color:{color};">{score} / {max_score}</div>
                </div>""",
            unsafe_allow_html=True,
        )
    with c2:
        st.markdown(
            f"""<div class="soc-card summary-card">
                    <div class="section-label">Severity</div>
                    <div class="metric-value" style="color:{color};">{severity}</div>
                </div>""",
            unsafe_allow_html=True,
        )
    with c3:
        st.markdown(
            f"""<div class="soc-card summary-card">
                    <div class="section-label">Result</div>
                    <div class="metric-value" style="color:{color};">{outcome}</div>
                </div>""",
            unsafe_allow_html=True,
        )


def render_risk_scale(t):
    st.markdown("#### Risk Scale")
    bands = [
        ("LOW", "0–2", t["low"]),
        ("MEDIUM", "3–4", t["medium"]),
        ("HIGH", "5–6", t["high"]),
        ("CRITICAL", "7–20", t["critical"]),
    ]
    cols = st.columns(4)
    for col, (label, rng, color) in zip(cols, bands):
        with col:
            st.markdown(
                f"""<div class="soc-card" style="text-align:center; border-left:4px solid {color};">
                        <div style="font-weight:700; color:{color};">{label}</div>
                        <div class="mono" style="display:inline-block; margin-top:6px; padding:4px 10px;">{rng}</div>
                    </div>""",
                unsafe_allow_html=True,
            )


def render_risk_factors(t, result):
    st.markdown("#### ⚠️ Triggered Risk Factors")
    reasons = result["reason_details"]
    if not reasons:
        st.markdown(
            f"<div class='soc-card'>No risk-contributing indicators were detected.</div>",
            unsafe_allow_html=True,
        )
        return

    color = sev_color(t, result["severity"])
    html = "<div class='soc-card'>"
    for r in reasons:
        html += (
            f"<div class='badge' style='border-left:3px solid {color};'>"
            f"<b style='color:{color};'>+{r['points']}</b>&nbsp;&nbsp;{r['label']}"
            f"</div>"
        )
    total = sum(r["points"] for r in reasons)
    html += f"<div style='margin-top:10px; color:{t['muted']}; font-size:13px;'>Total contributed points: {total} / {result['max_score']}</div>"
    html += "</div>"
    st.markdown(html, unsafe_allow_html=True)


def render_structure_breakdown(t, result):
    st.markdown("#### 🧩 URL Structure Breakdown")
    s = result["structure"]
    cols = st.columns(4)
    labels = ["Protocol", "Domain / Host", "Path", "Query Parameters"]
    keys = ["protocol", "host", "path", "query"]
    for col, label, key in zip(cols, labels, keys):
        with col:
            st.markdown(
                f"""<div class="struct-card">
                        <div class="section-label">{label}</div>
                        <div class="struct-mono">{s[key]}</div>
                    </div>""",
                unsafe_allow_html=True,
            )


def render_feature_table(t, result):
    st.markdown("#### 🔎 Detailed Extracted URL Features")
    features = result["features"]

    rows = []
    for key, value in features.items():
        if isinstance(value, bool):
            display = "✓ Detected" if value else "✕ Not detected"
        else:
            display = str(value)
        rows.append({"Feature": key, "Value": display})

    st.dataframe(
        rows,
        use_container_width=True,
        hide_index=True,
        column_config={
            "Feature": st.column_config.TextColumn("Feature", width="medium"),
            "Value": st.column_config.TextColumn("Value", width="medium"),
        },
    )


def render_recommendation(t, result):
    st.markdown("#### 🛡️ Defensive Recommendation")
    severity = result["severity"]
    green = t["low"]

    messages = {
        "LOW": "No major warning indicators were identified. Verify the website before entering sensitive information.",
        "MEDIUM": "Use caution and verify the domain before entering personal information.",
        "HIGH": "Avoid opening the URL unless you can verify the domain through a trusted source.",
        "CRITICAL": "Do not open the URL or enter credentials. Verify the URL through a trusted source.",
    }

    st.markdown(
        f"""<div class="soc-card" style="border-left: 4px solid {green}; background-color: {green}12;">
                <div style="color: {green}; font-weight: 600; font-size: 15px; margin-bottom: 6px;">
                    🟢 Action Guidance ({severity})
                </div>
                <div style="color: {t['text']}; font-size: 14px; line-height: 1.5;">
                    {messages.get(severity, '')}
                </div>
                <div style="color: {t['muted']}; font-size: 12px; margin-top: 8px;">
                    This is a heuristic assessment based on URL structure only — not definitive proof of maliciousness.
                </div>
            </div>""",
        unsafe_allow_html=True,
    )


def render_warning_banner(t, result):
    severity = result["severity"]

    banners = {
        "LOW": (
            "✅ LOW RISK — LIKELY SAFE URL",
            "This URL does not exhibit common phishing indicators or suspicious structure patterns. It appears standard, but always verify before entering sensitive credentials.",
            t["low"],
        ),
        "MEDIUM": (
            "⚠️ MEDIUM RISK — SUSPICIOUS INDICATORS DETECTED",
            "This URL contains unusual structural patterns or potential phishing indicators. Proceed with caution and verify the source before entering personal details.",
            t["medium"],
        ),
        "HIGH": (
            "🚨 HIGH RISK — POTENTIALLY MALICIOUS URL",
            "Multiple high-risk security indicators were detected in this URL. Avoid interacting with this link or sharing sensitive information.",
            t["high"],
        ),
        "CRITICAL": (
            "⛔ CRITICAL THREAT — LIKELY MALICIOUS TARGET",
            "HIGH ALERT: This URL exhibits severe threat patterns (e.g. IP host, brand spoofing, or deceptive redirection). Extreme risk of credential theft or phishing!",
            t["critical"],
        ),
    }

    title, text, b_color = banners.get(severity, banners["LOW"])

    st.markdown(
        f"""
        <div class="soc-card" style="
            border-left: 6px solid {b_color};
            background-color: {b_color}18;
            border-color: {b_color}44;
            padding: 18px 22px;
            margin-bottom: 20px;
        ">
            <div style="font-size: 18px; font-weight: 800; color: {b_color}; letter-spacing: 0.02em; margin-bottom: 6px;">
                {title}
            </div>
            <div style="font-size: 14.5px; color: {t['text']}; line-height: 1.5; font-weight: 500;">
                {text}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_disclaimer(t):
    st.markdown(
        f"""<div class="disclaimer">
                <b>Educational Disclaimer:</b> This tool is a college cybersecurity project intended to
                demonstrate rule-based phishing indicator detection. It analyzes only the structural and
                statistical characteristics of a URL string. It does NOT visit the URL, does NOT perform
                payload/network analysis, and does NOT use machine learning or external threat-intelligence
                services. Results are indicative only and must not be treated as a definitive security verdict.
            </div>""",
        unsafe_allow_html=True,
    )


def render_invalid(t, raw_input):
    st.markdown(
        f"""<div class="soc-card" style="border-left:4px solid {t['critical']};">
                <b style="color:{t['critical']};">⚠️ Invalid URL</b><br>
                <span style="color:{t['muted']};">
                Could not parse "<span class="mono" style="padding:2px 6px;">{raw_input}</span>" as a valid URL.
                Please check the format and try again (e.g. https://example.com).
                </span>
            </div>""",
        unsafe_allow_html=True,
    )


# ==========================================================================
# MAIN APP FLOW
# ==========================================================================
def main():
    t = THEMES[st.session_state.theme_name]
    inject_css(t)

    render_sidebar(t)
    render_header(t)

    analyze_clicked = render_analyzer_input(t)

    if analyze_clicked:
        raw = st.session_state.url_input
        if not raw or not raw.strip():
            st.warning("Please enter a URL to analyze.")
        else:
            result = detect_url(raw)
            if not result["is_valid"]:
                st.session_state.last_result = {"invalid": True, "raw": raw}
            else:
                st.session_state.prev_score = (
                    st.session_state.last_result["score"]
                    if st.session_state.last_result and not st.session_state.last_result.get("invalid")
                    else 0
                )
                st.session_state.last_result = result
                st.session_state.history.insert(
                    0,
                    {
                        "time": datetime.now().strftime("%H:%M:%S"),
                        "url": result["url"],
                        "score": result["score"],
                        "severity": result["severity"],
                        "result": result["result"],
                    },
                )
                st.session_state.history = st.session_state.history[:10]

    st.markdown("---")

    last = st.session_state.last_result
    if last is None:
        st.info("Enter a URL above and click **⚡ Analyze Target** to run a heuristic security scan.")
    elif last.get("invalid"):
        render_invalid(t, last["raw"])
    else:
        render_warning_banner(t, last)
        st.markdown("### 📊 Visual Risk Level")
        gauge_l, gauge_c, gauge_r = st.columns([1, 3, 1])
        with gauge_c:
            render_gauge(t, last["score"], last["severity"], st.session_state.prev_score)
        render_risk_summary(t, last)

        render_risk_scale(t)
        render_risk_factors(t, last)
        render_structure_breakdown(t, last)
        render_feature_table(t, last)
        render_recommendation(t, last)

    render_disclaimer(t)


if __name__ == "__main__":
    main()