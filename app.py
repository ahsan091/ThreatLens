"""
AI SOC Analyst Agent — Streamlit Web Interface
Premium dark-themed security investigation dashboard.
"""

import sys
import os
import json
import streamlit as st
import pandas as pd
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from parsers import parse_log_file, detect_log_type
from agent.threat_classifier import ThreatClassifier
from agent.ip_enrichment import IPEnrichment
from agent.soc_agent import SOCAgent, check_ollama_status
from mitre.mitre_mapper import MITREMapper
from reports.report_generator import ReportGenerator

# ─── Constants ────────────────────────────────────────────────────────

MAX_EVENTS = 5000
MODEL_NAME = "llama3.1:8b-instruct"

# ─── Page Configuration ──────────────────────────────────────────────

st.set_page_config(
    page_title="ThreatLens — AI SOC Analyst Agent",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── Custom CSS for Premium Dark Theme ────────────────────────────────

st.markdown("""
<style>
    /* ── Modern Font (Next.js style) ── */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');

    /* ── Root Variables ── */
    :root {
        --bg-main: #000000;
        --bg-card: rgba(18, 18, 18, 0.6);
        --bg-sidebar: #050505;
        --border-color: rgba(255, 255, 255, 0.1);
        --border-hover: rgba(255, 255, 255, 0.2);
        --text-primary: #ededed;
        --text-secondary: #a1a1aa;
        --accent: #ededed;
        --accent-glow: rgba(255, 255, 255, 0.1);
    }

    /* ── Global App Canvas ── */
    .stApp {
        background: var(--bg-main) !important;
        background-image: 
            radial-gradient(circle at 15% 15%, rgba(255,255,255, 0.03) 0%, transparent 20%),
            radial-gradient(circle at 85% 85%, rgba(255,255,255, 0.03) 0%, transparent 20%) !important;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important;
        overflow: hidden !important;
    }

    /* Prevent main body scroll, handle overflow in containers */
    .main .block-container {
        max-height: 100vh;
        overflow-y: auto;
        padding-top: 2rem !important;
        padding-bottom: 2rem !important;
    }

    .stApp > header { background: transparent !important; }

    /* ── Sidebar ── */
    section[data-testid="stSidebar"] {
        background: var(--bg-sidebar) !important;
        border-right: 1px solid var(--border-color) !important;
    }
    section[data-testid="stSidebar"] .stMarkdown p,
    section[data-testid="stSidebar"] .stMarkdown li {
        color: var(--text-secondary) !important;
        font-size: 0.9rem !important;
        font-weight: 400 !important;
    }

    /* ── Typography (Tight tracking like Vercel) ── */
    h1 { color: var(--text-primary) !important; font-weight: 800 !important; letter-spacing: -0.04em !important; }
    h2 { color: var(--text-primary) !important; font-weight: 700 !important; letter-spacing: -0.03em !important; }
    h3 { color: var(--text-primary) !important; font-weight: 600 !important; letter-spacing: -0.02em !important;}
    p, li, span { color: var(--text-secondary) !important; letter-spacing: -0.01em !important; }
    strong { color: var(--text-primary) !important; font-weight: 600 !important; }

    /* ── Metric Cards ── */
    div[data-testid="stMetric"] {
        background: var(--bg-card) !important;
        border: 1px solid var(--border-color) !important;
        border-radius: 12px !important;
        padding: 24px !important;
        backdrop-filter: blur(16px) !important;
        -webkit-backdrop-filter: blur(16px) !important;
        transition: transform 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease !important;
    }
    div[data-testid="stMetric"]:hover {
        border-color: var(--border-hover) !important;
        box-shadow: 0 10px 30px -10px rgba(0, 0, 0, 0.5), 0 0 20px var(--accent-glow) !important;
        transform: translateY(-2px) !important;
    }
    div[data-testid="stMetric"] label {
        color: var(--text-secondary) !important;
        font-size: 0.85rem !important;
        font-weight: 500 !important;
        letter-spacing: 0.02em !important;
        text-transform: uppercase !important;
    }
    div[data-testid="stMetric"] div[data-testid="stMetricValue"] {
        color: var(--text-primary) !important;
        font-weight: 800 !important;
        font-size: 2.2rem !important;
        letter-spacing: -0.03em !important;
    }

    /* ── Data Tables ── */
    .stDataFrame {
        border: 1px solid var(--border-color) !important;
        border-radius: 12px !important;
        overflow: hidden !important;
    }
    .stDataFrame thead th {
        background: rgba(10,10,10,0.95) !important;
        color: var(--text-primary) !important;
        font-weight: 600 !important;
        font-size: 0.85rem !important;
        letter-spacing: 0.02em !important;
        border-bottom: 1px solid var(--border-color) !important;
    }
    .stDataFrame tbody td {
        color: var(--text-secondary) !important;
        border-color: rgba(255,255,255,0.05) !important;
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 0.85rem !important;
    }
    .stDataFrame table {
        background-color: transparent !important;
    }

    /* ── Buttons (Vercel Style: High Contrast) ── */
    .stDownloadButton > button, .stButton > button {
        background: #ffffff !important;
        color: #000000 !important;
        border: 1px solid transparent !important;
        border-radius: 6px !important;
        font-weight: 600 !important;
        font-size: 0.9rem !important;
        padding: 0.5rem 1.5rem !important;
        transition: all 0.2s ease !important;
        box-shadow: 0 0 15px rgba(255,255,255,0.1) !important;
    }
    .stDownloadButton > button:hover, .stButton > button:hover {
        background: #e5e5e5 !important;
        transform: scale(1.02) !important;
        box-shadow: 0 0 20px rgba(255,255,255,0.2) !important;
    }
    .stDownloadButton > button *, .stButton > button * {
        color: #000000 !important;
    }

    /* ── Expander ── */
    .streamlit-expanderHeader {
        background: var(--bg-card) !important;
        border: 1px solid var(--border-color) !important;
        border-radius: 12px !important;
        color: var(--text-primary) !important;
        font-weight: 600 !important;
        transition: border-color 0.2s ease !important;
        padding: 1rem !important;
    }
    .streamlit-expanderHeader:hover {
        border-color: var(--border-hover) !important;
        background: rgba(30, 30, 30, 0.6) !important;
    }
    .streamlit-expanderContent {
        background: rgba(10,10,10,0.5) !important;
        border: 1px solid var(--border-color) !important;
        border-top: none !important;
        border-bottom-left-radius: 12px !important;
        border-bottom-right-radius: 12px !important;
    }

    /* ── File Uploader ── */
    .stFileUploader > div {
        border: 1px dashed rgba(255,255,255,0.2) !important;
        border-radius: 16px !important;
        background: rgba(15,15,15,0.4) !important;
        padding: 24px !important;
        transition: all 0.3s ease !important;
        backdrop-filter: blur(10px) !important;
    }
    .stFileUploader > div:hover {
        border-color: rgba(255,255,255,0.6) !important;
        background: rgba(25,25,25,0.6) !important;
    }
    .stFileUploader small { color: var(--text-secondary) !important; }
    .stFileUploader span { color: var(--text-primary) !important; font-weight: 500 !important; }

    /* ── Select Box & Inputs ── */
    .stSelectbox > div > div, .stCheckbox > div {
        background: rgba(20,20,20,0.8) !important;
        border-color: var(--border-color) !important;
        border-radius: 8px !important;
        color: var(--text-primary) !important;
        transition: border-color 0.2s ease;
    }
    .stSelectbox > div > div:hover {
        border-color: rgba(255,255,255,0.4) !important;
    }

    /* ── Tabs (Sleek Minimalist) ── */
    .stTabs [data-baseweb="tab-list"] {
        gap: 32px;
        background-color: transparent !important;
    }
    .stTabs [data-baseweb="tab"] {
        background-color: transparent !important;
        border: none !important;
        border-bottom: 2px solid transparent !important;
        padding-bottom: 8px !important;
        padding-top: 8px !important;
        color: rgba(255,255,255,0.5) !important;
        font-weight: 500 !important;
        font-size: 0.95rem !important;
        transition: color 0.2s ease, border-color 0.2s ease !important;
    }
    .stTabs [aria-selected="true"] {
        color: #ffffff !important;
        border-bottom-color: #ffffff !important;
    }

    /* ── Status Card Custom Render ── */
    .status-card {
        background: var(--bg-card);
        border: 1px solid var(--border-color);
        border-radius: 16px;
        padding: 24px;
        margin: 12px 0;
        backdrop-filter: blur(16px);
        -webkit-backdrop-filter: blur(16px);
        transition: all 0.2s ease;
    }
    .status-card:hover {
        border-color: rgba(255,255,255,0.3);
        background: rgba(25, 25, 25, 0.8);
        transform: translateY(-2px);
    }
    .status-connected { border-left: 3px solid #ededed; }
    .status-disconnected { border-left: 3px solid #ef4444; }

    /* ── Hero Header (Glassmorphic & Sleek) ── */
    .hero-header {
        background: radial-gradient(100% 100% at 50% 0%, rgba(255,255,255,0.08) 0%, rgba(0,0,0,0) 100%);
        border: 1px solid var(--border-color);
        border-radius: 24px;
        padding: 40px 32px;
        margin-bottom: 20px;
        text-align: center;
        position: relative;
        overflow: hidden;
        backdrop-filter: blur(20px);
    }
    .hero-header::before {
        content: '';
        position: absolute; top: 0; left: 15%; right: 15%; height: 1px;
        background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
    }
    .hero-header h1 {
        background: linear-gradient(to bottom right, #ffffff, #888888);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        font-size: 3rem !important;
        font-weight: 800 !important;
        letter-spacing: -0.05em !important;
        margin-bottom: 8px !important;
    }
    .hero-subtitle {
        color: var(--text-secondary) !important;
        font-size: 1.05rem;
        font-weight: 400;
        letter-spacing: -0.01em;
        max-width: 600px;
        margin: 0 auto;
    }

    /* ── Custom Badge Styles ── */
    .severity-badge {
        display: inline-block;
        padding: 3px 10px;
        border-radius: 8px;
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }

    /* ── Scrollbar ── */
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: var(--bg-main); }
    ::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.1); border-radius: 4px; }
    ::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,0.2); }

    /* ── Hide Streamlit Defaults ── */
    #MainMenu { visibility: hidden; }
    footer { visibility: hidden; }
    header { visibility: hidden; }
    .stAppHeader { display: none; }
    .stDeployButton { display: none; }
    
    /* Hide Header Anchor Links */
    .stMarkdown h1 a, .stMarkdown h2 a, .stMarkdown h3 a, 
    .stMarkdown h4 a, .stMarkdown h5 a, .stMarkdown h6 a {
        display: none !important;
    }
    a.st-anchor-link { display: none !important; }
</style>
""", unsafe_allow_html=True)

# ─── Cache ────────────────────────────────────────────────────────────

@st.cache_data
def load_mitre_dataset():
    """Load and cache the MITRE ATT&CK dataset."""
    data_path = os.path.join(os.path.dirname(__file__), 'data', 'mitre_attack_dataset.json')
    with open(data_path, 'r') as f:
        return json.load(f)


# ─── Sidebar ──────────────────────────────────────────────────────────


# ─── Main Content ─────────────────────────────────────────────────────

# Hero Header
st.markdown("""
<div class="hero-header">
    <h1>🛡️ ThreatLens</h1>
    <p class="hero-subtitle">AI-Powered Security Operations Center Analyst</p>
</div>
""", unsafe_allow_html=True)

# ─── Control Panel ───
st.markdown("<h3 style='margin-bottom: 24px; font-size: 1.4rem; color: #ededed; text-align: center;'>📂 Log Ingestion</h3>", unsafe_allow_html=True)

col_spacer1, col_center, col_spacer2 = st.columns([1, 2, 1])

with col_center:
    log_type = st.selectbox(
        "Log Type Decoder",
        options=['auto', 'linux_auth', 'linux_syslog', 'firewall', 'windows', 'web'],
        format_func=lambda x: {
            'auto': '🔍 Auto-Detect Format',
            'linux_auth': '🐧 Linux Auth Log',
            'linux_syslog': '🐧 Linux Syslog',
            'firewall': '🔥 Network Firewall',
            'windows': '🪟 Windows Events',
            'web': '🌐 Web Access Log',
        }.get(x, x),
        label_visibility="collapsed"
    )

    uploaded_file = st.file_uploader(
        "Drop File via Streamlit Upload",
        type=['log', 'txt', 'evtx', 'csv'],
        label_visibility="collapsed"
    )

# Silent configuration for removed UI components
enable_ai = True
enable_ip_intel = False
ollama_status = check_ollama_status(MODEL_NAME)

# ─── Analysis Pipeline ───────────────────────────────────────────────

if uploaded_file is not None:
    # Read file content
    content = uploaded_file.read().decode('utf-8', errors='replace')
    file_name = uploaded_file.name

    # Detect log type
    detected_type = detect_log_type(content)
    actual_type = log_type if log_type != 'auto' else detected_type

    st.markdown(f"""
    <div style="background: var(--bg-card); border: 1px solid var(--border-color);
                border-radius: 12px; padding: 14px 20px; margin-bottom: 20px;">
        <span style="color: #818cf8; font-weight: 600;">📄 {file_name}</span>
        <span style="color: #64748b; margin-left: 16px;">Detected: <span style="color: #34d399; font-weight: 500;">{actual_type}</span></span>
        <span style="color: #64748b; margin-left: 16px;">Lines: <span style="color: #e2e8f0;">{len(content.splitlines()):,}</span></span>
    </div>
    """, unsafe_allow_html=True)

    with st.spinner("🔍 Parsing log file and extracting security events..."):
        # Step 1: Parse logs
        events = parse_log_file(content, log_type=actual_type)

        # Apply event limit
        if len(events) > MAX_EVENTS:
            st.warning(f"⚠️ Log contains {len(events):,} events. Capped at {MAX_EVENTS:,} for processing.")
            events = events[:MAX_EVENTS]

    if not events:
        st.warning("⚠️ No security events detected in the uploaded log file. "
                    "Try selecting a different log type or check the file format.")
        st.stop()

    with st.spinner("🧠 Classifying threats and correlating events..."):
        # Step 2: Classify and correlate
        classifier = ThreatClassifier()
        classification = classifier.classify_events(events)

        classified_events = classification['classified_events']
        incidents = classification['correlated_incidents']
        summary = classification['summary']

    with st.spinner("🎯 Mapping to MITRE ATT&CK framework..."):
        # Step 3: MITRE mapping
        mapper = MITREMapper()
        mitre_result = mapper.map_events(classified_events)

    # Step 4: IP Intelligence (optional)
    ip_intel = {}
    if enable_ip_intel:
        with st.spinner("🌐 Enriching IP intelligence..."):
            enricher = IPEnrichment()
            ip_intel = enricher.enrich_events(classified_events)

    # Step 5: AI Investigation (optional)
    ai_analysis = ""
    if enable_ai and ollama_status['ollama_running'] and ollama_status['model_available']:
        with st.spinner("🤖 AI agent is investigating (this may take a moment)..."):
            agent = SOCAgent()
            if agent.initialize():
                ai_analysis = agent.investigate(
                    classified_events, incidents,
                    mitre_result.get('unique_techniques', []),
                    ip_intel, summary
                )
    if not ai_analysis:
        # Fallback to rule-based
        agent = SOCAgent()
        ai_analysis = agent._rule_based_investigate(
            classified_events, incidents,
            mitre_result.get('unique_techniques', []),
            ip_intel, summary,
            fallback_reason="Using rule-based analysis" if not enable_ai else "Ollama not available — using rule-based analysis"
        )

    # ─── Dashboard ────────────────────────────────────────────────────

    st.markdown("## 📊 Security Dashboard")

    # Metric cards
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("Total Events", f"{summary.get('total_events', 0):,}")
    with col2:
        st.metric("Incidents", f"{summary.get('total_incidents', 0)}")
    with col3:
        critical_count = summary.get('severity_distribution', {}).get('critical', 0)
        st.metric("Critical", f"{critical_count}", delta=None)
    with col4:
        high_count = summary.get('severity_distribution', {}).get('high', 0)
        st.metric("High", f"{high_count}", delta=None)
    with col5:
        st.metric("Source IPs", f"{summary.get('unique_source_ips', 0)}")

    st.markdown("")

    # Charts row
    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:
        st.markdown("### 📈 Severity Distribution")
        sev_dist = summary.get('severity_distribution', {})
        if sev_dist:
            sev_df = pd.DataFrame({
                'Severity': list(sev_dist.keys()),
                'Count': list(sev_dist.values())
            })
            severity_order = ['critical', 'high', 'medium', 'low']
            sev_df['Severity'] = pd.Categorical(sev_df['Severity'], categories=severity_order, ordered=True)
            sev_df = sev_df.sort_values('Severity')
            st.bar_chart(sev_df.set_index('Severity'), color='#818cf8')

    with chart_col2:
        st.markdown("### 🔥 Attack Type Heatmap")
        attack_dist = summary.get('attack_type_distribution', {})
        if attack_dist:
            attack_df = pd.DataFrame({
                'Attack Type': [k.replace('_', ' ').title() for k in attack_dist.keys()],
                'Count': list(attack_dist.values())
            })
            attack_df = attack_df.sort_values('Count', ascending=True)
            st.bar_chart(attack_df.set_index('Attack Type'), color='#f87171', horizontal=True)

    # Event Timeline
    st.markdown("### 📅 Event Timeline")
    try:
        timeline_data = []
        for event in classified_events:
            ts = event.get('timestamp', '')
            if ts:
                try:
                    from dateutil import parser as date_parser
                    dt = date_parser.parse(ts)
                    timeline_data.append({
                        'Hour': dt.strftime('%H:%M'),
                        'Event Type': event.get('event_type', 'unknown'),
                        'Severity': event.get('severity', 'low'),
                    })
                except (ValueError, TypeError):
                    pass

        if timeline_data:
            tl_df = pd.DataFrame(timeline_data)
            hour_counts = tl_df.groupby('Hour').size().reset_index(name='Events')
            st.line_chart(hour_counts.set_index('Hour'), color='#22d3ee')
        else:
            st.info("Timeline data not available.")
    except Exception:
        st.info("Could not generate timeline chart.")

    # ─── Tabs ─────────────────────────────────────────────────────────

    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "📋 Events", "🔗 Incidents", "🌐 IP Intel", "🎯 MITRE", "🤖 AI Analysis", "📄 Reports"
    ])

    # ── Events Tab ──
    with tab1:
        st.markdown("### Security Events")
        st.markdown(f"*Showing {len(classified_events):,} classified events*")

        if classified_events:
            events_for_table = []
            for event in classified_events:
                events_for_table.append({
                    'Timestamp': event.get('timestamp', ''),
                    'Severity': event.get('severity', 'low').upper(),
                    'Event Type': event.get('event_type', '').replace('_', ' ').title(),
                    'Attack Type': event.get('attack_type', '').replace('_', ' ').title(),
                    'Source IP': event.get('source_ip', ''),
                    'User': event.get('user', ''),
                    'Host': event.get('host', ''),
                })

            df = pd.DataFrame(events_for_table)
            st.dataframe(df, use_container_width=True, height=400)

    # ── Incidents Tab ──
    with tab2:
        st.markdown("### Correlated Incidents")

        if incidents:
            severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
            sorted_incidents = sorted(incidents, key=lambda i: severity_order.get(i.get('severity', 'low'), 4))

            for i, inc in enumerate(sorted_incidents, 1):
                sev = inc.get('severity', 'low')
                sev_emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}.get(sev, '⚪')
                is_multi = inc.get('is_multi_stage', False)
                multi_badge = " ⚡ MULTI-STAGE" if is_multi else ""

                with st.expander(f"{sev_emoji} Incident {i}: {inc.get('incident_type', 'Unknown').replace('_', ' ').title()} "
                                 f"— {inc.get('event_count', 0)} events [{sev.upper()}]{multi_badge}"):
                    col_a, col_b, col_c = st.columns(3)
                    with col_a:
                        st.markdown(f"**Source IP:** `{inc.get('source_ip', 'N/A')}`")
                    with col_b:
                        st.markdown(f"**First Seen:** {inc.get('first_seen', 'N/A')}")
                    with col_c:
                        st.markdown(f"**Last Seen:** {inc.get('last_seen', 'N/A')}")

                    st.markdown(f"**Description:** {inc.get('description', '')}")

                    if inc.get('affected_users'):
                        st.markdown(f"**Affected Users:** {', '.join(inc['affected_users'])}")

                    if is_multi:
                        st.warning(f"⚡ Multi-stage attack pattern: **{inc.get('pattern_name', 'Unknown')}**")
        else:
            st.info("No correlated incidents found.")

    # ── IP Intelligence Tab ──
    with tab3:
        st.markdown("### IP Intelligence")

        if ip_intel:
            ip_data = []
            for ip, info in ip_intel.items():
                ip_data.append({
                    'IP Address': ip,
                    'Country': info.get('country', 'Unknown'),
                    'ASN': info.get('asn', 'Unknown'),
                    'Organization': info.get('org', 'Unknown'),
                    'Private': '✅' if info.get('is_private') else '❌',
                    'Risk Note': info.get('risk_note', ''),
                })

            ip_df = pd.DataFrame(ip_data)
            st.dataframe(ip_df, use_container_width=True)
        else:
            if not enable_ip_intel:
                st.info("Enable IP Intelligence in the sidebar to enrich source IPs with geolocation and ASN data.")
            else:
                st.info("No IP intelligence data available.")

    # ── MITRE Tab ──
    with tab4:
        st.markdown("### MITRE ATT&CK Mapping")

        technique_summary = mitre_result.get('technique_summary', [])
        if technique_summary:
            mitre_data = []
            for tech in technique_summary:
                mitre_data.append({
                    'Technique ID': tech['technique_id'],
                    'Name': tech['name'],
                    'Tactic': tech['tactic'],
                    'Events': tech['count'],
                })

            mitre_df = pd.DataFrame(mitre_data)
            st.dataframe(mitre_df, use_container_width=True)

            # Remediation recommendations
            st.markdown("#### 🛠️ Recommended Remediations")
            seen = set()
            for tech in technique_summary:
                for rem in tech.get('remediation', []):
                    if rem not in seen:
                        seen.add(rem)
                        st.markdown(f"- {rem}")
        else:
            st.info("No MITRE ATT&CK mappings found.")

    # ── AI Analysis Tab ──
    with tab5:
        st.markdown("### AI Investigation Analysis")

        if ai_analysis:
            st.markdown(ai_analysis)
        else:
            st.info("AI analysis not available.")

    # ── Reports Tab ──
    with tab6:
        st.markdown("### Export Reports")

        analysis_data = {
            'classified_events': classified_events,
            'correlated_incidents': incidents,
            'summary': summary,
            'mitre_mappings': mitre_result,
            'ip_intel': ip_intel,
            'ai_analysis': ai_analysis,
            'log_filename': file_name,
        }

        report_gen = ReportGenerator()

        col_r1, col_r2, col_r3 = st.columns(3)

        with col_r1:
            st.markdown("#### 📝 Markdown")
            md_report = report_gen.generate_markdown(analysis_data)
            st.download_button(
                label="⬇️ Download Markdown",
                data=md_report,
                file_name=f"soc_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                mime="text/markdown",
            )

        with col_r2:
            st.markdown("#### 📊 JSON")
            json_report = report_gen.generate_json(analysis_data)
            st.download_button(
                label="⬇️ Download JSON",
                data=json_report,
                file_name=f"soc_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
            )

        with col_r3:
            st.markdown("#### 📑 PDF")
            pdf_bytes = report_gen.generate_pdf(analysis_data)
            if pdf_bytes:
                st.download_button(
                    label="⬇️ Download PDF",
                    data=pdf_bytes,
                    file_name=f"soc_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                    mime="application/pdf",
                )
            else:
                st.warning("PDF generation requires fpdf2: `pip install fpdf2`")

        # Preview Markdown report
        with st.expander("📖 Preview Markdown Report"):
            st.markdown(md_report)

else:
    # Landing page when no file is uploaded
    st.markdown("""
    <div style="text-align: center; padding: 40px 20px;">
        <div style="font-size: 4rem; margin-bottom: 16px;">📂</div>
        <h2 style="color: #e2e8f0 !important; margin-bottom: 8px;">Upload a Log File to Begin Investigation</h2>
        <p style="color: #64748b !important; font-size: 1.1rem; max-width: 600px; margin: 0 auto;">
            Upload security logs from Linux, Windows, or web servers. The AI SOC Agent will automatically
            parse events, classify threats, map to MITRE ATT&CK, and generate investigation reports.
        </p>
    </div>
    """, unsafe_allow_html=True)

    # Pipeline visualization
    st.markdown("---")
    st.markdown("### ⚙️ Investigation Pipeline")
    st.markdown("""
    <div style="display: flex; justify-content: center; gap: 8px; flex-wrap: wrap; padding: 20px 0;">
        <div class="status-card" style="text-align: center; min-width: 120px; flex: 1;">
            <div style="font-size: 1.5rem;">📤</div>
            <div style="color: #e2e8f0; font-size: 0.8rem; font-weight: 600;">Upload</div>
        </div>
        <div style="color: #64748b; display: flex; align-items: center; font-size: 1.2rem;">→</div>
        <div class="status-card" style="text-align: center; min-width: 120px; flex: 1;">
            <div style="font-size: 1.5rem;">🔍</div>
            <div style="color: #e2e8f0; font-size: 0.8rem; font-weight: 600;">Parse</div>
        </div>
        <div style="color: #64748b; display: flex; align-items: center; font-size: 1.2rem;">→</div>
        <div class="status-card" style="text-align: center; min-width: 120px; flex: 1;">
            <div style="font-size: 1.5rem;">⚡</div>
            <div style="color: #e2e8f0; font-size: 0.8rem; font-weight: 600;">Classify</div>
        </div>
        <div style="color: #64748b; display: flex; align-items: center; font-size: 1.2rem;">→</div>
        <div class="status-card" style="text-align: center; min-width: 120px; flex: 1;">
            <div style="font-size: 1.5rem;">🔗</div>
            <div style="color: #e2e8f0; font-size: 0.8rem; font-weight: 600;">Correlate</div>
        </div>
        <div style="color: #64748b; display: flex; align-items: center; font-size: 1.2rem;">→</div>
        <div class="status-card" style="text-align: center; min-width: 120px; flex: 1;">
            <div style="font-size: 1.5rem;">🎯</div>
            <div style="color: #e2e8f0; font-size: 0.8rem; font-weight: 600;">MITRE</div>
        </div>
        <div style="color: #64748b; display: flex; align-items: center; font-size: 1.2rem;">→</div>
        <div class="status-card" style="text-align: center; min-width: 120px; flex: 1;">
            <div style="font-size: 1.5rem;">🤖</div>
            <div style="color: #e2e8f0; font-size: 0.8rem; font-weight: 600;">AI Agent</div>
        </div>
        <div style="color: #64748b; display: flex; align-items: center; font-size: 1.2rem;">→</div>
        <div class="status-card" style="text-align: center; min-width: 120px; flex: 1;">
            <div style="font-size: 1.5rem;">📄</div>
            <div style="color: #e2e8f0; font-size: 0.8rem; font-weight: 600;">Report</div>
        </div>
    </div>
    """, unsafe_allow_html=True)
