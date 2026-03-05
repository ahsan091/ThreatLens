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
    /* ── Import Fonts ── */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');

    /* ── Root Variables ── */
    :root {
        --bg-primary: #0a0e17;
        --bg-secondary: #111827;
        --bg-card: #1a1f2e;
        --bg-card-hover: #222838;
        --border-color: #2a3042;
        --border-glow: rgba(99, 102, 241, 0.3);
        --text-primary: #e2e8f0;
        --text-secondary: #94a3b8;
        --text-muted: #64748b;
        --accent-blue: #818cf8;
        --accent-purple: #a78bfa;
        --accent-cyan: #22d3ee;
        --accent-green: #34d399;
        --accent-red: #f87171;
        --accent-orange: #fb923c;
        --accent-yellow: #fbbf24;
        --gradient-primary: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        --gradient-danger: linear-gradient(135deg, #f87171 0%, #ef4444 100%);
        --gradient-success: linear-gradient(135deg, #34d399 0%, #059669 100%);
        --shadow-card: 0 4px 24px rgba(0, 0, 0, 0.3);
        --shadow-glow: 0 0 20px rgba(99, 102, 241, 0.15);
    }

    /* ── Global ── */
    .stApp {
        background: var(--bg-primary) !important;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important;
    }

    .stApp > header { background: transparent !important; }

    /* ── Sidebar ── */
    section[data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0f1523 0%, #111827 100%) !important;
        border-right: 1px solid var(--border-color) !important;
    }
    section[data-testid="stSidebar"] .stMarkdown p,
    section[data-testid="stSidebar"] .stMarkdown li {
        color: var(--text-secondary) !important;
        font-size: 0.9rem !important;
    }

    /* ── Typography ── */
    h1 { color: var(--text-primary) !important; font-weight: 800 !important; letter-spacing: -0.02em !important; }
    h2 { color: var(--text-primary) !important; font-weight: 700 !important; }
    h3 { color: var(--accent-blue) !important; font-weight: 600 !important; }
    p, li, span { color: var(--text-secondary) !important; }

    /* ── Metric Cards ── */
    div[data-testid="stMetric"] {
        background: var(--bg-card) !important;
        border: 1px solid var(--border-color) !important;
        border-radius: 12px !important;
        padding: 16px 20px !important;
        box-shadow: var(--shadow-card) !important;
        transition: all 0.3s ease !important;
    }
    div[data-testid="stMetric"]:hover {
        border-color: var(--border-glow) !important;
        box-shadow: var(--shadow-glow) !important;
        transform: translateY(-2px) !important;
    }
    div[data-testid="stMetric"] label {
        color: var(--text-muted) !important;
        font-size: 0.85rem !important;
        text-transform: uppercase !important;
        letter-spacing: 0.05em !important;
    }
    div[data-testid="stMetric"] div[data-testid="stMetricValue"] {
        color: var(--text-primary) !important;
        font-weight: 700 !important;
        font-size: 1.8rem !important;
    }

    /* ── Data Tables ── */
    .stDataFrame {
        border: 1px solid var(--border-color) !important;
        border-radius: 12px !important;
        overflow: hidden !important;
    }
    .stDataFrame thead th {
        background: var(--bg-card) !important;
        color: var(--accent-blue) !important;
        font-weight: 600 !important;
        text-transform: uppercase !important;
        font-size: 0.8rem !important;
        letter-spacing: 0.05em !important;
    }
    .stDataFrame tbody td {
        color: var(--text-secondary) !important;
        border-color: var(--border-color) !important;
    }

    /* ── Buttons ── */
    .stDownloadButton > button, .stButton > button {
        background: var(--gradient-primary) !important;
        color: white !important;
        border: none !important;
        border-radius: 8px !important;
        font-weight: 600 !important;
        padding: 0.5rem 1.5rem !important;
        transition: all 0.3s ease !important;
        box-shadow: 0 2px 12px rgba(102, 126, 234, 0.3) !important;
    }
    .stDownloadButton > button:hover, .stButton > button:hover {
        transform: translateY(-2px) !important;
        box-shadow: 0 4px 20px rgba(102, 126, 234, 0.5) !important;
    }

    /* ── Expander ── */
    .streamlit-expanderHeader {
        background: var(--bg-card) !important;
        border: 1px solid var(--border-color) !important;
        border-radius: 8px !important;
        color: var(--text-primary) !important;
        font-weight: 600 !important;
    }
    .streamlit-expanderContent {
        background: var(--bg-card) !important;
        border: 1px solid var(--border-color) !important;
        border-top: none !important;
    }

    /* ── File Uploader ── */
    .stFileUploader > div {
        border: 2px dashed var(--border-color) !important;
        border-radius: 12px !important;
        background: var(--bg-card) !important;
        transition: all 0.3s ease !important;
    }
    .stFileUploader > div:hover {
        border-color: var(--accent-blue) !important;
        background: var(--bg-card-hover) !important;
    }

    /* ── Select Box ── */
    .stSelectbox > div > div {
        background: var(--bg-card) !important;
        border-color: var(--border-color) !important;
        border-radius: 8px !important;
        color: var(--text-primary) !important;
    }

    /* ── Tabs ── */
    .stTabs > div > div > div > button {
        color: var(--text-muted) !important;
        font-weight: 500 !important;
        border-bottom: 2px solid transparent !important;
        transition: all 0.3s ease !important;
    }
    .stTabs > div > div > div > button[aria-selected="true"] {
        color: var(--accent-blue) !important;
        border-bottom-color: var(--accent-blue) !important;
    }

    /* ── Custom Badge Styles ── */
    .severity-badge {
        display: inline-block;
        padding: 2px 10px;
        border-radius: 12px;
        font-size: 0.75rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    .sev-critical { background: rgba(248,113,113,0.2); color: #f87171; border: 1px solid rgba(248,113,113,0.3); }
    .sev-high { background: rgba(251,146,60,0.2); color: #fb923c; border: 1px solid rgba(251,146,60,0.3); }
    .sev-medium { background: rgba(251,191,36,0.2); color: #fbbf24; border: 1px solid rgba(251,191,36,0.3); }
    .sev-low { background: rgba(52,211,153,0.2); color: #34d399; border: 1px solid rgba(52,211,153,0.3); }

    /* ── Status Card ── */
    .status-card {
        background: var(--bg-card);
        border: 1px solid var(--border-color);
        border-radius: 12px;
        padding: 16px;
        margin: 8px 0;
    }
    .status-connected { border-left: 4px solid #34d399; }
    .status-disconnected { border-left: 4px solid #f87171; }

    /* ── Hero Header ── */
    .hero-header {
        background: linear-gradient(135deg, rgba(99,102,241,0.1) 0%, rgba(167,139,250,0.1) 100%);
        border: 1px solid var(--border-color);
        border-radius: 16px;
        padding: 24px 32px;
        margin-bottom: 24px;
        text-align: center;
    }
    .hero-header h1 {
        background: linear-gradient(135deg, #818cf8, #a78bfa, #22d3ee);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        font-size: 2.2rem !important;
        margin-bottom: 4px !important;
    }
    .hero-subtitle {
        color: var(--text-muted) !important;
        font-size: 1rem;
        font-weight: 400;
    }

    /* ── Scrollbar ── */
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: var(--bg-primary); }
    ::-webkit-scrollbar-thumb { background: var(--border-color); border-radius: 3px; }
    ::-webkit-scrollbar-thumb:hover { background: var(--accent-blue); }

    /* ── Hide Streamlit Defaults ── */
    #MainMenu { visibility: hidden; }
    footer { visibility: hidden; }
    .stDeployButton { display: none; }
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

with st.sidebar:
    st.markdown("""
    <div style="text-align:center; padding: 12px 0 8px 0;">
        <span style="font-size: 2.5rem;">🛡️</span>
        <h2 style="margin-top: 4px; background: linear-gradient(135deg, #818cf8, #a78bfa); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; font-size: 1.4rem;">
            ThreatLens
        </h2>
        <p style="color: #64748b !important; font-size: 0.8rem; margin-top: -8px;">AI SOC Analyst Agent</p>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")

    # LLM Status
    st.markdown("##### 🤖 LLM Status")
    ollama_status = check_ollama_status(MODEL_NAME)

    if ollama_status['ollama_running'] and ollama_status['model_available']:
        status_class = "status-connected"
        status_icon = "✅"
    else:
        status_class = "status-disconnected"
        status_icon = "❌"

    st.markdown(f"""
    <div class="status-card {status_class}">
        <div style="color: #e2e8f0; font-size: 0.85rem; font-weight: 600;">
            {status_icon} {ollama_status['status_message']}
        </div>
        <div style="color: #64748b; font-size: 0.75rem; margin-top: 4px;">
            Engine: Ollama &nbsp;|&nbsp; Model: {MODEL_NAME}
        </div>
    </div>
    """, unsafe_allow_html=True)

    if not ollama_status['model_available'] and ollama_status['ollama_running']:
        if st.button("📥 Pull Model", key="pull_model"):
            with st.spinner(f"Pulling {MODEL_NAME}..."):
                from agent.soc_agent import pull_model
                success = pull_model(MODEL_NAME)
                if success:
                    st.success("Model pulled successfully!")
                    st.rerun()
                else:
                    st.error("Failed to pull model.")

    st.markdown("---")

    # Log Upload
    st.markdown("##### 📂 Log Upload")

    log_type = st.selectbox(
        "Log Type",
        options=['auto', 'linux_auth', 'linux_syslog', 'firewall', 'windows', 'web'],
        format_func=lambda x: {
            'auto': '🔍 Auto-Detect',
            'linux_auth': '🐧 Linux Auth Log',
            'linux_syslog': '🐧 Linux Syslog',
            'firewall': '🔥 Firewall Log',
            'windows': '🪟 Windows Event Log',
            'web': '🌐 Web Server Log',
        }.get(x, x),
    )

    uploaded_file = st.file_uploader(
        "Upload log file",
        type=['log', 'txt', 'evtx', 'csv'],
        help="Supports Linux auth/syslog, Windows event logs, Apache/Nginx access logs, firewall logs"
    )

    # IP Intelligence toggle
    st.markdown("---")
    st.markdown("##### ⚙️ Settings")
    enable_ip_intel = st.checkbox("🌐 Enable IP Intelligence", value=False,
                                  help="Look up geolocation and ASN for source IPs using ipwhois")
    enable_ai = st.checkbox("🤖 Enable AI Analysis", value=True,
                            help="Use Ollama LLM for enhanced investigation narrative")

    # Event limit indicator
    st.markdown(f"""
    <div style="background: rgba(99,102,241,0.1); border: 1px solid rgba(99,102,241,0.2);
                border-radius: 8px; padding: 10px; margin-top: 12px;">
        <div style="color: #818cf8; font-size: 0.8rem; font-weight: 600;">📊 Event Limit</div>
        <div style="color: #94a3b8; font-size: 0.75rem;">Max {MAX_EVENTS:,} events per upload</div>
    </div>
    """, unsafe_allow_html=True)

# ─── Main Content ─────────────────────────────────────────────────────

# Hero Header
st.markdown("""
<div class="hero-header">
    <h1>🛡️ ThreatLens</h1>
    <p class="hero-subtitle">AI-Powered Security Operations Center Analyst</p>
</div>
""", unsafe_allow_html=True)

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

    # Supported log types
    st.markdown("---")
    st.markdown("### 📋 Supported Log Types")

    sup_col1, sup_col2, sup_col3 = st.columns(3)

    with sup_col1:
        st.markdown("""
        <div class="status-card" style="border-left: 4px solid #818cf8;">
            <h4 style="color: #818cf8 !important;">🐧 Linux</h4>
            <ul style="color: #94a3b8 !important; font-size: 0.85rem;">
                <li>auth.log / secure</li>
                <li>syslog / messages</li>
                <li>UFW firewall logs</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

    with sup_col2:
        st.markdown("""
        <div class="status-card" style="border-left: 4px solid #a78bfa;">
            <h4 style="color: #a78bfa !important;">🪟 Windows</h4>
            <ul style="color: #94a3b8 !important; font-size: 0.85rem;">
                <li>Event ID 4624/4625</li>
                <li>Event ID 4672/4688</li>
                <li>Exported Event Logs</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

    with sup_col3:
        st.markdown("""
        <div class="status-card" style="border-left: 4px solid #22d3ee;">
            <h4 style="color: #22d3ee !important;">🌐 Web</h4>
            <ul style="color: #94a3b8 !important; font-size: 0.85rem;">
                <li>Apache access logs</li>
                <li>Nginx access logs</li>
                <li>Combined log format</li>
            </ul>
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
