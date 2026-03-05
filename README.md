<div align="center">

# 🛡️ ThreatLens

**The Next-Generation AI Security Operations Center Agent**

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg?style=for-the-badge&logo=python)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)](https://streamlit.io/)
[![LangChain](https://img.shields.io/badge/LangChain-1C3C3C?style=for-the-badge&logo=langchain&logoColor=white)](https://langchain.com/)
[![Ollama](https://img.shields.io/badge/Ollama-White?style=for-the-badge&logo=ollama&logoColor=black)](https://ollama.com/)

*Automated Tier-1 Log Triage. Immediate Threat Context. Board-Ready Reporting.*

---

</div>

## 🌟 Overview

**ThreatLens** is an intelligent, privacy-first cybersecurity investigation platform designed to supercharge your Security Operations Center (SOC). 

By seamlessly combining robust deterministic rules engines with the reasoning power of local Large Language Models (LLMs), ThreatLens instantly transforms raw, incomprehensible log files into **actionable security intelligence, correlated incidents, and professional PDF reports**—all running entirely on your local infrastructure.

<br>

## 🚀 Key Capabilities

ThreatLens eliminates alert fatigue and drastically reduces Mean Time to Respond (MTTR):

- 🧠 **Local AI Reasoning**: Powered by `llama3.1:8b-instruct` via Ollama for instant contextual analysis without sending sensitive log data to external cloud APIs.
- 🔗 **Advanced Event Correlation**: Groups related alerts into unified incidents and detects complex multi-stage attack chains (e.g., *Reconnaissance → Intrusion → Privilege Escalation*).
- 🎯 **Automated MITRE ATT&CK Mapping**: Seamlessly translates detected threats into the globally recognized MITRE ATT&CK framework for standardized reporting and mitigation.
- 🌐 **Integrated IP Intelligence**: Automatically triangulates malicious source IPs, fetching deep geolocation and ASN data to identify high-risk hosting providers and origin nations.
- 📊 **Executive Dashboard**: A premium, dark-themed Streamlit interface delivering instant visibility into severity distributions, attack heatmaps, and temporal timelines.
- 📄 **One-Click Reporting**: Instantly exports comprehensive investigation summaries in client-ready **PDF, JSON, or Markdown** formats.

<br>

## 📂 Supported Integrations

ThreatLens effortlessly ingests and parses logs from critical infrastructure:

| Endpoint Type | Supported Logs | Detected Threats |
| :--- | :--- | :--- |
| **Linux Servers** | `auth.log`, `secure`, `syslog` | Brute Force, Pam Failures, Suspicious `sudo`, Account Creation |
| **Windows Servers** | Exported Security Events (4624, 4625, 4672, 4688) | Credential Access, Privilege Escalation, Malicious Process Spawning |
| **Web Applications** | Apache/Nginx Combined Access Logs | SQLi, XSS, Path Traversal, Command Injection, Malicious Scanners |
| **Network Security** | `ufw` Logs | Port Scans, Targeted Drops |

<br>

## ⚡ Quick Start Deployment

Get ThreatLens running in your environment in minutes.

### 1. Clone & Initialize Environment

```bash
git clone https://github.com/your-org/ThreatLens.git
cd ThreatLens

# Create and activate a pristine Python virtual environment
python3 -m venv venv
source venv/bin/activate

# Install core dependencies
pip install -r requirements.txt
```

### 2. Initialize the AI Engine (Ollama)

```bash
# Install the Ollama Daemon
curl -fsSL https://ollama.com/install.sh | sh

# Pull the primary inference model
ollama pull llama3.1:8b
```
*(Note: ThreatLens is highly resilient and will fall back to its deterministic rules engine if Ollama is unavailable.)*

### 3. Launch the Platform

```bash
streamlit run app.py
```
*Navigate to `http://localhost:8501` to begin your investigation.*

<br>

## 🏗️ Architectural Pipeline

ThreatLens operates on a streamlined, modular ingestion and analysis pipeline:

1. **Upload**: Accepts unformatted `.log`, `.txt`, `.csv`, or `.evtx` exports.
2. **Normalize**: Custom parsers (`linux_parser.py`, `windows_parser.py`, `web_parser.py`) extract telemetry using optimized regex.
3. **Classify**: The `threat_classifier.py` engine evaluates severity and detects attack signatures.
4. **Correlate**: Groups temporal and source-based events into unified incidents.
5. **Map**: `mitre_mapper.py` attaches actionable MITRE TTPs.
6. **Enrich**: `ip_enrichment.py` executes out-of-band OSINT lookups via `ipwhois`.
7. **Generate**: The `soc_agent.py` synthesizes the contextual narrative.

<br>

## 🔒 Privacy & Security First

ThreatLens was built for restricted environments. **No log data ever leaves your network.** 
- All LLM inference is performed locally via Ollama.
- The MITRE ATT&CK knowledge base is stored locally in `data/mitre_attack_dataset.json`.
- Event processing limits protect your host machine from resource exhaustion.

---

<div align="center">
  <b>Built for Analysts. Powered by AI.</b><br>
  <i>Empower your security team with ThreatLens today.</i>
</div>
