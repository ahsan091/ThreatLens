# 🛡️ ThreatLens — AI SOC Analyst Agent

**Intelligent Security Log Investigation System**

An AI-powered cybersecurity investigation tool that automates Tier-1 SOC analysis. Upload security logs, detect threats, map to MITRE ATT&CK, and generate professional incident reports — all powered by local AI.

---

## ⚡ Quick Start

### 1. Install Dependencies

```bash
cd ThreatLens
pip install -r requirements.txt
```

### 2. Install Ollama (for AI-enhanced analysis)

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull the model
ollama pull llama3.1:8b-instruct
```

> **Note:** The system works fully without Ollama using rule-based analysis. Ollama adds an AI reasoning narrative to reports.

### 3. Run the Application

```bash
streamlit run app.py
```

Open [http://localhost:8501](http://localhost:8501) in your browser.

---

## 📂 Supported Log Types

| Log Type | Source | Events Detected |
|----------|--------|----------------|
| **Linux Auth** | `auth.log`, `secure` | SSH brute force, failed logins, sudo abuse, account creation |
| **Linux Syslog** | `syslog`, `messages` | Service failures, suspicious cron jobs, OOM kills |
| **Firewall** | `ufw.log` | Port scans, blocked connections |
| **Windows** | Exported Event Logs | Event IDs 4624/4625/4672/4688 |
| **Web Server** | Apache/Nginx access logs | SQL injection, XSS, path traversal, web shells |

---

## 🏗️ Architecture

```
Log Upload → Log Parser → Event Normalization → Threat Classifier
    → Event Correlation → IP Intelligence → MITRE ATT&CK Mapping
    → AI SOC Agent (Llama 3.1) → Incident Report Generator
    → Streamlit Dashboard
```

---

## 📁 Project Structure

```
ThreatLens/
├── app.py                          # Streamlit web interface
├── requirements.txt                # Python dependencies
├── agent/
│   ├── soc_agent.py                # AI SOC agent (Ollama/LangChain)
│   ├── threat_classifier.py        # Rule-based classifier + event correlation
│   ├── ip_enrichment.py            # IP geolocation via ipwhois
│   └── tools.py                    # LangChain agent tools
├── parsers/
│   ├── __init__.py                 # Auto-detection + routing
│   ├── linux_parser.py             # Linux auth/syslog/firewall parser
│   ├── windows_parser.py           # Windows event log parser
│   ├── web_parser.py               # Apache/Nginx log parser
│   └── normalizer.py               # Unified event format
├── mitre/
│   └── mitre_mapper.py             # MITRE ATT&CK technique mapping
├── reports/
│   └── report_generator.py         # PDF/JSON/Markdown reports
├── data/
│   └── mitre_attack_dataset.json   # MITRE ATT&CK knowledge base
├── logs/sample_logs/               # Sample logs for testing
│   ├── linux_auth.log
│   ├── linux_syslog.log
│   ├── windows_security.log
│   ├── apache_access.log
│   └── firewall.log
└── tests/                          # Automated test suite
    ├── test_linux_parser.py
    ├── test_windows_parser.py
    ├── test_web_parser.py
    ├── test_threat_classifier.py
    ├── test_mitre_mapper.py
    └── test_report_generator.py
```

---

## 🧪 Running Tests

```bash
python -m pytest tests/ -v
```

---

## ✨ Key Features

- **AI-Enhanced, Not AI-Dependent** — Full rule-based detection works without Ollama
- **Event Correlation** — Groups related events into incidents (e.g., 20 failed SSH → 1 brute force incident)
- **Multi-Stage Attack Detection** — Identifies attack chains (brute force → login → privilege escalation)
- **IP Intelligence** — Geolocation and ASN enrichment via ipwhois
- **MITRE ATT&CK Mapping** — Maps all detections to framework techniques
- **Export Reports** — PDF, JSON, and Markdown formats
- **5,000 Event Limit** — Protects against processing overload
- **60s LLM Timeout** — Prevents UI freezes

---

## 🛠️ Technology Stack

| Component | Technology |
|-----------|-----------|
| Language | Python |
| AI Agent | LangChain + Ollama |
| AI Model | Llama 3.1 (8B Instruct) |
| Web UI | Streamlit |
| Log Parsing | Python Regex |
| PDF Export | fpdf2 |
| IP Intelligence | ipwhois |

---

*Built with ❤️ by ThreatLens — AI SOC Analyst Agent*
