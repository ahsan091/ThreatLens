"""
AI SOC Investigation Agent
LangChain-based agent using Ollama (llama3.1:8b-instruct) for local AI reasoning.
Falls back to rule-based analysis if Ollama is unavailable.
"""

import json
import subprocess


def check_ollama_status(model: str = "llama3.1:8b-instruct") -> dict:
    """
    Check if Ollama is running and the specified model is available.
    
    Returns:
        {
            'ollama_running': bool,
            'model_available': bool,
            'model_name': str,
            'status_message': str
        }
    """
    result = {
        'ollama_running': False,
        'model_available': False,
        'model_name': model,
        'status_message': 'Checking...',
    }

    try:
        # Check if Ollama is running
        proc = subprocess.run(
            ['ollama', 'list'],
            capture_output=True, text=True, timeout=10
        )
        if proc.returncode == 0:
            result['ollama_running'] = True
            # Check if model is available
            if model.split(':')[0] in proc.stdout:
                result['model_available'] = True
                result['status_message'] = f'✅ Connected — {model}'
            else:
                result['status_message'] = f'⚠️ Model {model} not found — will attempt to pull'
        else:
            result['status_message'] = '❌ Ollama not responding'
    except FileNotFoundError:
        result['status_message'] = '❌ Ollama not installed'
    except subprocess.TimeoutExpired:
        result['status_message'] = '❌ Ollama timeout'
    except Exception as e:
        result['status_message'] = f'❌ Error: {str(e)[:80]}'

    return result


def pull_model(model: str = "llama3.1:8b-instruct") -> bool:
    """Attempt to pull the specified model via Ollama."""
    try:
        proc = subprocess.run(
            ['ollama', 'pull', model],
            capture_output=True, text=True, timeout=600
        )
        return proc.returncode == 0
    except Exception:
        return False


class SOCAgent:
    """
    AI SOC Investigation Agent.
    Uses LangChain + Ollama for AI-enhanced analysis.
    Falls back to rule-based analysis if AI is unavailable.
    """

    MODEL = "llama3.1:8b-instruct"
    BASE_URL = "http://localhost:11434"
    TEMPERATURE = 0.2
    TIMEOUT = 60

    SOC_SYSTEM_PROMPT = """You are an expert Tier-1 SOC (Security Operations Center) Analyst.
You are analyzing security events extracted from system logs.

Your task is to:
1. Analyze the provided security events and identified incidents
2. Determine the most likely attack scenario
3. Assess the potential impact on the organization
4. Provide specific, actionable remediation recommendations
5. Identify any attack chains or multi-stage attacks

Be concise but thorough. Use professional SOC terminology.
Structure your response with clear sections:
- EXECUTIVE SUMMARY (2-3 sentences)
- ATTACK ANALYSIS (key findings)
- RISK ASSESSMENT (impact and likelihood)
- RECOMMENDED ACTIONS (numbered list, prioritized)
- ADDITIONAL OBSERVATIONS (anything noteworthy)
"""

    def __init__(self):
        self._llm = None
        self._available = False

    def initialize(self) -> bool:
        """Initialize the LLM connection. Returns True if successful."""
        try:
            from langchain_community.chat_models import ChatOllama
            self._llm = ChatOllama(
                model=self.MODEL,
                base_url=self.BASE_URL,
                temperature=self.TEMPERATURE,
                timeout=self.TIMEOUT,
            )
            self._available = True
            return True
        except ImportError:
            self._available = False
            return False
        except Exception:
            self._available = False
            return False

    @property
    def is_available(self) -> bool:
        return self._available

    def investigate(self, classified_events: list, incidents: list,
                    mitre_mappings: list, ip_intel: dict, summary: dict) -> str:
        """
        Run the AI investigation on the classified events and return analysis.
        Falls back to rule-based analysis if AI is unavailable.
        """
        # Build context for the AI
        context = self._build_context(classified_events, incidents, mitre_mappings, ip_intel, summary)

        if self._available and self._llm:
            try:
                return self._ai_investigate(context)
            except Exception as e:
                return self._rule_based_investigate(
                    classified_events, incidents, mitre_mappings, ip_intel, summary,
                    fallback_reason=f"AI analysis failed: {str(e)[:100]}"
                )
        else:
            return self._rule_based_investigate(
                classified_events, incidents, mitre_mappings, ip_intel, summary,
                fallback_reason="Ollama AI not available — using rule-based analysis"
            )

    def _build_context(self, events: list, incidents: list,
                       mitre_mappings: list, ip_intel: dict, summary: dict) -> str:
        """Build a context string for the AI from all analysis data."""
        lines = ["=== SECURITY EVENT ANALYSIS CONTEXT ===\n"]

        # Summary
        lines.append(f"Total events analyzed: {summary.get('total_events', 0)}")
        lines.append(f"Total incidents identified: {summary.get('total_incidents', 0)}")
        lines.append(f"Unique source IPs: {summary.get('unique_source_ips', 0)}")
        lines.append(f"Multi-stage attacks: {summary.get('multi_stage_attacks', 0)}")

        # Severity distribution
        sev_dist = summary.get('severity_distribution', {})
        lines.append(f"\nSeverity Distribution: Critical={sev_dist.get('critical', 0)}, "
                      f"High={sev_dist.get('high', 0)}, Medium={sev_dist.get('medium', 0)}, "
                      f"Low={sev_dist.get('low', 0)}")

        # Top incidents
        lines.append("\n--- Key Incidents ---")
        for inc in incidents[:10]:
            lines.append(f"• {inc.get('description', 'Unknown')} "
                         f"[Severity: {inc.get('severity', 'unknown').upper()}] "
                         f"[Events: {inc.get('event_count', 0)}]")

        # MITRE mappings
        if mitre_mappings:
            lines.append("\n--- MITRE ATT&CK Mappings ---")
            for mapping in mitre_mappings[:10]:
                lines.append(f"• {mapping.get('technique_id', '')} - {mapping.get('name', '')} "
                             f"({mapping.get('tactic', '')})")

        # IP Intelligence
        if ip_intel:
            lines.append("\n--- IP Intelligence ---")
            for ip, info in list(ip_intel.items())[:10]:
                if not info.get('is_private', False):
                    lines.append(f"• {ip}: Country={info.get('country', 'Unknown')}, "
                                 f"Org={info.get('org', 'Unknown')}")

        # Critical events sample
        critical_events = [e for e in events if e.get('severity') in ('critical', 'high')][:5]
        if critical_events:
            lines.append("\n--- Sample Critical/High Severity Events ---")
            for event in critical_events:
                lines.append(
                    f"• [{event.get('severity', '').upper()}] {event.get('event_type', '')}: "
                    f"IP={event.get('source_ip', 'N/A')}, User={event.get('user', 'N/A')}, "
                    f"Host={event.get('host', 'N/A')}"
                )

        return '\n'.join(lines)

    def _ai_investigate(self, context: str) -> str:
        """Run AI-powered investigation using Ollama."""
        from langchain_core.messages import SystemMessage, HumanMessage

        messages = [
            SystemMessage(content=self.SOC_SYSTEM_PROMPT),
            HumanMessage(content=f"Analyze the following security events and provide your investigation findings:\n\n{context}"),
        ]

        response = self._llm.invoke(messages)
        return response.content

    def _rule_based_investigate(self, events: list, incidents: list,
                                mitre_mappings: list, ip_intel: dict,
                                summary: dict, fallback_reason: str = "") -> str:
        """Generate a rule-based investigation report (no AI required)."""
        lines = []

        if fallback_reason:
            lines.append(f"ℹ️ {fallback_reason}\n")

        # Executive summary
        total = summary.get('total_events', 0)
        sev = summary.get('severity_distribution', {})
        critical = sev.get('critical', 0)
        high = sev.get('high', 0)

        lines.append("## EXECUTIVE SUMMARY")
        lines.append(f"Analysis of {total} security events revealed {summary.get('total_incidents', 0)} "
                      f"correlated incidents. {critical + high} events were classified as Critical or High severity. "
                      f"{summary.get('unique_source_ips', 0)} unique source IPs were identified.")

        if summary.get('multi_stage_attacks', 0) > 0:
            lines.append(f"⚠️ {summary['multi_stage_attacks']} multi-stage attack pattern(s) detected — "
                         f"indicating advanced persistent threat activity.")

        # Attack analysis
        lines.append("\n## ATTACK ANALYSIS")
        attack_dist = summary.get('attack_type_distribution', {})
        for atype, count in sorted(attack_dist.items(), key=lambda x: -x[1]):
            lines.append(f"• **{atype.replace('_', ' ').title()}**: {count} events")

        # Key incidents
        if incidents:
            lines.append("\n## KEY INCIDENTS")
            severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
            sorted_incidents = sorted(incidents, key=lambda i: severity_order.get(i.get('severity', 'low'), 4))
            for inc in sorted_incidents[:8]:
                sev_emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}.get(inc.get('severity'), '⚪')
                lines.append(f"{sev_emoji} **{inc.get('description', '')}** [{inc.get('severity', '').upper()}]")
                if inc.get('affected_users'):
                    lines.append(f"  Affected users: {', '.join(inc['affected_users'])}")

        # Risk assessment
        lines.append("\n## RISK ASSESSMENT")
        if critical > 0:
            lines.append("🔴 **CRITICAL RISK** — Immediate action required. Critical security events detected "
                         "that may indicate active system compromise.")
        elif high > 0:
            lines.append("🟠 **HIGH RISK** — Prompt investigation needed. Multiple high-severity events "
                         "suggest active attack attempts.")
        elif sev.get('medium', 0) > 0:
            lines.append("🟡 **MEDIUM RISK** — Monitoring recommended. Suspicious activity detected that "
                         "should be investigated.")
        else:
            lines.append("🟢 **LOW RISK** — Routine security events. No immediate action required.")

        # Recommended actions
        lines.append("\n## RECOMMENDED ACTIONS")
        action_num = 1

        # Gather external IPs for blocking
        external_ips = []
        if ip_intel:
            external_ips = [ip for ip, info in ip_intel.items() if not info.get('is_private', True)]

        if external_ips:
            lines.append(f"{action_num}. **Block malicious IPs**: {', '.join(external_ips[:5])}")
            action_num += 1

        if any(at in attack_dist for at in ['brute_force', 'failed_login']):
            lines.append(f"{action_num}. **Enable multi-factor authentication** on all external-facing services")
            action_num += 1
            lines.append(f"{action_num}. **Implement account lockout policies** after 5 failed attempts")
            action_num += 1

        if any(at in attack_dist for at in ['sql_injection', 'xss_attempt', 'command_injection']):
            lines.append(f"{action_num}. **Deploy Web Application Firewall (WAF)** rules")
            action_num += 1
            lines.append(f"{action_num}. **Review and patch web application** input validation")
            action_num += 1

        if 'privilege_escalation' in attack_dist:
            lines.append(f"{action_num}. **Audit user privileges** and enforce least-privilege access")
            action_num += 1

        if 'web_shell' in attack_dist:
            lines.append(f"{action_num}. **Scan web server directories** for uploaded web shells")
            action_num += 1

        if any(at in attack_dist for at in ['suspicious_command', 'suspicious_process']):
            lines.append(f"{action_num}. **Review and isolate affected hosts** for forensic analysis")
            action_num += 1

        lines.append(f"{action_num}. **Preserve log files** for evidence and further investigation")

        return '\n'.join(lines)
