"""
Incident Report Generator
Generates security investigation reports in Markdown, JSON, and PDF formats.
"""

import json
import os
from datetime import datetime


class ReportGenerator:
    """Generates structured incident investigation reports."""

    def __init__(self, output_dir: str = None):
        if output_dir is None:
            output_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'reports', 'output')
        self._output_dir = output_dir
        os.makedirs(self._output_dir, exist_ok=True)

    def generate_all(self, analysis_data: dict) -> dict:
        """
        Generate reports in all three formats.
        
        Args:
            analysis_data: {
                'classified_events': [...],
                'correlated_incidents': [...],
                'summary': {...},
                'mitre_mappings': {...},
                'ip_intel': {...},
                'ai_analysis': str,
                'log_filename': str,
            }
        
        Returns:
            {'markdown': str, 'json': str, 'pdf_bytes': bytes}
        """
        md = self.generate_markdown(analysis_data)
        js = self.generate_json(analysis_data)
        pdf = self.generate_pdf(analysis_data)

        return {
            'markdown': md,
            'json': js,
            'pdf_bytes': pdf,
        }

    # ─── Markdown Report ──────────────────────────────────────────────

    def generate_markdown(self, data: dict) -> str:
        """Generate a Markdown format incident report."""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        summary = data.get('summary', {})
        incidents = data.get('correlated_incidents', [])
        mitre = data.get('mitre_mappings', {})
        ip_intel = data.get('ip_intel', {})
        ai_analysis = data.get('ai_analysis', '')
        log_filename = data.get('log_filename', 'Unknown')

        lines = [
            "# 🛡️ AI SOC Analyst — Incident Investigation Report",
            "",
            f"**Report Generated:** {now}",
            f"**Log Source:** {log_filename}",
            f"**Total Events Analyzed:** {summary.get('total_events', 0)}",
            f"**Total Incidents:** {summary.get('total_incidents', 0)}",
            f"**Unique Source IPs:** {summary.get('unique_source_ips', 0)}",
            "",
            "---",
            "",
        ]

        # Executive Summary
        lines.append("## 📊 Executive Summary")
        lines.append("")
        sev = summary.get('severity_distribution', {})
        lines.append(f"| Severity | Count |")
        lines.append(f"|----------|-------|")
        for level in ['critical', 'high', 'medium', 'low']:
            count = sev.get(level, 0)
            if count > 0:
                emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}[level]
                lines.append(f"| {emoji} {level.upper()} | {count} |")
        lines.append("")

        # Attack Type Distribution
        attack_dist = summary.get('attack_type_distribution', {})
        if attack_dist:
            lines.append("### Attack Types Detected")
            lines.append("")
            lines.append("| Attack Type | Count |")
            lines.append("|------------|-------|")
            for atype, count in sorted(attack_dist.items(), key=lambda x: -x[1]):
                lines.append(f"| {atype.replace('_', ' ').title()} | {count} |")
            lines.append("")

        # Correlated Incidents
        if incidents:
            lines.append("## 🔗 Correlated Incidents")
            lines.append("")
            severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
            sorted_inc = sorted(incidents, key=lambda i: severity_order.get(i.get('severity', 'low'), 4))
            for i, inc in enumerate(sorted_inc, 1):
                sev_emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}.get(inc.get('severity'), '⚪')
                lines.append(f"### Incident {i}: {inc.get('incident_type', 'Unknown').replace('_', ' ').title()}")
                lines.append("")
                lines.append(f"- **Severity:** {sev_emoji} {inc.get('severity', 'unknown').upper()}")
                lines.append(f"- **Source IP:** `{inc.get('source_ip', 'N/A')}`")
                lines.append(f"- **Event Count:** {inc.get('event_count', 0)}")
                lines.append(f"- **First Seen:** {inc.get('first_seen', 'N/A')}")
                lines.append(f"- **Last Seen:** {inc.get('last_seen', 'N/A')}")
                lines.append(f"- **Description:** {inc.get('description', '')}")
                if inc.get('affected_users'):
                    lines.append(f"- **Affected Users:** {', '.join(inc['affected_users'])}")
                if inc.get('is_multi_stage'):
                    lines.append(f"- **⚠️ Multi-Stage Attack:** {inc.get('pattern_name', 'Yes')}")
                lines.append("")

        # IP Intelligence
        external_ips = {ip: info for ip, info in ip_intel.items() if not info.get('is_private', True)}
        if external_ips:
            lines.append("## 🌐 IP Intelligence")
            lines.append("")
            lines.append("| IP Address | Country | Organization | Risk Note |")
            lines.append("|-----------|---------|-------------|-----------|")
            for ip, info in external_ips.items():
                lines.append(f"| `{ip}` | {info.get('country', 'Unknown')} | "
                             f"{info.get('org', 'Unknown')} | {info.get('risk_note', '')} |")
            lines.append("")

        # MITRE ATT&CK Mapping
        technique_summary = mitre.get('technique_summary', [])
        if technique_summary:
            lines.append("## 🎯 MITRE ATT&CK Mapping")
            lines.append("")
            lines.append("| Technique ID | Name | Tactic | Events |")
            lines.append("|-------------|------|--------|--------|")
            for tech in technique_summary:
                lines.append(f"| {tech['technique_id']} | {tech['name']} | "
                             f"{tech['tactic']} | {tech['count']} |")
            lines.append("")

            # Remediation recommendations
            lines.append("### Recommended Remediations")
            lines.append("")
            seen_remediations = set()
            for tech in technique_summary:
                for rem in tech.get('remediation', []):
                    if rem not in seen_remediations:
                        seen_remediations.add(rem)
                        lines.append(f"- {rem}")
            lines.append("")

        # AI Analysis
        if ai_analysis:
            lines.append("## 🤖 AI Investigation Analysis")
            lines.append("")
            lines.append(ai_analysis)
            lines.append("")

        # Footer
        lines.append("---")
        lines.append(f"*Report generated by AI SOC Analyst Agent (ThreatLens) — {now}*")

        return '\n'.join(lines)

    # ─── JSON Report ──────────────────────────────────────────────────

    def generate_json(self, data: dict) -> str:
        """Generate a JSON format incident report."""
        now = datetime.now().isoformat()

        report = {
            'report_metadata': {
                'generated_at': now,
                'tool': 'AI SOC Analyst Agent (ThreatLens)',
                'log_source': data.get('log_filename', 'Unknown'),
            },
            'summary': data.get('summary', {}),
            'correlated_incidents': self._clean_incidents_for_json(data.get('correlated_incidents', [])),
            'mitre_mappings': {
                'technique_summary': data.get('mitre_mappings', {}).get('technique_summary', []),
                'unique_techniques': [
                    {k: v for k, v in t.items() if k != 'sub_techniques'}
                    for t in data.get('mitre_mappings', {}).get('unique_techniques', [])
                ],
            },
            'ip_intelligence': data.get('ip_intel', {}),
            'ai_analysis': data.get('ai_analysis', ''),
            'classified_events': data.get('classified_events', [])[:100],  # Cap at 100 for JSON size
        }

        return json.dumps(report, indent=2, default=str)

    def _clean_incidents_for_json(self, incidents: list) -> list:
        """Remove full event lists from incidents for cleaner JSON output."""
        cleaned = []
        for inc in incidents:
            clean_inc = {k: v for k, v in inc.items() if k != 'events'}
            clean_inc['event_count'] = inc.get('event_count', len(inc.get('events', [])))
            cleaned.append(clean_inc)
        return cleaned

    # ─── PDF Report ───────────────────────────────────────────────────

    def generate_pdf(self, data: dict) -> bytes:
        """Generate a PDF format incident report."""
        try:
            from fpdf import FPDF
        except ImportError:
            return b""

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        summary = data.get('summary', {})
        incidents = data.get('correlated_incidents', [])
        mitre = data.get('mitre_mappings', {})
        ip_intel = data.get('ip_intel', {})
        ai_analysis = data.get('ai_analysis', '')

        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()

        # Title
        pdf.set_font("Helvetica", "B", 20)
        pdf.cell(0, 12, "AI SOC Analyst - Incident Report", new_x="LMARGIN", new_y="NEXT", align="C")
        pdf.ln(5)

        # Metadata
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 6, f"Report Generated: {now}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 6, f"Log Source: {data.get('log_filename', 'Unknown')}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 6, f"Total Events: {summary.get('total_events', 0)} | "
                       f"Incidents: {summary.get('total_incidents', 0)} | "
                       f"Unique IPs: {summary.get('unique_source_ips', 0)}", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(5)

        # Severity distribution
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 8, "Severity Distribution", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        sev = summary.get('severity_distribution', {})
        for level in ['critical', 'high', 'medium', 'low']:
            count = sev.get(level, 0)
            if count > 0:
                pdf.cell(0, 6, f"  {level.upper()}: {count}", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)

        # Attack type distribution
        attack_dist = summary.get('attack_type_distribution', {})
        if attack_dist:
            pdf.set_font("Helvetica", "B", 14)
            pdf.cell(0, 8, "Attack Types", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 10)
            for atype, count in sorted(attack_dist.items(), key=lambda x: -x[1]):
                pdf.cell(0, 6, f"  {atype.replace('_', ' ').title()}: {count}", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(3)

        # Incidents
        if incidents:
            pdf.set_font("Helvetica", "B", 14)
            pdf.cell(0, 8, "Correlated Incidents", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 10)
            severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
            sorted_inc = sorted(incidents, key=lambda i: severity_order.get(i.get('severity', 'low'), 4))
            for inc in sorted_inc[:10]:
                pdf.set_font("Helvetica", "B", 10)
                pdf.cell(0, 6, f"{inc.get('incident_type', 'Unknown').replace('_', ' ').title()} "
                               f"[{inc.get('severity', '').upper()}]", new_x="LMARGIN", new_y="NEXT")
                pdf.set_font("Helvetica", "", 9)
                pdf.cell(0, 5, f"  Source IP: {inc.get('source_ip', 'N/A')} | "
                               f"Events: {inc.get('event_count', 0)}", new_x="LMARGIN", new_y="NEXT")
                desc = inc.get('description', '')
                if desc:
                    pdf.cell(0, 5, f"  {desc[:100]}", new_x="LMARGIN", new_y="NEXT")
                pdf.ln(2)

        # IP Intelligence
        external_ips = {ip: info for ip, info in ip_intel.items() if not info.get('is_private', True)}
        if external_ips:
            pdf.add_page()
            pdf.set_font("Helvetica", "B", 14)
            pdf.cell(0, 8, "IP Intelligence", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 10)
            for ip, info in external_ips.items():
                pdf.cell(0, 6, f"  {ip}: {info.get('country', 'Unknown')} | "
                               f"{info.get('org', 'Unknown')}", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(3)

        # MITRE mappings
        technique_summary = mitre.get('technique_summary', [])
        if technique_summary:
            pdf.set_font("Helvetica", "B", 14)
            pdf.cell(0, 8, "MITRE ATT&CK Mapping", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 10)
            for tech in technique_summary:
                pdf.cell(0, 6, f"  {tech['technique_id']} - {tech['name']} "
                               f"({tech['tactic']}) [{tech['count']} events]", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(3)

        # AI Analysis
        if ai_analysis:
            pdf.add_page()
            pdf.set_font("Helvetica", "B", 14)
            pdf.cell(0, 8, "AI Investigation Analysis", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 9)
            # Clean markdown formatting for PDF
            clean_analysis = ai_analysis.replace('**', '').replace('##', '').replace('# ', '')
            clean_analysis = clean_analysis.replace('🔴', '[CRITICAL]').replace('🟠', '[HIGH]')
            clean_analysis = clean_analysis.replace('🟡', '[MEDIUM]').replace('🟢', '[LOW]')
            clean_analysis = clean_analysis.replace('⚠️', '[WARNING]')
            # Use effective page width to avoid overflow
            effective_w = pdf.w - pdf.l_margin - pdf.r_margin
            for line in clean_analysis.split('\n'):
                line = line.strip()
                if line:
                    # Truncate extremely long lines to prevent rendering issues
                    if len(line) > 500:
                        line = line[:500] + '...'
                    try:
                        pdf.multi_cell(effective_w, 5, line)
                    except Exception:
                        # Fallback: use cell with truncation
                        pdf.cell(0, 5, line[:120], new_x="LMARGIN", new_y="NEXT")

        # Footer
        pdf.ln(10)
        pdf.set_font("Helvetica", "I", 8)
        pdf.cell(0, 5, f"Generated by AI SOC Analyst Agent (ThreatLens) - {now}", new_x="LMARGIN", new_y="NEXT", align="C")

        return pdf.output()
