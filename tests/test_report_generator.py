"""
Tests for Report Generator
Validates Markdown, JSON, and PDF report output.
"""

import sys
import os
import json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reports.report_generator import ReportGenerator


def _sample_analysis_data():
    """Build sample analysis data for report testing."""
    return {
        'classified_events': [
            {
                'timestamp': '2026-03-04T03:14:22',
                'host': 'server01',
                'os': 'linux',
                'log_category': 'authentication',
                'event_type': 'failed_login',
                'attack_type': 'brute_force',
                'severity': 'high',
                'user': 'root',
                'source_ip': '185.22.91.44',
            },
            {
                'timestamp': '2026-03-04T03:30:00',
                'host': 'webserver',
                'os': 'linux',
                'log_category': 'web',
                'event_type': 'sql_injection',
                'attack_type': 'sql_injection',
                'severity': 'high',
                'source_ip': '103.45.67.89',
            },
        ],
        'correlated_incidents': [
            {
                'incident_type': 'brute_force',
                'source_ip': '185.22.91.44',
                'event_count': 15,
                'severity': 'high',
                'first_seen': '2026-03-04T03:14:22',
                'last_seen': '2026-03-04T03:15:04',
                'description': '15 brute force events from 185.22.91.44',
                'affected_users': ['root', 'admin'],
            },
        ],
        'summary': {
            'total_events': 2,
            'total_incidents': 1,
            'severity_distribution': {'high': 2},
            'attack_type_distribution': {'brute_force': 1, 'sql_injection': 1},
            'unique_source_ips': 2,
        },
        'mitre_mappings': {
            'technique_summary': [
                {
                    'technique_id': 'T1110',
                    'name': 'Brute Force',
                    'tactic': 'Credential Access',
                    'count': 1,
                    'remediation': ['Implement account lockout', 'Enable MFA'],
                },
            ],
            'unique_techniques': [
                {
                    'technique_id': 'T1110',
                    'name': 'Brute Force',
                    'tactic': 'Credential Access',
                    'description': 'Adversaries may use brute force techniques.',
                },
            ],
        },
        'ip_intel': {
            '185.22.91.44': {
                'ip': '185.22.91.44',
                'country': 'RU',
                'asn': 'AS12345',
                'org': 'Evil Hosting LLC',
                'is_private': False,
                'risk_note': 'Hosting provider',
            },
        },
        'ai_analysis': '## EXECUTIVE SUMMARY\nBrute force attack detected from Russian IP.',
        'log_filename': 'test_sample.log',
    }


class TestReportGenerator:
    """Test suite for ReportGenerator."""

    def setup_method(self):
        self.generator = ReportGenerator()
        self.data = _sample_analysis_data()

    # ─── Markdown Report ──────────────────────────────────────────────

    def test_markdown_report_generated(self):
        md = self.generator.generate_markdown(self.data)
        assert isinstance(md, str)
        assert len(md) > 100

    def test_markdown_contains_title(self):
        md = self.generator.generate_markdown(self.data)
        assert 'Incident Investigation Report' in md

    def test_markdown_contains_severity(self):
        md = self.generator.generate_markdown(self.data)
        assert 'HIGH' in md

    def test_markdown_contains_mitre(self):
        md = self.generator.generate_markdown(self.data)
        assert 'T1110' in md
        assert 'Brute Force' in md

    def test_markdown_contains_ip_intel(self):
        md = self.generator.generate_markdown(self.data)
        assert '185.22.91.44' in md

    def test_markdown_contains_incidents(self):
        md = self.generator.generate_markdown(self.data)
        assert 'Correlated Incidents' in md

    def test_markdown_contains_ai_analysis(self):
        md = self.generator.generate_markdown(self.data)
        assert 'AI Investigation Analysis' in md

    # ─── JSON Report ──────────────────────────────────────────────────

    def test_json_report_valid(self):
        js = self.generator.generate_json(self.data)
        parsed = json.loads(js)
        assert isinstance(parsed, dict)

    def test_json_contains_metadata(self):
        js = self.generator.generate_json(self.data)
        parsed = json.loads(js)
        assert 'report_metadata' in parsed
        assert parsed['report_metadata']['log_source'] == 'test_sample.log'

    def test_json_contains_summary(self):
        js = self.generator.generate_json(self.data)
        parsed = json.loads(js)
        assert parsed['summary']['total_events'] == 2

    def test_json_contains_mitre(self):
        js = self.generator.generate_json(self.data)
        parsed = json.loads(js)
        assert len(parsed['mitre_mappings']['technique_summary']) > 0

    # ─── PDF Report ───────────────────────────────────────────────────

    def test_pdf_report_generated(self):
        pdf = self.generator.generate_pdf(self.data)
        assert isinstance(pdf, (bytes, bytearray))
        assert len(pdf) > 100  # Should produce a non-trivial PDF

    def test_pdf_starts_with_header(self):
        pdf = self.generator.generate_pdf(self.data)
        assert pdf[:5] == b'%PDF-'  # Valid PDF header
