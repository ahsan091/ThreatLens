"""
Tests for Threat Classification Engine
Validates severity assignment, attack classification, and event correlation.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.threat_classifier import ThreatClassifier


class TestThreatClassifier:
    """Test suite for ThreatClassifier."""

    def setup_method(self):
        self.classifier = ThreatClassifier()

    # ─── Single Event Classification ──────────────────────────────────

    def test_classify_failed_login(self):
        events = [{'event_type': 'failed_login', 'severity': 'medium', 'source_ip': '1.2.3.4', 'user': 'root'}]
        result = self.classifier.classify_events(events)
        assert len(result['classified_events']) == 1
        assert result['classified_events'][0]['attack_type'] == 'brute_force'

    def test_classify_sql_injection(self):
        events = [{'event_type': 'sql_injection', 'severity': 'high', 'source_ip': '1.2.3.4'}]
        result = self.classifier.classify_events(events)
        assert result['classified_events'][0]['attack_type'] == 'sql_injection'

    def test_skip_benign_events(self):
        events = [{'event_type': 'successful_login', 'severity': 'low', 'source_ip': '10.0.0.1', 'user': 'admin'}]
        result = self.classifier.classify_events(events)
        assert len(result['classified_events']) == 0  # non-attack event skipped

    # ─── Frequency Escalation ─────────────────────────────────────────

    def test_frequency_escalation_brute_force(self):
        events = [
            {'event_type': 'failed_login', 'severity': 'medium', 'source_ip': '1.2.3.4', 'user': 'root'}
            for _ in range(10)
        ]
        result = self.classifier.classify_events(events)
        # 10 failed logins from same IP should escalate to 'high'
        assert all(e['severity'] == 'high' for e in result['classified_events'])

    def test_no_escalation_below_threshold(self):
        events = [
            {'event_type': 'failed_login', 'severity': 'medium', 'source_ip': '1.2.3.4', 'user': 'root'}
            for _ in range(3)
        ]
        result = self.classifier.classify_events(events)
        assert all(e['severity'] == 'medium' for e in result['classified_events'])

    # ─── Event Correlation ────────────────────────────────────────────

    def test_correlate_same_ip_events(self):
        events = [
            {'event_type': 'failed_login', 'severity': 'medium', 'source_ip': '1.2.3.4',
             'user': 'root', 'timestamp': '2026-03-04T03:14:22'}
            for _ in range(5)
        ]
        result = self.classifier.classify_events(events)
        assert result['summary']['total_incidents'] > 0
        # Should have a correlated incident
        incident = result['correlated_incidents'][0]
        assert incident['source_ip'] == '1.2.3.4'
        assert incident['event_count'] == 5

    def test_separate_ip_separate_incidents(self):
        events = [
            {'event_type': 'failed_login', 'severity': 'medium', 'source_ip': '1.2.3.4',
             'user': 'root', 'timestamp': '2026-03-04T03:14:22'},
            {'event_type': 'failed_login', 'severity': 'medium', 'source_ip': '1.2.3.4',
             'user': 'root', 'timestamp': '2026-03-04T03:14:25'},
            {'event_type': 'failed_login', 'severity': 'medium', 'source_ip': '5.6.7.8',
             'user': 'admin', 'timestamp': '2026-03-04T03:14:22'},
            {'event_type': 'failed_login', 'severity': 'medium', 'source_ip': '5.6.7.8',
             'user': 'admin', 'timestamp': '2026-03-04T03:14:25'},
        ]
        result = self.classifier.classify_events(events)
        ips_in_incidents = set(i['source_ip'] for i in result['correlated_incidents'])
        assert '1.2.3.4' in ips_in_incidents
        assert '5.6.7.8' in ips_in_incidents

    # ─── Multi-Stage Attack Detection ─────────────────────────────────

    def test_detect_multi_stage_brute_force_then_login(self):
        events = [
            {'event_type': 'failed_login', 'severity': 'medium', 'source_ip': '1.2.3.4',
             'user': 'root', 'timestamp': '2026-03-04T03:14:22'},
            {'event_type': 'successful_login', 'severity': 'low', 'source_ip': '1.2.3.4',
             'user': 'root', 'timestamp': '2026-03-04T03:15:00'},
        ]
        result = self.classifier.classify_events(events)
        multi_stage = [i for i in result['correlated_incidents'] if i.get('is_multi_stage')]
        assert len(multi_stage) > 0
        assert multi_stage[0]['severity'] == 'critical'

    # ─── Summary Statistics ───────────────────────────────────────────

    def test_summary_statistics(self):
        events = [
            {'event_type': 'failed_login', 'severity': 'medium', 'source_ip': '1.2.3.4', 'user': 'root'},
            {'event_type': 'sql_injection', 'severity': 'high', 'source_ip': '5.6.7.8'},
            {'event_type': 'web_shell', 'severity': 'critical', 'source_ip': '9.10.11.12'},
        ]
        result = self.classifier.classify_events(events)
        summary = result['summary']
        assert summary['total_events'] == 3
        assert summary['unique_source_ips'] == 3
        assert 'critical' in summary['severity_distribution']
        assert 'high' in summary['severity_distribution']
