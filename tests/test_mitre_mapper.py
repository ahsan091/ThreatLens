"""
Tests for MITRE ATT&CK Mapper
Validates correct technique mapping and summary generation.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mitre.mitre_mapper import MITREMapper


class TestMITREMapper:
    """Test suite for MITREMapper."""

    def setup_method(self):
        self.mapper = MITREMapper()

    # ─── Attack Type Mapping ──────────────────────────────────────────

    def test_map_brute_force(self):
        result = self.mapper.map_attack_type('brute_force')
        assert len(result) > 0
        technique_ids = [t['technique_id'] for t in result]
        assert 'T1110' in technique_ids

    def test_map_sql_injection(self):
        result = self.mapper.map_attack_type('sql_injection')
        assert len(result) > 0
        technique_ids = [t['technique_id'] for t in result]
        assert 'T1190' in technique_ids

    def test_map_port_scan(self):
        result = self.mapper.map_attack_type('port_scan')
        assert len(result) > 0
        technique_ids = [t['technique_id'] for t in result]
        assert 'T1046' in technique_ids

    def test_map_privilege_escalation(self):
        result = self.mapper.map_attack_type('privilege_escalation')
        assert len(result) > 0
        technique_ids = [t['technique_id'] for t in result]
        assert 'T1548' in technique_ids

    def test_map_unknown_attack_type(self):
        result = self.mapper.map_attack_type('nonexistent_attack')
        assert len(result) == 0

    # ─── Technique Lookup ─────────────────────────────────────────────

    def test_get_technique_by_id(self):
        tech = self.mapper.get_technique_by_id('T1110')
        assert tech is not None
        assert tech['name'] == 'Brute Force'
        assert tech['tactic'] == 'Credential Access'

    def test_technique_has_remediation(self):
        tech = self.mapper.get_technique_by_id('T1110')
        assert 'remediation' in tech
        assert len(tech['remediation']) > 0

    # ─── Batch Event Mapping ─────────────────────────────────────────

    def test_map_events_batch(self):
        events = [
            {'attack_type': 'brute_force', 'event_type': 'failed_login'},
            {'attack_type': 'brute_force', 'event_type': 'failed_login'},
            {'attack_type': 'sql_injection', 'event_type': 'sql_injection'},
        ]
        result = self.mapper.map_events(events)
        assert len(result['event_mappings']) > 0
        assert len(result['unique_techniques']) > 0
        assert len(result['technique_summary']) > 0

        # Check technique counts
        t1110 = [t for t in result['technique_summary'] if t['technique_id'] == 'T1110']
        assert len(t1110) > 0
        assert t1110[0]['count'] >= 2

    def test_map_events_empty(self):
        result = self.mapper.map_events([])
        assert result['event_mappings'] == []
        assert result['unique_techniques'] == []

    # ─── Dataset Integrity ────────────────────────────────────────────

    def test_all_techniques_loaded(self):
        techniques = self.mapper.get_all_techniques()
        assert len(techniques) >= 15  # We have ~20 techniques in the dataset
