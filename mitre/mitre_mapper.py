"""
MITRE ATT&CK Mapper
Maps classified attack types to MITRE ATT&CK techniques.
"""

import json
import os


class MITREMapper:
    """Maps detected attack types to MITRE ATT&CK techniques, tactics, and remediation."""

    def __init__(self, dataset_path: str = None):
        if dataset_path is None:
            dataset_path = os.path.join(
                os.path.dirname(os.path.dirname(__file__)),
                'data', 'mitre_attack_dataset.json'
            )
        self._dataset = self._load_dataset(dataset_path)
        self._techniques_index = self._build_index()

    @staticmethod
    def _load_dataset(path: str) -> dict:
        """Load the MITRE ATT&CK dataset from JSON file."""
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Warning: Could not load MITRE dataset: {e}")
            return {"techniques": [], "attack_type_mapping": {}, "severity_rules": {}}

    def _build_index(self) -> dict:
        """Build a technique ID to technique data index for fast lookup."""
        index = {}
        for tech in self._dataset.get('techniques', []):
            index[tech['technique_id']] = tech
        return index

    def map_attack_type(self, attack_type: str) -> list:
        """
        Map an attack type string to its MITRE ATT&CK techniques.
        
        Args:
            attack_type: e.g., 'brute_force', 'sql_injection'
        
        Returns:
            List of technique dicts with id, name, tactic, description, remediation.
        """
        mapping = self._dataset.get('attack_type_mapping', {})
        technique_ids = mapping.get(attack_type, [])

        results = []
        for tid in technique_ids:
            tech = self._techniques_index.get(tid)
            if tech:
                results.append({
                    'technique_id': tech['technique_id'],
                    'name': tech['name'],
                    'tactic': tech['tactic'],
                    'description': tech['description'],
                    'remediation': tech.get('remediation', []),
                    'sub_techniques': tech.get('sub_techniques', []),
                    'detection': tech.get('detection', ''),
                })

        return results

    def map_events(self, classified_events: list) -> dict:
        """
        Map all classified events to MITRE techniques.
        
        Returns:
            {
                'event_mappings': [{'event': ..., 'mitre': [...]}],
                'unique_techniques': [...],
                'technique_summary': [{'technique_id': ..., 'name': ..., 'count': int}]
            }
        """
        event_mappings = []
        technique_counts = {}
        seen_techniques = {}

        for event in classified_events:
            attack_type = event.get('attack_type', event.get('event_type', ''))
            techniques = self.map_attack_type(attack_type)

            if techniques:
                event_mappings.append({
                    'event': event,
                    'mitre': techniques,
                })

                for tech in techniques:
                    tid = tech['technique_id']
                    technique_counts[tid] = technique_counts.get(tid, 0) + 1
                    if tid not in seen_techniques:
                        seen_techniques[tid] = tech

        # Build technique summary sorted by frequency
        technique_summary = []
        for tid, count in sorted(technique_counts.items(), key=lambda x: -x[1]):
            tech = seen_techniques[tid]
            technique_summary.append({
                'technique_id': tid,
                'name': tech['name'],
                'tactic': tech['tactic'],
                'count': count,
                'remediation': tech.get('remediation', []),
            })

        return {
            'event_mappings': event_mappings,
            'unique_techniques': list(seen_techniques.values()),
            'technique_summary': technique_summary,
        }

    def get_all_techniques(self) -> list:
        """Return all techniques in the dataset."""
        return self._dataset.get('techniques', [])

    def get_technique_by_id(self, technique_id: str) -> dict | None:
        """Look up a specific technique by its ID."""
        return self._techniques_index.get(technique_id)
