"""
Threat Classification Engine
Rule-based classifier with event correlation.
Works entirely without AI — the core detection backbone.
"""

from collections import defaultdict
from datetime import datetime, timedelta
from dateutil import parser as date_parser


class ThreatClassifier:
    """
    Classifies security events into attack categories and severity levels.
    Performs event correlation to group related events into incidents.
    """

    # ─── Attack classification rules ──────────────────────────────────

    EVENT_TYPE_TO_ATTACK = {
        'failed_login': 'brute_force',
        'successful_login': None,  # Not an attack by default
        'suspicious_command': 'suspicious_command',
        'sudo_execution': None,
        'account_creation': 'account_creation',
        'privilege_escalation': 'privilege_escalation',
        'suspicious_process': 'suspicious_process',
        'process_creation': None,
        'firewall_block': 'firewall_block',
        'firewall_allow': None,
        'service_failure': 'service_failure',
        'suspicious_cron': 'cron_modification',
        'oom_kill': 'service_failure',
        'sql_injection': 'sql_injection',
        'xss_attempt': 'xss_attempt',
        'path_traversal': 'path_traversal',
        'command_injection': 'command_injection',
        'web_shell': 'web_shell',
        'scanner_detected': 'port_scan',
        'suspicious_path_access': 'suspicious_path_access',
    }

    # ─── Severity escalation rules based on frequency ─────────────────

    FREQUENCY_ESCALATION = {
        'failed_login': {'threshold': 5, 'escalate_to': 'high'},
        'firewall_block': {'threshold': 8, 'escalate_to': 'high'},
        'scanner_detected': {'threshold': 3, 'escalate_to': 'high'},
    }

    # ─── Correlation rules ────────────────────────────────────────────

    CORRELATION_WINDOW_MINUTES = 30  # Group events within this time window

    MULTI_STAGE_PATTERNS = [
        {
            'name': 'Brute Force followed by Successful Login',
            'stages': ['failed_login', 'successful_login'],
            'severity': 'critical',
            'attack_type': 'credential_compromise',
        },
        {
            'name': 'Login followed by Privilege Escalation',
            'stages': ['successful_login', 'privilege_escalation'],
            'severity': 'critical',
            'attack_type': 'privilege_escalation_chain',
        },
        {
            'name': 'Login followed by Suspicious Command',
            'stages': ['successful_login', 'suspicious_command'],
            'severity': 'high',
            'attack_type': 'post_exploitation',
        },
        {
            'name': 'Web Attack followed by Web Shell',
            'stages': ['sql_injection', 'web_shell'],
            'severity': 'critical',
            'attack_type': 'web_compromise',
        },
        {
            'name': 'Port Scan followed by Brute Force',
            'stages': ['firewall_block', 'failed_login'],
            'severity': 'high',
            'attack_type': 'reconnaissance_and_attack',
        },
    ]

    def classify_events(self, events: list) -> dict:
        """
        Classify a list of normalized events.
        
        Returns:
            {
                'classified_events': [...],    # events with attack_type and final severity
                'correlated_incidents': [...],  # grouped incidents
                'summary': {...}               # statistics
            }
        """
        # Step 1: Classify individual events
        classified = []
        for event in events:
            classified_event = self._classify_single(event)
            if classified_event:
                classified.append(classified_event)

        # Step 2: Apply frequency-based severity escalation
        self._apply_frequency_escalation(classified)

        # Step 3: Correlate events into incidents
        incidents = self._correlate_events(classified)

        # Step 4: Detect multi-stage attacks using ALL events (including
        # benign ones like successful_login that are needed for chain detection)
        multi_stage = self._detect_multi_stage(events)
        incidents.extend(multi_stage)

        # Step 5: Build summary statistics
        summary = self._build_summary(classified, incidents)

        return {
            'classified_events': classified,
            'correlated_incidents': incidents,
            'summary': summary,
        }

    def _classify_single(self, event: dict) -> dict | None:
        """Classify a single event and add attack_type."""
        event_type = event.get('event_type', 'unknown')
        attack_type = self.EVENT_TYPE_TO_ATTACK.get(event_type)

        # Skip non-security events
        if attack_type is None and event_type in self.EVENT_TYPE_TO_ATTACK:
            return None

        classified = dict(event)
        classified['attack_type'] = attack_type if attack_type else event_type
        return classified

    def _apply_frequency_escalation(self, events: list):
        """Escalate severity for events that exceed frequency thresholds."""
        # Group events by (event_type, source_ip)
        groups = defaultdict(list)
        for event in events:
            key = (event.get('event_type'), event.get('source_ip', ''))
            groups[key].append(event)

        for (event_type, _), group_events in groups.items():
            rule = self.FREQUENCY_ESCALATION.get(event_type)
            if rule and len(group_events) >= rule['threshold']:
                for event in group_events:
                    event['severity'] = rule['escalate_to']

    def _correlate_events(self, events: list) -> list:
        """
        Correlate events into incidents based on source IP and time window.
        Groups multiple events from the same source IP within the time window.
        """
        incidents = []

        # Group events by source IP
        ip_groups = defaultdict(list)
        for event in events:
            ip = event.get('source_ip', '')
            if ip:
                ip_groups[ip].append(event)

        for source_ip, ip_events in ip_groups.items():
            if len(ip_events) < 2:
                continue

            # Sort by timestamp
            ip_events.sort(key=lambda e: e.get('timestamp', ''))

            # Group by attack type
            attack_groups = defaultdict(list)
            for event in ip_events:
                attack_groups[event.get('attack_type', 'unknown')].append(event)

            for attack_type, attack_events in attack_groups.items():
                if len(attack_events) < 2:
                    continue

                # Determine highest severity
                severity_order = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
                max_severity = max(attack_events,
                                   key=lambda e: severity_order.get(e.get('severity', 'low'), 0))

                incident = {
                    'incident_type': attack_type,
                    'source_ip': source_ip,
                    'event_count': len(attack_events),
                    'severity': max_severity.get('severity', 'medium'),
                    'first_seen': attack_events[0].get('timestamp', ''),
                    'last_seen': attack_events[-1].get('timestamp', ''),
                    'description': f"{len(attack_events)} {attack_type.replace('_', ' ')} events from {source_ip}",
                    'affected_users': list(set(
                        e.get('user', '') for e in attack_events if e.get('user')
                    )),
                    'events': attack_events,
                }
                incidents.append(incident)

        return incidents

    def _detect_multi_stage(self, events: list) -> list:
        """Detect multi-stage attack patterns across events."""
        multi_stage_incidents = []

        # Group events by source IP
        ip_groups = defaultdict(list)
        for event in events:
            ip = event.get('source_ip', '')
            if ip:
                ip_groups[ip].append(event)

        for source_ip, ip_events in ip_groups.items():
            ip_events.sort(key=lambda e: e.get('timestamp', ''))
            event_types = [e.get('event_type', '') for e in ip_events]

            for pattern in self.MULTI_STAGE_PATTERNS:
                stages = pattern['stages']
                # Check if all stages appear in order
                stage_idx = 0
                matching_events = []
                for i, et in enumerate(event_types):
                    if stage_idx < len(stages) and et == stages[stage_idx]:
                        matching_events.append(ip_events[i])
                        stage_idx += 1
                    if stage_idx == len(stages):
                        break

                if stage_idx == len(stages):
                    # Verify time window
                    if self._within_time_window(matching_events):
                        incident = {
                            'incident_type': pattern['attack_type'],
                            'source_ip': source_ip,
                            'event_count': len(matching_events),
                            'severity': pattern['severity'],
                            'first_seen': matching_events[0].get('timestamp', ''),
                            'last_seen': matching_events[-1].get('timestamp', ''),
                            'description': f"Multi-stage attack: {pattern['name']} from {source_ip}",
                            'pattern_name': pattern['name'],
                            'affected_users': list(set(
                                e.get('user', '') for e in matching_events if e.get('user')
                            )),
                            'events': matching_events,
                            'is_multi_stage': True,
                        }
                        multi_stage_incidents.append(incident)

        return multi_stage_incidents

    def _within_time_window(self, events: list) -> bool:
        """Check if all events are within the correlation time window."""
        if len(events) < 2:
            return True
        try:
            first = date_parser.parse(events[0].get('timestamp', ''))
            last = date_parser.parse(events[-1].get('timestamp', ''))
            delta = abs((last - first).total_seconds())
            return delta <= self.CORRELATION_WINDOW_MINUTES * 60
        except (ValueError, TypeError):
            return True  # If timestamps can't be parsed, assume correlated

    def _build_summary(self, events: list, incidents: list) -> dict:
        """Build summary statistics."""
        severity_counts = defaultdict(int)
        attack_type_counts = defaultdict(int)

        for event in events:
            severity_counts[event.get('severity', 'low')] += 1
            attack_type_counts[event.get('attack_type', 'unknown')] += 1

        unique_ips = set(e.get('source_ip', '') for e in events if e.get('source_ip'))

        return {
            'total_events': len(events),
            'total_incidents': len(incidents),
            'severity_distribution': dict(severity_counts),
            'attack_type_distribution': dict(attack_type_counts),
            'unique_source_ips': len(unique_ips),
            'source_ips': list(unique_ips),
            'multi_stage_attacks': sum(1 for i in incidents if i.get('is_multi_stage')),
        }
