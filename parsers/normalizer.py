"""
Event Normalizer
Converts raw parsed events into a unified SecurityEvent format.
"""

from datetime import datetime
from dateutil import parser as date_parser


class EventNormalizer:
    """Normalizes parsed log events into a unified security event structure."""

    def normalize(self, raw_event: dict) -> dict:
        """
        Normalize a raw parsed event into a unified SecurityEvent dictionary.
        
        Expected raw_event keys (all optional, parser-dependent):
            - timestamp (str): Raw timestamp string
            - host (str): Hostname
            - os (str): 'linux' or 'windows'
            - log_category (str): e.g. 'authentication', 'system', 'web', 'network', 'firewall'
            - event_type (str): e.g. 'failed_login', 'port_scan', 'sql_injection'
            - severity (str): 'low', 'medium', 'high', 'critical'
            - user (str): Username involved
            - source_ip (str): Source IP address
            - destination_ip (str): Destination IP address
            - destination_port (int): Destination port
            - process (str): Process name
            - command (str): Command executed
            - message (str): Raw log message
            - details (dict): Additional structured data
        """
        # Parse timestamp safely
        timestamp = raw_event.get('timestamp', '')
        try:
            if timestamp:
                parsed_ts = date_parser.parse(timestamp, fuzzy=True)
                timestamp = parsed_ts.isoformat()
        except (ValueError, TypeError):
            timestamp = timestamp if timestamp else datetime.now().isoformat()

        # Build normalized event
        normalized = {
            'timestamp': timestamp,
            'host': raw_event.get('host', 'unknown'),
            'os': raw_event.get('os', 'unknown'),
            'log_category': raw_event.get('log_category', 'unknown'),
            'event_type': raw_event.get('event_type', 'unknown'),
            'severity': raw_event.get('severity', 'low'),
            'user': raw_event.get('user', ''),
            'source_ip': raw_event.get('source_ip', ''),
            'destination_ip': raw_event.get('destination_ip', ''),
            'destination_port': raw_event.get('destination_port', 0),
            'process': raw_event.get('process', ''),
            'command': raw_event.get('command', ''),
            'message': raw_event.get('message', ''),
            'details': raw_event.get('details', {}),
        }

        return normalized
