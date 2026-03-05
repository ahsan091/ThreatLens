"""
LangChain Agent Tools
Tools available to the SOC Investigation Agent.
"""

import json
import os


def load_mitre_dataset() -> dict:
    """Load the MITRE ATT&CK dataset from the data directory."""
    data_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'mitre_attack_dataset.json')
    try:
        with open(data_path, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"techniques": [], "attack_type_mapping": {}, "severity_rules": {}}


def analyze_events_tool(events_json: str) -> str:
    """
    Summarize a batch of security events for the SOC agent.
    Input: JSON string of events list.
    Output: Human-readable summary.
    """
    try:
        events = json.loads(events_json) if isinstance(events_json, str) else events_json
    except (json.JSONDecodeError, TypeError):
        return "Error: Could not parse events data."

    if not events:
        return "No events to analyze."

    total = len(events)
    severity_counts = {}
    attack_types = {}
    source_ips = set()
    affected_users = set()

    for event in events:
        sev = event.get('severity', 'unknown')
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

        atype = event.get('attack_type', event.get('event_type', 'unknown'))
        attack_types[atype] = attack_types.get(atype, 0) + 1

        ip = event.get('source_ip', '')
        if ip:
            source_ips.add(ip)

        user = event.get('user', '')
        if user:
            affected_users.add(user)

    lines = [
        f"=== Event Analysis Summary ===",
        f"Total security events: {total}",
        f"Unique source IPs: {len(source_ips)}",
        f"Affected users: {', '.join(affected_users) if affected_users else 'None identified'}",
        f"",
        f"Severity Distribution:",
    ]
    for sev in ['critical', 'high', 'medium', 'low']:
        if sev in severity_counts:
            lines.append(f"  {sev.upper()}: {severity_counts[sev]}")

    lines.append(f"")
    lines.append(f"Attack Types:")
    for atype, count in sorted(attack_types.items(), key=lambda x: -x[1]):
        lines.append(f"  {atype}: {count}")

    return '\n'.join(lines)


def lookup_mitre_tool(attack_type: str) -> str:
    """
    Look up MITRE ATT&CK techniques for a given attack type.
    Input: attack type string (e.g., 'brute_force', 'sql_injection')
    Output: MITRE technique details.
    """
    dataset = load_mitre_dataset()
    mapping = dataset.get('attack_type_mapping', {})
    techniques = dataset.get('techniques', [])

    technique_ids = mapping.get(attack_type, [])
    if not technique_ids:
        return f"No MITRE ATT&CK mapping found for attack type: {attack_type}"

    results = []
    for tid in technique_ids:
        for tech in techniques:
            if tech['technique_id'] == tid:
                results.append(
                    f"Technique {tech['technique_id']} - {tech['name']}\n"
                    f"  Tactic: {tech['tactic']}\n"
                    f"  Description: {tech['description'][:200]}\n"
                    f"  Remediation: {'; '.join(tech.get('remediation', []))}"
                )
                break

    if not results:
        return f"MITRE techniques {technique_ids} referenced but details not found in dataset."

    return '\n\n'.join(results)


def classify_threat_tool(event_json: str) -> str:
    """
    Classify a single event's threat level and type.
    Input: JSON string of a single event.
    Output: Classification result.
    """
    try:
        event = json.loads(event_json) if isinstance(event_json, str) else event_json
    except (json.JSONDecodeError, TypeError):
        return "Error: Could not parse event data."

    event_type = event.get('event_type', 'unknown')
    severity = event.get('severity', 'unknown')
    source_ip = event.get('source_ip', 'unknown')
    user = event.get('user', 'unknown')

    result = (
        f"Event Classification:\n"
        f"  Type: {event_type}\n"
        f"  Severity: {severity.upper()}\n"
        f"  Source IP: {source_ip}\n"
        f"  User: {user}\n"
        f"  Category: {event.get('attack_type', event_type)}"
    )

    return result
