"""
Log Parsers Package
Auto-detects log type and routes to the appropriate parser.
"""

from parsers.linux_parser import LinuxLogParser
from parsers.windows_parser import WindowsLogParser
from parsers.web_parser import WebLogParser
from parsers.normalizer import EventNormalizer


def detect_log_type(content: str) -> str:
    """
    Auto-detect log type based on file content heuristics.
    
    Returns one of: 'linux_auth', 'linux_syslog', 'windows', 'web', 'firewall', 'unknown'
    """
    lines = content.strip().split('\n')
    if not lines:
        return 'unknown'

    sample = '\n'.join(lines[:50]).lower()

    # Windows Event Log markers
    if 'event id' in sample or 'microsoft-windows-security' in sample or 'eventid' in sample:
        return 'windows'

    # Web server log (Apache/Nginx combined format)
    if ('"get ' in sample or '"post ' in sample or '"put ' in sample) and 'http/' in sample:
        return 'web'

    # Linux auth log markers
    if 'sshd[' in sample or 'pam_unix' in sample or 'sudo:' in sample or 'failed password' in sample:
        return 'linux_auth'

    # Firewall log markers (UFW, iptables)
    if '[ufw ' in sample or 'iptables' in sample or 'firewall' in sample.split('\n')[0]:
        return 'firewall'

    # Linux syslog fallback
    if 'systemd[' in sample or 'kernel:' in sample or 'cron[' in sample:
        return 'linux_syslog'

    return 'unknown'


def parse_log_file(content: str, log_type: str = None) -> list:
    """
    Parse a log file and return a list of normalized security events.
    
    Args:
        content: Raw log file content as string
        log_type: Optional log type override. If None, auto-detects.
    
    Returns:
        List of normalized event dictionaries
    """
    if log_type is None or log_type == 'auto':
        log_type = detect_log_type(content)

    normalizer = EventNormalizer()

    if log_type in ('linux_auth', 'linux_syslog', 'firewall'):
        parser = LinuxLogParser()
        raw_events = parser.parse(content, log_type)
    elif log_type == 'windows':
        parser = WindowsLogParser()
        raw_events = parser.parse(content)
    elif log_type == 'web':
        parser = WebLogParser()
        raw_events = parser.parse(content)
    else:
        return []

    normalized = [normalizer.normalize(event) for event in raw_events]
    return normalized
