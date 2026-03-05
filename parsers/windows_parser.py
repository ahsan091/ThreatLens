"""
Windows Event Log Parser
Parses exported Windows Security Event Log text files.
Handles Event IDs: 4624, 4625, 4672, 4688
"""

import re


class WindowsLogParser:
    """Parses exported Windows Event Log text for security events."""

    # ─── Regex pattern for pipe-delimited exported event log ──────────

    RE_EVENT_LINE = re.compile(
        r'TimeCreated:\s*(\S+(?:\s+\S+)?)\s*\|\s*'
        r'EventID:\s*(\d+)\s*\|\s*'
        r'Level:\s*(\S+)\s*\|\s*'
        r'Computer:\s*(\S+)\s*\|\s*'
        r'Channel:\s*(\S+)\s*\|\s*'
        r'Provider:\s*(\S+)\s*\|\s*'
        r'Message:\s*(.*)',
        re.IGNORECASE
    )

    # ─── Sub-patterns for message body extraction ─────────────────────

    RE_ACCOUNT = re.compile(r'Account:\s*(\S+)', re.IGNORECASE)
    RE_SOURCE_IP = re.compile(r'Source Network Address:\s*(\S+)', re.IGNORECASE)
    RE_LOGON_TYPE = re.compile(r'Logon Type:\s*(\d+)', re.IGNORECASE)
    RE_FAILURE_REASON = re.compile(r'Failure Reason:\s*(.+?)(?:\.|$)', re.IGNORECASE)
    RE_PRIVILEGES = re.compile(r'Privileges:\s*(.+?)(?:\.|$)', re.IGNORECASE)
    RE_PROCESS_NAME = re.compile(r'New Process Name:\s*(\S+)', re.IGNORECASE)
    RE_COMMAND_LINE = re.compile(r'Process Command Line:\s*(.*)', re.IGNORECASE)
    RE_SECURITY_ID = re.compile(r'Security ID:\s*(\S+)', re.IGNORECASE)

    # ─── Suspicious process/command indicators ────────────────────────

    SUSPICIOUS_PROCESSES = [
        'powershell.exe', 'cmd.exe', 'rundll32.exe', 'regsvr32.exe',
        'mshta.exe', 'wscript.exe', 'cscript.exe', 'certutil.exe',
    ]

    SUSPICIOUS_COMMANDS = [
        '-enc ', '-ep bypass', '-nop ', 'iex', 'downloadstring',
        'invoke-expression', 'net user', 'net localgroup',
        'whoami', 'mimikatz', 'procdump', 'lsass',
        'minidump', 'comsvcs', '/add', 'administrators',
    ]

    # ─── Logon type descriptions ──────────────────────────────────────

    LOGON_TYPES = {
        '2': 'Interactive',
        '3': 'Network',
        '4': 'Batch',
        '5': 'Service',
        '7': 'Unlock',
        '8': 'NetworkCleartext',
        '9': 'NewCredentials',
        '10': 'RemoteInteractive (RDP)',
        '11': 'CachedInteractive',
    }

    def parse(self, content: str) -> list:
        """
        Parse Windows Event Log text and return a list of raw event dicts.
        """
        events = []
        for line in content.strip().split('\n'):
            line = line.strip()
            if not line:
                continue

            m = self.RE_EVENT_LINE.search(line)
            if not m:
                continue

            timestamp = m.group(1)
            event_id = m.group(2)
            computer = m.group(4)
            message = m.group(7)

            event = None

            if event_id == '4625':
                event = self._parse_4625(timestamp, computer, message)
            elif event_id == '4624':
                event = self._parse_4624(timestamp, computer, message)
            elif event_id == '4672':
                event = self._parse_4672(timestamp, computer, message)
            elif event_id == '4688':
                event = self._parse_4688(timestamp, computer, message)

            if event:
                event['message'] = line
                events.append(event)

        return events

    # ─── Event ID parsers ─────────────────────────────────────────────

    def _parse_4625(self, timestamp: str, computer: str, message: str) -> dict:
        """Failed login attempt."""
        account = self._extract(self.RE_ACCOUNT, message, 'unknown')
        source_ip = self._extract(self.RE_SOURCE_IP, message, '')
        logon_type = self._extract(self.RE_LOGON_TYPE, message, '')
        failure_reason = self._extract(self.RE_FAILURE_REASON, message, '')

        return {
            'timestamp': timestamp,
            'host': computer,
            'os': 'windows',
            'log_category': 'authentication',
            'event_type': 'failed_login',
            'severity': 'medium',
            'user': account,
            'source_ip': source_ip,
            'details': {
                'event_id': 4625,
                'logon_type': logon_type,
                'logon_type_desc': self.LOGON_TYPES.get(logon_type, 'Unknown'),
                'failure_reason': failure_reason,
            },
        }

    def _parse_4624(self, timestamp: str, computer: str, message: str) -> dict:
        """Successful login."""
        account = self._extract(self.RE_ACCOUNT, message, 'unknown')
        source_ip = self._extract(self.RE_SOURCE_IP, message, '')
        logon_type = self._extract(self.RE_LOGON_TYPE, message, '')

        return {
            'timestamp': timestamp,
            'host': computer,
            'os': 'windows',
            'log_category': 'authentication',
            'event_type': 'successful_login',
            'severity': 'low',
            'user': account,
            'source_ip': source_ip,
            'details': {
                'event_id': 4624,
                'logon_type': logon_type,
                'logon_type_desc': self.LOGON_TYPES.get(logon_type, 'Unknown'),
            },
        }

    def _parse_4672(self, timestamp: str, computer: str, message: str) -> dict:
        """Special privileges assigned to new logon."""
        account = self._extract(self.RE_ACCOUNT, message, 'unknown')
        privileges = self._extract(self.RE_PRIVILEGES, message, '')
        security_id = self._extract(self.RE_SECURITY_ID, message, '')

        # High-risk privileges
        dangerous_privs = ['SeDebugPrivilege', 'SeTakeOwnershipPrivilege', 'SeBackupPrivilege']
        has_dangerous = any(p in privileges for p in dangerous_privs)
        severity = 'high' if has_dangerous else 'medium'

        return {
            'timestamp': timestamp,
            'host': computer,
            'os': 'windows',
            'log_category': 'authentication',
            'event_type': 'privilege_escalation',
            'severity': severity,
            'user': account,
            'details': {
                'event_id': 4672,
                'privileges': privileges,
                'security_id': security_id,
                'dangerous_privileges': has_dangerous,
            },
        }

    def _parse_4688(self, timestamp: str, computer: str, message: str) -> dict:
        """New process created."""
        account = self._extract(self.RE_ACCOUNT, message, 'unknown')
        process_name = self._extract(self.RE_PROCESS_NAME, message, '')
        command_line = self._extract(self.RE_COMMAND_LINE, message, '')

        # Check if the process/command is suspicious
        proc_lower = process_name.lower()
        cmd_lower = command_line.lower()

        is_suspicious_proc = any(sp in proc_lower for sp in self.SUSPICIOUS_PROCESSES)
        is_suspicious_cmd = any(sc in cmd_lower for sc in self.SUSPICIOUS_COMMANDS)
        is_suspicious = is_suspicious_proc and is_suspicious_cmd

        if is_suspicious:
            event_type = 'suspicious_process'
            severity = 'critical' if 'lsass' in cmd_lower or 'mimikatz' in cmd_lower else 'high'
        else:
            event_type = 'process_creation'
            severity = 'low'

        return {
            'timestamp': timestamp,
            'host': computer,
            'os': 'windows',
            'log_category': 'process',
            'event_type': event_type,
            'severity': severity,
            'user': account,
            'process': process_name,
            'command': command_line,
            'details': {
                'event_id': 4688,
                'suspicious_process': is_suspicious_proc,
                'suspicious_command': is_suspicious_cmd,
            },
        }

    # ─── Helper ───────────────────────────────────────────────────────

    @staticmethod
    def _extract(pattern: re.Pattern, text: str, default: str = '') -> str:
        """Extract first match of pattern from text, or return default."""
        m = pattern.search(text)
        return m.group(1).strip().rstrip('.') if m else default
