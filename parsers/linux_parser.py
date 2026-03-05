"""
Linux Log Parser
Parses auth.log, syslog, secure, and UFW firewall logs.
"""

import re
from datetime import datetime


class LinuxLogParser:
    """Parses Linux system and authentication logs for security events."""

    # ─── Regex patterns ───────────────────────────────────────────────

    # Standard syslog timestamp: "Mar  4 03:14:22"
    SYSLOG_TS = r'([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'

    # Host and process: "server01 sshd[12401]:"
    HOST_PROC = r'(\S+)\s+(\S+?)(?:\[(\d+)\])?:'

    # Full syslog prefix
    SYSLOG_PREFIX = SYSLOG_TS + r'\s+' + HOST_PROC

    # SSH failed password
    RE_FAILED_PASSWORD = re.compile(
        SYSLOG_PREFIX + r'\s+Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)',
        re.IGNORECASE
    )

    # SSH accepted password / publickey
    RE_ACCEPTED_LOGIN = re.compile(
        SYSLOG_PREFIX + r'\s+Accepted (\S+) for (\S+) from (\S+) port (\d+)',
        re.IGNORECASE
    )

    # PAM authentication failure
    RE_PAM_AUTH_FAILURE = re.compile(
        SYSLOG_PREFIX + r'\s+pam_unix\(\S+\):\s+authentication failure;.*rhost=(\S+)\s+user=(\S*)',
        re.IGNORECASE
    )

    # sudo command execution
    RE_SUDO = re.compile(
        SYSLOG_PREFIX + r'\s+(\S+)\s*:\s+TTY=(\S+)\s*;\s*PWD=(\S+)\s*;\s*USER=(\S+)\s*;\s*COMMAND=(.*)',
        re.IGNORECASE
    )

    # useradd — new user created
    RE_USERADD = re.compile(
        SYSLOG_PREFIX + r'\s+new user:\s+name=(\S+),\s*UID=(\d+),\s*GID=(\d+)',
        re.IGNORECASE
    )

    # UFW firewall log
    RE_UFW = re.compile(
        SYSLOG_PREFIX + r'\s+\[UFW\s+(BLOCK|ALLOW)\]\s+.*SRC=(\S+)\s+DST=(\S+)\s+.*PROTO=(\S+)\s+SPT=(\d+)\s+DPT=(\d+)',
        re.IGNORECASE
    )

    # Service failure (systemd)
    RE_SERVICE_FAILURE = re.compile(
        SYSLOG_PREFIX + r'\s+(\S+\.service):\s+(?:Failed|Main process exited).*',
        re.IGNORECASE
    )

    # Suspicious cron job
    RE_CRON = re.compile(
        SYSLOG_PREFIX + r'\s+\((\S+)\)\s+CMD\s+\((.+)\)',
        re.IGNORECASE
    )

    # OOM killer
    RE_OOM = re.compile(
        SYSLOG_PREFIX + r'\s+Out of memory:\s+Killed process (\d+)\s+\((\S+)\)',
        re.IGNORECASE
    )

    # ─── Suspicious patterns for classification ───────────────────────

    SUSPICIOUS_COMMANDS = [
        'wget', 'curl', '/tmp/', 'chmod +x', 'base64',
        '/etc/shadow', '/etc/passwd', 'backdoor', 'reverse',
        'nc ', 'ncat', 'netcat', '/dev/tcp', 'bash -i',
        'python -c', 'perl -e', 'ruby -e', 'mkfifo',
    ]

    SUSPICIOUS_CRON_PATTERNS = [
        '/tmp/', '.hidden', 'wget', 'curl', 'base64',
        'backdoor', '/dev/null 2>&1', 'collect.php',
    ]

    def parse(self, content: str, log_type: str = 'linux_auth') -> list:
        """
        Parse Linux log content and return a list of raw event dictionaries.
        
        Args:
            content: Raw log file content
            log_type: One of 'linux_auth', 'linux_syslog', 'firewall'
        """
        events = []
        for line in content.strip().split('\n'):
            line = line.strip()
            if not line:
                continue

            event = None

            if log_type in ('linux_auth', 'linux_syslog', 'firewall'):
                event = self._parse_failed_password(line)
                if not event:
                    event = self._parse_accepted_login(line)
                if not event:
                    event = self._parse_pam_failure(line)
                if not event:
                    event = self._parse_sudo(line)
                if not event:
                    event = self._parse_useradd(line)
                if not event:
                    event = self._parse_ufw(line)
                if not event:
                    event = self._parse_service_failure(line)
                if not event:
                    event = self._parse_cron(line)
                if not event:
                    event = self._parse_oom(line)

            if event:
                event['message'] = line
                events.append(event)

        return events

    # ─── Individual parsers ───────────────────────────────────────────

    def _parse_failed_password(self, line: str) -> dict | None:
        m = self.RE_FAILED_PASSWORD.search(line)
        if not m:
            return None
        return {
            'timestamp': self._build_timestamp(m.group(1)),
            'host': m.group(2),
            'os': 'linux',
            'log_category': 'authentication',
            'event_type': 'failed_login',
            'severity': 'medium',
            'process': m.group(3),
            'user': m.group(5),
            'source_ip': m.group(6),
            'destination_port': int(m.group(7)),
            'details': {'method': 'ssh', 'invalid_user': 'invalid user' in line.lower()},
        }

    def _parse_accepted_login(self, line: str) -> dict | None:
        m = self.RE_ACCEPTED_LOGIN.search(line)
        if not m:
            return None
        return {
            'timestamp': self._build_timestamp(m.group(1)),
            'host': m.group(2),
            'os': 'linux',
            'log_category': 'authentication',
            'event_type': 'successful_login',
            'severity': 'low',
            'process': m.group(3),
            'user': m.group(6),
            'source_ip': m.group(7),
            'destination_port': int(m.group(8)),
            'details': {'method': m.group(5), 'auth_type': m.group(5)},
        }

    def _parse_pam_failure(self, line: str) -> dict | None:
        m = self.RE_PAM_AUTH_FAILURE.search(line)
        if not m:
            return None
        return {
            'timestamp': self._build_timestamp(m.group(1)),
            'host': m.group(2),
            'os': 'linux',
            'log_category': 'authentication',
            'event_type': 'failed_login',
            'severity': 'medium',
            'process': m.group(3),
            'source_ip': m.group(5),
            'user': m.group(6) if m.group(6) else 'unknown',
            'details': {'method': 'pam'},
        }

    def _parse_sudo(self, line: str) -> dict | None:
        m = self.RE_SUDO.search(line)
        if not m:
            return None
        command = m.group(9).strip()
        is_suspicious = any(pat in command.lower() for pat in self.SUSPICIOUS_COMMANDS)
        severity = 'high' if is_suspicious else 'low'
        event_type = 'suspicious_command' if is_suspicious else 'sudo_execution'

        return {
            'timestamp': self._build_timestamp(m.group(1)),
            'host': m.group(2),
            'os': 'linux',
            'log_category': 'system',
            'event_type': event_type,
            'severity': severity,
            'user': m.group(5),
            'command': command,
            'details': {
                'tty': m.group(6),
                'pwd': m.group(7),
                'target_user': m.group(8),
                'suspicious': is_suspicious,
            },
        }

    def _parse_useradd(self, line: str) -> dict | None:
        m = self.RE_USERADD.search(line)
        if not m:
            return None
        uid = int(m.group(6))
        severity = 'critical' if uid == 0 else 'high'
        return {
            'timestamp': self._build_timestamp(m.group(1)),
            'host': m.group(2),
            'os': 'linux',
            'log_category': 'system',
            'event_type': 'account_creation',
            'severity': severity,
            'user': m.group(5),
            'details': {'new_user': m.group(5), 'uid': uid, 'gid': int(m.group(7))},
        }

    def _parse_ufw(self, line: str) -> dict | None:
        m = self.RE_UFW.search(line)
        if not m:
            return None
        action = m.group(5).upper()
        event_type = 'firewall_block' if action == 'BLOCK' else 'firewall_allow'
        severity = 'medium' if action == 'BLOCK' else 'low'
        return {
            'timestamp': self._build_timestamp(m.group(1)),
            'host': m.group(2),
            'os': 'linux',
            'log_category': 'firewall',
            'event_type': event_type,
            'severity': severity,
            'source_ip': m.group(6),
            'destination_ip': m.group(7),
            'destination_port': int(m.group(10)),
            'details': {
                'action': action,
                'protocol': m.group(8),
                'source_port': int(m.group(9)),
            },
        }

    def _parse_service_failure(self, line: str) -> dict | None:
        m = self.RE_SERVICE_FAILURE.search(line)
        if not m:
            return None
        return {
            'timestamp': self._build_timestamp(m.group(1)),
            'host': m.group(2),
            'os': 'linux',
            'log_category': 'system',
            'event_type': 'service_failure',
            'severity': 'medium',
            'process': m.group(3),
            'details': {'service': m.group(5)},
        }

    def _parse_cron(self, line: str) -> dict | None:
        m = self.RE_CRON.search(line)
        if not m:
            return None
        command = m.group(6).strip()
        is_suspicious = any(pat in command.lower() for pat in self.SUSPICIOUS_CRON_PATTERNS)
        if not is_suspicious:
            return None  # Only flag suspicious cron entries
        return {
            'timestamp': self._build_timestamp(m.group(1)),
            'host': m.group(2),
            'os': 'linux',
            'log_category': 'system',
            'event_type': 'suspicious_cron',
            'severity': 'high',
            'user': m.group(5),
            'command': command,
            'details': {'suspicious': True},
        }

    def _parse_oom(self, line: str) -> dict | None:
        m = self.RE_OOM.search(line)
        if not m:
            return None
        return {
            'timestamp': self._build_timestamp(m.group(1)),
            'host': m.group(2),
            'os': 'linux',
            'log_category': 'system',
            'event_type': 'oom_kill',
            'severity': 'medium',
            'process': m.group(6),
            'details': {'killed_pid': int(m.group(5)), 'killed_process': m.group(6)},
        }

    # ─── Helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _build_timestamp(raw_ts: str) -> str:
        """Convert syslog timestamp to ISO format using current year."""
        try:
            current_year = datetime.now().year
            ts = datetime.strptime(f"{current_year} {raw_ts}", "%Y %b %d %H:%M:%S")
            return ts.isoformat()
        except ValueError:
            return raw_ts
