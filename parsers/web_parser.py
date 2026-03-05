"""
Web Server Log Parser
Parses Apache/Nginx combined log format and detects web application attacks.
"""

import re
from urllib.parse import unquote


class WebLogParser:
    """Parses web server access logs for security events."""

    # ─── Combined log format regex ────────────────────────────────────
    # 185.22.91.44 - user [04/Mar/2026:03:14:22 +0000] "GET /path HTTP/1.1" 200 3456 "ref" "UA"

    RE_ACCESS_LOG = re.compile(
        r'(\S+)\s+'           # source_ip
        r'(\S+)\s+'           # ident
        r'(\S+)\s+'           # user
        r'\[([^\]]+)\]\s+'    # timestamp
        r'"(\S+)\s+'          # method
        r'(\S+)\s+'           # path
        r'(\S+)"\s+'          # protocol
        r'(\d{3})\s+'         # status
        r'(\d+|-)\s*'         # size
        r'(?:"([^"]*)"\s*)?'  # referer
        r'(?:"([^"]*)")?'    # user_agent
    )

    # ─── Attack detection patterns ────────────────────────────────────

    SQL_INJECTION_PATTERNS = [
        r"(?:UNION\s+SELECT|UNION\s+ALL\s+SELECT)",
        r"(?:OR\s+1\s*=\s*1)",
        r"(?:AND\s+1\s*=\s*1)",
        r"(?:DROP\s+TABLE)",
        r"(?:INSERT\s+INTO)",
        r"(?:DELETE\s+FROM)",
        r"(?:UPDATE\s+\S+\s+SET)",
        r"(?:SELECT\s+.*FROM)",
        r"(?:--\s*$|;\s*--)",
        r"(?:'\s*OR\s+')",
        r"(?:SLEEP\s*\()",
        r"(?:BENCHMARK\s*\()",
    ]

    XSS_PATTERNS = [
        r"<script",
        r"javascript:",
        r"onerror\s*=",
        r"onload\s*=",
        r"onclick\s*=",
        r"alert\s*\(",
        r"document\.cookie",
        r"<img\s+src\s*=\s*x",
        r"<svg\s+onload",
    ]

    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",
        r"\.\.\%2[fF]",
        r"/etc/passwd",
        r"/etc/shadow",
        r"/proc/self",
        r"\\\\",
    ]

    COMMAND_INJECTION_PATTERNS = [
        r";\s*(?:cat|ls|id|whoami|wget|curl|nc|bash)",
        r"\|\s*(?:cat|ls|id|whoami)",
        r"`.*`",
        r"\$\(.*\)",
        r"cmd=",
    ]

    SUSPICIOUS_USER_AGENTS = [
        'sqlmap', 'nikto', 'dirbuster', 'gobuster', 'hydra',
        'nessus', 'openvas', 'masscan', 'zap', 'burp',
        'w3af', 'acunetix', 'nmap', 'metasploit',
    ]

    SUSPICIOUS_PATHS = [
        '/wp-admin', '/wp-login', '/administrator', '/phpmyadmin',
        '/admin', '/.env', '/.git', '/config', '/backup',
        '/shell', '/cmd', '/uploads/shell', '/cgi-bin',
    ]

    def __init__(self):
        # Pre-compile all attack regex
        self._sqli_re = [re.compile(p, re.IGNORECASE) for p in self.SQL_INJECTION_PATTERNS]
        self._xss_re = [re.compile(p, re.IGNORECASE) for p in self.XSS_PATTERNS]
        self._traversal_re = [re.compile(p, re.IGNORECASE) for p in self.PATH_TRAVERSAL_PATTERNS]
        self._cmdi_re = [re.compile(p, re.IGNORECASE) for p in self.COMMAND_INJECTION_PATTERNS]

    def parse(self, content: str) -> list:
        """
        Parse web server log content and return a list of raw event dicts.
        Only returns events with detected security issues.
        """
        events = []
        for line in content.strip().split('\n'):
            line = line.strip()
            if not line:
                continue

            m = self.RE_ACCESS_LOG.search(line)
            if not m:
                continue

            source_ip = m.group(1)
            user = m.group(3) if m.group(3) != '-' else ''
            timestamp = m.group(4)
            method = m.group(5)
            path = m.group(6)
            status = int(m.group(8))
            user_agent = m.group(11) if m.group(11) else ''

            # URL-decode the path for pattern matching
            decoded_path = unquote(path)

            # Detect attack patterns
            attacks = self._detect_attacks(decoded_path, user_agent, method)

            if attacks:
                for attack in attacks:
                    event = {
                        'timestamp': self._convert_timestamp(timestamp),
                        'host': 'webserver',
                        'os': 'linux',
                        'log_category': 'web',
                        'event_type': attack['type'],
                        'severity': attack['severity'],
                        'user': user,
                        'source_ip': source_ip,
                        'message': line,
                        'details': {
                            'method': method,
                            'path': path,
                            'decoded_path': decoded_path,
                            'status_code': status,
                            'user_agent': user_agent,
                            'attack_pattern': attack['pattern'],
                        },
                    }
                    events.append(event)

        return events

    def _detect_attacks(self, path: str, user_agent: str, method: str) -> list:
        """Detect attack patterns in the request. Returns list of detected attacks."""
        attacks = []

        # SQL Injection
        for rx in self._sqli_re:
            if rx.search(path):
                attacks.append({
                    'type': 'sql_injection',
                    'severity': 'high',
                    'pattern': rx.pattern,
                })
                break

        # XSS
        for rx in self._xss_re:
            if rx.search(path):
                attacks.append({
                    'type': 'xss_attempt',
                    'severity': 'medium',
                    'pattern': rx.pattern,
                })
                break

        # Path Traversal
        for rx in self._traversal_re:
            if rx.search(path):
                attacks.append({
                    'type': 'path_traversal',
                    'severity': 'high',
                    'pattern': rx.pattern,
                })
                break

        # Command Injection
        for rx in self._cmdi_re:
            if rx.search(path):
                attacks.append({
                    'type': 'command_injection',
                    'severity': 'critical',
                    'pattern': rx.pattern,
                })
                break

        # Suspicious user agent (scanner detection)
        ua_lower = user_agent.lower()
        for scanner in self.SUSPICIOUS_USER_AGENTS:
            if scanner in ua_lower:
                attacks.append({
                    'type': 'scanner_detected',
                    'severity': 'medium',
                    'pattern': f'user_agent:{scanner}',
                })
                break

        # Suspicious path access
        path_lower = path.lower()
        for susp_path in self.SUSPICIOUS_PATHS:
            if susp_path in path_lower:
                # Web shell access is critical
                if 'shell' in path_lower and (method == 'POST' or 'cmd=' in path_lower):
                    attacks.append({
                        'type': 'web_shell',
                        'severity': 'critical',
                        'pattern': f'webshell_access:{susp_path}',
                    })
                else:
                    attacks.append({
                        'type': 'suspicious_path_access',
                        'severity': 'medium',
                        'pattern': f'path:{susp_path}',
                    })
                break

        return attacks

    @staticmethod
    def _convert_timestamp(raw_ts: str) -> str:
        """Convert Apache timestamp to ISO format."""
        try:
            from datetime import datetime
            # "04/Mar/2026:03:14:22 +0000"
            dt = datetime.strptime(raw_ts, "%d/%b/%Y:%H:%M:%S %z")
            return dt.isoformat()
        except (ValueError, TypeError):
            return raw_ts
