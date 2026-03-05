"""
Tests for Web Server Log Parser
Validates detection of SQL injection, XSS, path traversal, web shells, and scanners.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from parsers.web_parser import WebLogParser


class TestWebLogParser:
    """Test suite for WebLogParser."""

    def setup_method(self):
        self.parser = WebLogParser()

    # ─── SQL Injection Tests ──────────────────────────────────────────

    def test_detect_sql_injection_union(self):
        log = '185.22.91.44 - - [04/Mar/2026:03:14:49 +0000] "GET /api/users?id=1%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1" 200 5678 "-" "Mozilla/5.0"'
        events = self.parser.parse(log)
        assert any(e['event_type'] == 'sql_injection' for e in events)

    def test_detect_sql_injection_or_1_1(self):
        log = "185.22.91.44 - - [04/Mar/2026:03:14:22 +0000] \"GET /login.php?username=admin'%20OR%201=1--&password=pass HTTP/1.1\" 200 3456 \"-\" \"Mozilla/5.0\""
        events = self.parser.parse(log)
        assert any(e['event_type'] == 'sql_injection' for e in events)

    def test_detect_sql_injection_drop_table(self):
        log = '103.45.67.89 - - [04/Mar/2026:03:17:44 +0000] "GET /products?category=1;%20DROP%20TABLE%20users;-- HTTP/1.1" 500 234 "-" "Mozilla/5.0"'
        events = self.parser.parse(log)
        assert any(e['event_type'] == 'sql_injection' for e in events)

    # ─── XSS Tests ────────────────────────────────────────────────────

    def test_detect_xss_script_tag(self):
        log = "185.22.91.44 - - [04/Mar/2026:03:14:25 +0000] \"GET /search?q=<script>alert('XSS')</script> HTTP/1.1\" 200 2345 \"-\" \"Mozilla/5.0\""
        events = self.parser.parse(log)
        assert any(e['event_type'] == 'xss_attempt' for e in events)

    def test_detect_xss_onerror(self):
        log = '103.45.67.89 - - [04/Mar/2026:03:17:50 +0000] "GET /profile?name=<img%20src=x%20onerror=alert(document.cookie)> HTTP/1.1" 200 3456 "-" "Mozilla/5.0"'
        events = self.parser.parse(log)
        assert any(e['event_type'] == 'xss_attempt' for e in events)

    # ─── Path Traversal Tests ─────────────────────────────────────────

    def test_detect_path_traversal(self):
        log = '185.22.91.44 - - [04/Mar/2026:03:14:28 +0000] "GET /index.php?page=../../../../etc/passwd HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'
        events = self.parser.parse(log)
        assert any(e['event_type'] == 'path_traversal' for e in events)

    # ─── Command Injection Tests ──────────────────────────────────────

    def test_detect_command_injection(self):
        log = '103.45.67.89 - - [04/Mar/2026:03:17:56 +0000] "GET /cgi-bin/test.cgi?cmd=id HTTP/1.1" 200 56 "-" "Nikto/2.1.6"'
        events = self.parser.parse(log)
        assert any(e['event_type'] == 'command_injection' for e in events)

    # ─── Scanner Detection Tests ──────────────────────────────────────

    def test_detect_sqlmap_scanner(self):
        log = '185.22.91.44 - - [04/Mar/2026:03:14:31 +0000] "POST /login.php HTTP/1.1" 200 4567 "-" "sqlmap/1.5.2"'
        events = self.parser.parse(log)
        assert any(e['event_type'] == 'scanner_detected' for e in events)

    def test_detect_dirbuster(self):
        log = '185.22.91.44 - - [04/Mar/2026:03:14:37 +0000] "GET /db/phpmyadmin/ HTTP/1.1" 404 456 "-" "DirBuster-1.0-RC1"'
        events = self.parser.parse(log)
        assert any(e['event_type'] == 'scanner_detected' for e in events)

    # ─── Web Shell Tests ──────────────────────────────────────────────

    def test_detect_web_shell_post(self):
        log = '91.134.55.77 - - [04/Mar/2026:05:00:00 +0000] "POST /uploads/shell.php HTTP/1.1" 200 45 "-" "Mozilla/5.0"'
        events = self.parser.parse(log)
        assert any(e['event_type'] == 'web_shell' for e in events)

    def test_detect_web_shell_cmd(self):
        log = '91.134.55.77 - - [04/Mar/2026:05:00:05 +0000] "GET /uploads/shell.php?cmd=cat%20/etc/passwd HTTP/1.1" 200 2345 "-" "Mozilla/5.0"'
        events = self.parser.parse(log)
        assert any(e['event_type'] == 'web_shell' for e in events)

    # ─── Full Sample File Test ────────────────────────────────────────

    def test_parse_sample_apache_log(self):
        sample_path = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                                   'logs', 'sample_logs', 'apache_access.log')
        with open(sample_path, 'r') as f:
            content = f.read()
        events = self.parser.parse(content)
        assert len(events) > 5
        event_types = set(e['event_type'] for e in events)
        assert 'sql_injection' in event_types
        assert 'xss_attempt' in event_types

    # ─── Benign Traffic Not Flagged ───────────────────────────────────

    def test_normal_request_no_events(self):
        log = '10.0.1.55 - developer [04/Mar/2026:03:20:00 +0000] "GET /dashboard HTTP/1.1" 200 8765 "-" "Mozilla/5.0 (X11; Linux x86_64)"'
        events = self.parser.parse(log)
        assert len(events) == 0
