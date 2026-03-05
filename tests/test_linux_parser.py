"""
Tests for Linux Log Parser
Validates extraction from auth.log, syslog, and firewall logs.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from parsers.linux_parser import LinuxLogParser


class TestLinuxLogParser:
    """Test suite for LinuxLogParser."""

    def setup_method(self):
        self.parser = LinuxLogParser()

    # ─── SSH Failed Password Tests ────────────────────────────────────

    def test_parse_failed_password(self):
        log = 'Mar  4 03:14:22 server01 sshd[12401]: Failed password for root from 185.22.91.44 port 44322 ssh2'
        events = self.parser.parse(log, 'linux_auth')
        assert len(events) == 1
        event = events[0]
        assert event['event_type'] == 'failed_login'
        assert event['user'] == 'root'
        assert event['source_ip'] == '185.22.91.44'
        assert event['os'] == 'linux'
        assert event['log_category'] == 'authentication'

    def test_parse_failed_password_invalid_user(self):
        log = 'Mar  4 03:17:44 server01 sshd[12410]: Failed password for invalid user test from 103.45.67.89 port 55201 ssh2'
        events = self.parser.parse(log, 'linux_auth')
        assert len(events) == 1
        assert events[0]['user'] == 'test'
        assert events[0]['details']['invalid_user'] is True

    def test_multiple_failed_passwords(self):
        log = """Mar  4 03:14:22 server01 sshd[12401]: Failed password for root from 185.22.91.44 port 44322 ssh2
Mar  4 03:14:25 server01 sshd[12401]: Failed password for root from 185.22.91.44 port 44322 ssh2
Mar  4 03:14:28 server01 sshd[12401]: Failed password for root from 185.22.91.44 port 44322 ssh2"""
        events = self.parser.parse(log, 'linux_auth')
        assert len(events) == 3
        assert all(e['event_type'] == 'failed_login' for e in events)

    # ─── SSH Accepted Login Tests ─────────────────────────────────────

    def test_parse_accepted_login(self):
        log = 'Mar  4 03:20:11 server01 sshd[12500]: Accepted password for developer from 10.0.1.55 port 60122 ssh2'
        events = self.parser.parse(log, 'linux_auth')
        assert len(events) == 1
        assert events[0]['event_type'] == 'successful_login'
        assert events[0]['user'] == 'developer'
        assert events[0]['severity'] == 'low'

    def test_parse_accepted_publickey(self):
        log = 'Mar  4 04:01:15 server01 sshd[12600]: Accepted publickey for sysadmin from 10.0.1.10 port 61000 ssh2'
        events = self.parser.parse(log, 'linux_auth')
        assert len(events) == 1
        assert events[0]['details']['auth_type'] == 'publickey'

    # ─── Sudo Tests ───────────────────────────────────────────────────

    def test_parse_suspicious_sudo(self):
        log = 'Mar  4 03:25:30 server01 sudo: developer : TTY=pts/0 ; PWD=/home/developer ; USER=root ; COMMAND=/bin/cat /etc/shadow'
        events = self.parser.parse(log, 'linux_auth')
        assert len(events) == 1
        assert events[0]['event_type'] == 'suspicious_command'
        assert events[0]['severity'] == 'high'
        assert '/etc/shadow' in events[0]['command']

    def test_parse_normal_sudo(self):
        log = 'Mar  4 03:25:30 server01 sudo: admin : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/apt update'
        events = self.parser.parse(log, 'linux_auth')
        assert len(events) == 1
        assert events[0]['event_type'] == 'sudo_execution'
        assert events[0]['severity'] == 'low'

    # ─── User Account Creation Tests ──────────────────────────────────

    def test_parse_useradd_uid0(self):
        log = 'Mar  4 06:30:00 server01 useradd[13000]: new user: name=backdoor_user, UID=0, GID=0, home=/root, shell=/bin/bash'
        events = self.parser.parse(log, 'linux_auth')
        assert len(events) == 1
        assert events[0]['event_type'] == 'account_creation'
        assert events[0]['severity'] == 'critical'
        assert events[0]['details']['uid'] == 0

    # ─── UFW Firewall Tests ──────────────────────────────────────────

    def test_parse_ufw_block(self):
        log = 'Mar  4 02:15:33 server01 kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:16:3e:5e:6c:00 SRC=185.22.91.44 DST=10.0.1.20 LEN=44 TTL=50 PROTO=TCP SPT=44888 DPT=22 WINDOW=1024 SYN URGP=0'
        events = self.parser.parse(log, 'firewall')
        assert len(events) == 1
        assert events[0]['event_type'] == 'firewall_block'
        assert events[0]['source_ip'] == '185.22.91.44'
        assert events[0]['destination_port'] == 22

    # ─── Service Failure Tests ────────────────────────────────────────

    def test_parse_service_failure(self):
        log = 'Mar  4 03:00:15 server01 systemd[1]: mysql.service: Failed with result \'signal\'.'
        events = self.parser.parse(log, 'linux_syslog')
        assert len(events) == 1
        assert events[0]['event_type'] == 'service_failure'

    # ─── Suspicious Cron Tests ────────────────────────────────────────

    def test_parse_suspicious_cron(self):
        log = 'Mar  4 04:30:00 server01 CRON[12000]: (root) CMD (/tmp/.hidden_cron.sh)'
        events = self.parser.parse(log, 'linux_syslog')
        assert len(events) == 1
        assert events[0]['event_type'] == 'suspicious_cron'
        assert events[0]['severity'] == 'high'

    # ─── Full Sample File Test ────────────────────────────────────────

    def test_parse_sample_auth_log(self):
        sample_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs', 'sample_logs', 'linux_auth.log')
        with open(sample_path, 'r') as f:
            content = f.read()
        events = self.parser.parse(content, 'linux_auth')
        assert len(events) > 10  # Should detect many events
        event_types = set(e['event_type'] for e in events)
        assert 'failed_login' in event_types
        assert 'successful_login' in event_types
