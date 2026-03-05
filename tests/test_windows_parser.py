"""
Tests for Windows Event Log Parser
Validates parsing of Event IDs 4624, 4625, 4672, 4688.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from parsers.windows_parser import WindowsLogParser


class TestWindowsLogParser:
    """Test suite for WindowsLogParser."""

    def setup_method(self):
        self.parser = WindowsLogParser()

    # ─── Event 4625: Failed Login ─────────────────────────────────────

    def test_parse_4625_failed_login(self):
        log = ('TimeCreated: 2026-03-04T03:14:22.000Z | EventID: 4625 | Level: Information | '
               'Computer: WORKSTATION01 | Channel: Security | Provider: Microsoft-Windows-Security-Auditing | '
               'Message: An account failed to log on. Subject: Security ID: S-1-0-0. Logon Type: 3. '
               'Account: Administrator. Source Network Address: 185.22.91.44. '
               'Failure Reason: Unknown user name or bad password.')
        events = self.parser.parse(log)
        assert len(events) == 1
        event = events[0]
        assert event['event_type'] == 'failed_login'
        assert event['user'] == 'Administrator'
        assert event['source_ip'] == '185.22.91.44'
        assert event['os'] == 'windows'
        assert event['details']['event_id'] == 4625

    # ─── Event 4624: Successful Login ─────────────────────────────────

    def test_parse_4624_successful_login(self):
        log = ('TimeCreated: 2026-03-04T03:20:00.000Z | EventID: 4624 | Level: Information | '
               'Computer: WORKSTATION01 | Channel: Security | Provider: Microsoft-Windows-Security-Auditing | '
               'Message: An account was successfully logged on. Subject: Security ID: S-1-5-18. '
               'Logon Type: 10. Account: jsmith. Source Network Address: 10.0.1.55. Logon Process: User32.')
        events = self.parser.parse(log)
        assert len(events) == 1
        assert events[0]['event_type'] == 'successful_login'
        assert events[0]['user'] == 'jsmith'
        assert events[0]['details']['logon_type'] == '10'
        assert events[0]['details']['logon_type_desc'] == 'RemoteInteractive (RDP)'

    # ─── Event 4672: Privilege Escalation ─────────────────────────────

    def test_parse_4672_privilege_escalation(self):
        log = ('TimeCreated: 2026-03-04T03:25:00.000Z | EventID: 4672 | Level: Information | '
               'Computer: WORKSTATION01 | Channel: Security | Provider: Microsoft-Windows-Security-Auditing | '
               'Message: Special privileges assigned to new logon. Subject: Security ID: S-1-5-21-3623811015. '
               'Account: jsmith. Privileges: SeDebugPrivilege, SeTakeOwnershipPrivilege, SeBackupPrivilege.')
        events = self.parser.parse(log)
        assert len(events) == 1
        assert events[0]['event_type'] == 'privilege_escalation'
        assert events[0]['severity'] == 'high'
        assert events[0]['details']['dangerous_privileges'] is True

    # ─── Event 4688: Process Creation ─────────────────────────────────

    def test_parse_4688_suspicious_process(self):
        log = ('TimeCreated: 2026-03-04T03:30:00.000Z | EventID: 4688 | Level: Information | '
               'Computer: WORKSTATION01 | Channel: Security | Provider: Microsoft-Windows-Security-Auditing | '
               'Message: A new process has been created. Subject: Security ID: S-1-5-21-3623811015. '
               'Account: jsmith. New Process Name: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe. '
               'Process Command Line: powershell.exe -ep bypass -nop -enc SQBFAFgAIAAoA...')
        events = self.parser.parse(log)
        assert len(events) == 1
        assert events[0]['event_type'] == 'suspicious_process'
        assert events[0]['severity'] in ('high', 'critical')

    def test_parse_4688_credential_dump(self):
        log = ('TimeCreated: 2026-03-04T03:31:00.000Z | EventID: 4688 | Level: Information | '
               'Computer: WORKSTATION01 | Channel: Security | Provider: Microsoft-Windows-Security-Auditing | '
               'Message: A new process has been created. Subject: Security ID: S-1-5-18. '
               'Account: SYSTEM. New Process Name: C:\\Windows\\System32\\rundll32.exe. '
               'Process Command Line: rundll32.exe comsvcs.dll MiniDump 672 C:\\temp\\lsass.dmp full')
        events = self.parser.parse(log)
        assert len(events) == 1
        assert events[0]['event_type'] == 'suspicious_process'
        assert events[0]['severity'] == 'critical'

    # ─── Full Sample File Test ────────────────────────────────────────

    def test_parse_sample_windows_log(self):
        sample_path = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                                   'logs', 'sample_logs', 'windows_security.log')
        with open(sample_path, 'r') as f:
            content = f.read()
        events = self.parser.parse(content)
        assert len(events) > 5
        event_types = set(e['event_type'] for e in events)
        assert 'failed_login' in event_types
        assert 'successful_login' in event_types
        assert 'privilege_escalation' in event_types

    # ─── Multiple Events Test ─────────────────────────────────────────

    def test_parse_multiple_4625(self):
        lines = []
        for i in range(5):
            lines.append(
                f'TimeCreated: 2026-03-04T03:14:{20+i}.000Z | EventID: 4625 | Level: Information | '
                f'Computer: WS01 | Channel: Security | Provider: Microsoft-Windows-Security-Auditing | '
                f'Message: An account failed to log on. Logon Type: 3. Account: admin. '
                f'Source Network Address: 10.0.0.{i}. Failure Reason: Bad password.'
            )
        events = self.parser.parse('\n'.join(lines))
        assert len(events) == 5
        assert all(e['event_type'] == 'failed_login' for e in events)
