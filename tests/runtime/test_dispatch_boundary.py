"""Security regression: approved work must still satisfy the dispatch boundary."""
from pathlib import Path
from tempfile import TemporaryDirectory
import threading
import time
import unittest
from unittest.mock import patch

from agent_runtime.secure_lab import LabStore, LabRun

TMP = Path(__file__).resolve().parents[2] / '.data' / 'tmp'
TMP.mkdir(parents=True, exist_ok=True)


class DispatchBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory(dir=TMP)
        self.store = LabStore(Path(self.temp.name))

    def tearDown(self):
        self.temp.cleanup()

    def test_high_severity_example_reaches_incident_workflow(self):
        config = {'provider': 'fixture', 'profile': 'balanced', 'mode': 'task'}
        run_id = self.store.create('owner', config)
        worker = LabRun(self.store, run_id, config,
                        'Investigate the high severity incidents. Create a cited report and a local demo ticket.', '')
        with patch('agent_runtime.secure_lab.integrity_status', return_value={'valid': True, 'reason': 'APPROVED_SOURCE_MATCH'}):
            worker.run()
        result = self.store.get(run_id, 'owner')['result']
        self.assertEqual(result['status'], 'COMPLETED')
        self.assertEqual([step['tool'] for step in result['steps']], ['read_file', 'calculate', 'create_report', 'create_ticket'])
        self.assertIn('INC-103', (worker.directory / 'artifacts' / 'report.txt').read_text())

    def test_integrity_change_during_approval_prevents_write(self):
        config = {'provider': 'fixture', 'profile': 'approval', 'mode': 'task'}
        run_id = self.store.create('owner', config)
        worker = LabRun(self.store, run_id, config, 'Create a report', '')
        state = {'valid': True, 'reason': 'APPROVED_SOURCE_MATCH'}
        with patch('agent_runtime.secure_lab.integrity_status', side_effect=lambda: state.copy()):
            thread = threading.Thread(target=worker.run)
            thread.start()
            try:
                until = time.monotonic() + 10
                while worker.approval_preview() is None and thread.is_alive() and time.monotonic() < until:
                    time.sleep(.01)
                preview = worker.approval_preview()
                self.assertIsNotNone(preview)
                state.update(valid=False, reason='SOURCE_MANIFEST_MISMATCH')
                self.assertTrue(worker.authorize_approval(preview['request_id'], preview['action_sha256'], True))
                thread.join(10)
                self.assertFalse(thread.is_alive())
                result = self.store.get(run_id, 'owner')['result']
                self.assertEqual(result['enforcing_layer'], 'L7')
                self.assertEqual(result['reason'], 'SOURCE_MANIFEST_MISMATCH')
                self.assertFalse((worker.directory / 'artifacts' / 'report.txt').exists())
                self.assertFalse(any(step['tool'] == 'create_report' and step['executor_invoked'] for step in result['steps']))
                self.assertFalse(worker.authorize_approval(preview['request_id'], preview['action_sha256'], True))
            finally:
                worker.cancelled.set()
                thread.join(10)


if __name__ == '__main__':
    unittest.main()
