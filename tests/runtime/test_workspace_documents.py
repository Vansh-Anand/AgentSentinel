"""Real upload/snapshot and worker boundary regressions, no model required."""
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from agent_runtime.workspace_documents import DocumentStore, DocumentError, snapshot
from agent_runtime.lab_tools import LabPolicy, LabExecutor, ExecutionLimit
from agent_runtime.native_worker import execute_packet
from agent_runtime.lab_provenance import ProvenanceLedger


class WorkspaceDocumentsTests(unittest.TestCase):
    def test_citation_validation_normalizes_case(self):
        ledger = ProvenanceLedger()
        self.assertEqual(ledger.unknown_citations('src-invented-reference'), ['SRC-INVENTED-REFERENCE'])
        self.assertEqual(ProvenanceLedger('USER_PROVIDED_UNTRUSTED').derived_classification(), 'USER_PROVIDED_UNTRUSTED')
    def setUp(self):
        self.temp = TemporaryDirectory(dir=Path(__file__).resolve().parents[2] / '.data' / 'tmp')
        self.root = Path(self.temp.name)
        self.store = DocumentStore(self.root)

    def tearDown(self):
        self.temp.cleanup()

    def test_ownership_delete_and_immutable_snapshot(self):
        metadata = self.store.upload('alice', 'events.csv', 'severity,count\nhigh,7\nlow,4\n')
        self.assertEqual(self.store.list('bob'), [])
        with self.assertRaises(DocumentError): self.store.selected('bob', [metadata['id']])
        with self.assertRaises(DocumentError): self.store.delete('bob', metadata['id'])
        catalog = snapshot(self.store.selected('alice', [metadata['id']]), self.root / 'snapshot')
        self.store.delete('alice', metadata['id'])
        self.assertEqual(self.store.list('alice'), [])
        policy = LabPolicy(self.root / 'snapshot', 'balanced', catalog)
        executor = LabExecutor(self.root / 'artifacts')
        value = executor.execute('read_file', {'path': metadata['id']}, policy)
        self.assertIn('high,7', value)
        self.assertEqual(executor.effects[0]['sha256'], metadata['sha256'])
        self.assertFalse(policy.decide('read_file', {'path': '../outside'}).allowed)
        self.assertFalse(policy.decide('read_file', {'path': 'events.csv'}).allowed)
        self.assertFalse(policy.decide('create_ticket', {'title': 'x', 'body': value}).allowed)

    def test_upload_validation_and_quotas(self):
        for name, content in [('../escape.md', 'text'), ('x.pdf', 'text'), ('x.md', '\x00bad'), ('x.txt', 'é' * 9000), ('x.md', ' ')]:
            with self.subTest(name=name, length=len(content)):
                with self.assertRaises(DocumentError): self.store.upload('alice', name, content)
        for index in range(16): self.store.upload('alice', f'{index}.txt', 'x')
        with self.assertRaises(DocumentError): self.store.upload('alice', 'extra.txt', 'x')
        with self.assertRaises(DocumentError): self.store.selected('alice', ['../escape'])

    def test_worker_policy_catalog_and_changed_snapshot(self):
        metadata = self.store.upload('alice', 'notes.md', '# Operations\nRetention is 47 days.')
        catalog = snapshot(self.store.selected('alice', [metadata['id']]), self.root / 'snapshot')
        policy = LabPolicy(self.root / 'snapshot', 'balanced', catalog)
        packet = {'workspace': str(policy.workspace), 'artifacts': str(self.root / 'artifacts'),
                  'profile': 'balanced', 'policy_sha256': policy.policy_hash, 'catalog': catalog,
                  'untrusted_readme': False, 'tool': 'read_file', 'arguments': {'path': metadata['id']}}
        result = execute_packet(packet)
        self.assertIn('47 days', result['output'])
        self.assertEqual(result['effects'][0]['classification'], 'USER_UPLOADED_UNTRUSTED')
        (policy.workspace / metadata['id']).write_text('changed', encoding='utf-8')
        with self.assertRaises(ExecutionLimit): execute_packet(packet)
        packet['catalog'] = {}
        with self.assertRaises(PermissionError): execute_packet(packet)

    def test_search_report_and_empty_workspace(self):
        metadata = self.store.upload('alice', 'notes.txt', 'Critical incidents: 7')
        catalog = snapshot(self.store.selected('alice', [metadata['id']]), self.root / 'snapshot')
        policy = LabPolicy(self.root / 'snapshot', 'balanced', catalog)
        executor = LabExecutor(self.root / 'artifacts')
        found = json.loads(executor.execute('search_documents', {'query': 'Critical'}, policy))
        self.assertEqual(found[0]['source_id'], metadata['source_id'])
        executor.execute('create_report', {'content': 'Seven incidents. ' + metadata['source_id']}, policy)
        self.assertTrue((self.root / 'artifacts' / 'report.txt').is_file())
        empty = LabPolicy(self.root / 'snapshot', 'balanced', {})
        self.assertFalse(empty.decide('read_file', {'path': metadata['id']}).allowed)
        self.assertTrue(empty.decide('calculate', {'expression': '2+3'}).allowed)


if __name__ == '__main__': unittest.main()
