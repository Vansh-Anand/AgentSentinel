"""The witness key is separate from the API key even in local protocol tests."""

import json
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest

from agent_runtime.export_evidence import export_public_run
from agent_runtime.service import run_demo_task
from agent_runtime.witness_anchor import issue_anchor, verify_anchor


class WitnessAnchorTests(unittest.TestCase):
    def test_independently_pinned_witness_rejects_tampering_and_wrong_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            api_data = root / "api-data"
            run = run_demo_task("Summarize README.md", "fixture", api_data / "runtime-audit")
            bundle = root / "portable"
            export_public_run(run["run_id"], api_data, bundle)
            api_key = (api_data / "runtime-signing-key.pub").read_text().strip()
            witness_dir = root / "independent-witness"
            proof_path = root / "proof.json"
            proof = issue_anchor(run["run_id"], bundle, api_key, witness_dir, proof_path)
            witness_key = (witness_dir / "witness-key.pub").read_text().strip()

            valid = verify_anchor(run["run_id"], bundle, proof_path, api_key, witness_key,
                                  witness_ledger=witness_dir / "anchors.sqlite")
            self.assertTrue(valid["valid"], valid)
            self.assertEqual(valid["sequence"], 1)
            self.assertFalse(verify_anchor(run["run_id"], bundle, proof_path,
                                           api_key, "0" * 64)["valid"])
            self.assertFalse(verify_anchor(run["run_id"], bundle, proof_path,
                                           "0" * 64, witness_key)["valid"])

            forged = json.loads(proof_path.read_text())
            forged["entry"]["witnessed_at"] = "2000-01-01T00:00:00+00:00"
            changed_path = root / "changed-proof.json"
            changed_path.write_text(json.dumps(forged))
            self.assertFalse(verify_anchor(run["run_id"], bundle, changed_path,
                                           api_key, witness_key)["valid"])

            second_path = root / "same-proof.json"
            second = issue_anchor(run["run_id"], bundle, api_key, witness_dir, second_path)
            self.assertEqual(second, proof)
            receipt_path = bundle / "runtime-receipts" / f'{run["run_id"]}.json'
            receipt_path.write_bytes(receipt_path.read_bytes() + b" ")
            self.assertFalse(verify_anchor(run["run_id"], bundle, proof_path,
                                           api_key, witness_key)["valid"])

    def test_ledger_chain_rejects_deleted_prior_entry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            api_data = root / "api-data"
            witness_dir = root / "witness"
            anchored = []
            for index in range(2):
                run = run_demo_task(f"Summarize README.md {index}", "fixture",
                                    api_data / "runtime-audit")
                bundle = root / f"portable-{index}"
                export_public_run(run["run_id"], api_data, bundle)
                api_key = (api_data / "runtime-signing-key.pub").read_text().strip()
                proof_path = root / f"proof-{index}.json"
                proof = issue_anchor(run["run_id"], bundle, api_key, witness_dir, proof_path)
                anchored.append((run["run_id"], bundle, proof_path, api_key, proof))
            witness_key = (witness_dir / "witness-key.pub").read_text().strip()
            self.assertEqual(anchored[1][4]["entry"]["previous_hash"], anchored[0][4]["entry_hash"])
            ledger_path = witness_dir / "anchors.sqlite"
            self.assertTrue(verify_anchor(*anchored[1][:4], witness_key,
                                          witness_ledger=ledger_path)["valid"])

            with closing(sqlite3.connect(ledger_path)) as ledger:
                with ledger:
                    ledger.execute("DELETE FROM anchors WHERE sequence=1")
            self.assertFalse(verify_anchor(*anchored[1][:4], witness_key,
                                           witness_ledger=ledger_path)["valid"])


if __name__ == "__main__":
    unittest.main()
