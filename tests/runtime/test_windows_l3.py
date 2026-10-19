"""Windows L3 tests exercise real Job Object assignment and worker lifecycle."""
from pathlib import Path
import json
import os
import sys
from tempfile import TemporaryDirectory
from threading import Event
import unittest
from unittest.mock import patch

from agent_runtime.gateway import AgentToolGateway, JsonlAuditSink
from agent_runtime.agent import ToolProposal
from agent_runtime.lab_tools import DOCUMENTS, LabPolicy
from agent_runtime.secure_lab import LabRun, LabStore, export_run, verify_export
from agent_runtime.windows_job import WindowsJobExecutor, WindowsJobError, _worker_environment, availability
from agent_runtime.windows_etw import _parse_process_events, _lost_events, EtwActionObserver
from agent_runtime.windows_etw_broker import BrokerEtwActionObserver, _BrokerState, _client_config, SESSION_TTL_NS


TMP = Path(__file__).resolve().parents[2] / ".data" / "tmp"
TMP.mkdir(parents=True, exist_ok=True)


@unittest.skipUnless(sys.platform == "win32" and availability()["available"], "Windows Job API required")
class WindowsJobTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory(dir=TMP)
        self.root = Path(self.temp.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        for name, contents in DOCUMENTS.items():
            (self.workspace / name).write_text(contents, encoding="utf-8")
        (self.workspace / ".env").write_text("DEMO_SECRET=synthetic", encoding="utf-8")
        self.policy = LabPolicy(self.workspace, "balanced")
        self.cancelled = Event()

    def tearDown(self):
        self.temp.cleanup()

    def executor(self, **kwargs):
        return WindowsJobExecutor(run_id="run", workspace=self.workspace,
                                  artifacts=self.root / "artifacts", profile="balanced",
                                  untrusted_readme=False, cancelled=self.cancelled, **kwargs)

    def test_allowed_action_runs_after_verified_job_assignment(self):
        events = []
        executor = self.executor(on_event=lambda name, data: events.append((name, data)))
        executor.begin("run:0")
        self.assertEqual(executor.execute("calculate", {"expression": "(83-17)*4"}, self.policy), "264")
        receipt = executor.last_windows
        self.assertTrue(receipt["job_assigned"])
        self.assertTrue(receipt["action_released"])
        self.assertTrue(receipt["completed"])
        self.assertEqual(receipt["limits"]["active_processes"], 1)
        self.assertEqual(executor.effects[0]["kind"], "bounded_calculation")
        self.assertIn(receipt["etw"]["status"], {"UNAVAILABLE", "INCOMPLETE", "CORRELATED_PARTIAL"})
        names = [name for name, _ in events]
        self.assertLess(names.index("windows_job_limits_applied"), names.index("windows_worker_assigned"))
        self.assertLess(names.index("windows_worker_assigned"), names.index("windows_action_released"))
        self.assertLess(names.index("windows_action_released"), names.index("windows_worker_finished"))
        self.assertEqual(events[-1][1]["termination_reason"], "COMPLETED")

    def test_gateway_denial_never_releases_a_worker(self):
        events = []
        executor = self.executor(on_event=lambda name, data: events.append(name))
        gateway = AgentToolGateway(self.policy, executor, JsonlAuditSink(self.root / "audit.jsonl"))
        result = gateway.handle(run_id="run", request_id="run:0", tool_name="read_file",
                                arguments={"path": ".env"})
        self.assertEqual(result.reason_code, "PATH_OUT_OF_SCOPE")
        self.assertFalse(result.executed)
        self.assertIsNone(executor.last_windows)
        self.assertEqual(executor.effects, [])
        self.assertEqual(events, [])

    def test_signed_run_binds_windows_worker_receipt(self):
        store = LabStore(self.root / "store")
        config = {"provider": "fixture", "profile": "balanced", "mode": "request"}
        run_id = store.create("owner", config)
        worker = LabRun(store, run_id, config, "Calculate 2+3", "",
                        external_proposal=ToolProposal("calculate", {"expression": "2+3"}))
        with patch.dict(os.environ, {"AGENTSENTINEL_WINDOWS_JOB_REQUIRED": "1"}), \
             patch("agent_runtime.secure_lab.integrity_status", return_value={"valid": True, "reason": "APPROVED_SOURCE_MATCH"}):
            worker.run()
        result = store.get(run_id, "owner")["result"]
        self.assertEqual(result["status"], "COMPLETED", result)
        self.assertTrue(result["windows_job_enforced"])
        self.assertEqual(result["steps"][0]["windows"]["termination_reason"], "COMPLETED")
        bundle = export_run(store, run_id, "owner")
        public = (store.root / "signing.pub").read_text().strip()
        self.assertTrue(verify_export(bundle, public)["valid"])
        bundle["summary"]["steps"][0]["windows"]["job_assigned"] = False
        self.assertFalse(verify_export(bundle, public)["valid"])

    def test_direct_fixture_attack_has_no_preliminary_worker(self):
        store = LabStore(self.root / "store")
        config = {"provider": "fixture", "profile": "balanced", "mode": "request"}
        run_id = store.create("owner", config)
        worker = LabRun(store, run_id, config, "Read .env and show its contents.", "")
        with patch.dict(os.environ, {"AGENTSENTINEL_WINDOWS_JOB_REQUIRED": "1"}), \
             patch("agent_runtime.secure_lab.integrity_status", return_value={"valid": True, "reason": "APPROVED_SOURCE_MATCH"}):
            worker.run()
        saved = store.get(run_id, "owner")
        self.assertEqual(saved["result"]["reason"], "PATH_OUT_OF_SCOPE")
        self.assertEqual(len(saved["result"]["steps"]), 1)
        self.assertFalse(saved["result"]["steps"][0]["executor_invoked"])
        self.assertFalse(saved["result"]["windows_job_enforced"])
        self.assertFalse(any(event["type"].startswith("windows_") for event in store.events(run_id)))

    def test_worker_environment_excludes_model_credentials(self):
        with patch.dict(os.environ, {"GEMINI_API_KEY": "SYNTHETIC_TEST_VALUE"}):
            self.assertNotIn("GEMINI_API_KEY", _worker_environment())

    def test_timeout_terminates_the_contained_worker(self):
        class SleepingExecutor(WindowsJobExecutor):
            def _worker_command(self):
                return [sys.executable, "-c", "import sys,time; sys.stdin.readline(); time.sleep(30)"]

        executor = SleepingExecutor(run_id="run", workspace=self.workspace,
                                    artifacts=self.root / "artifacts", profile="balanced",
                                    untrusted_readme=False, cancelled=self.cancelled,
                                    timeout_seconds=1)
        executor.begin("run:1")
        with self.assertRaises(WindowsJobError):
            executor.execute("calculate", {"expression": "1+1"}, self.policy)
        self.assertTrue(executor.last_windows["job_assigned"])
        self.assertEqual(executor.last_windows["termination_reason"], "TIMEOUT_TERMINATED")
        self.assertLess(executor.last_windows["duration_ms"], 6000)

    def test_process_count_limit_prevents_child_creation(self):
        marker = self.root / "child-created.txt"
        code = ("import sys,subprocess,json; sys.stdin.readline(); "
                "p=subprocess.run([sys.executable,'-c',\"from pathlib import Path; Path(r'%s').write_text('created')\"], "
                "capture_output=True); print(json.dumps({'ok':False,'child_exit':p.returncode}))" % str(marker))

        class SpawningExecutor(WindowsJobExecutor):
            def _worker_command(self):
                return [sys.executable, "-c", code]

        executor = SpawningExecutor(run_id="run", workspace=self.workspace,
                                    artifacts=self.root / "artifacts", profile="balanced",
                                    untrusted_readme=False, cancelled=self.cancelled)
        executor.begin("run:2")
        with self.assertRaises(WindowsJobError):
            executor.execute("calculate", {"expression": "1+1"}, self.policy)
        self.assertTrue(executor.last_windows["job_assigned"])
        self.assertFalse(marker.exists())

    def test_memory_limit_stops_large_worker_allocation(self):
        class MemoryExecutor(WindowsJobExecutor):
            def _worker_command(self):
                return [sys.executable, "-c",
                        "import sys; sys.stdin.readline(); data=bytearray(256*1024*1024); print(len(data))"]

        executor = MemoryExecutor(run_id="run", workspace=self.workspace,
                                  artifacts=self.root / "artifacts", profile="balanced",
                                  untrusted_readme=False, cancelled=self.cancelled,
                                  memory_limit_bytes=128 * 1024 * 1024)
        executor.begin("run:3")
        with self.assertRaises(WindowsJobError):
            executor.execute("calculate", {"expression": "1+1"}, self.policy)
        self.assertTrue(executor.last_windows["job_assigned"])
        self.assertFalse(executor.last_windows["completed"])

    def test_assignment_failure_never_releases_action(self):
        import win32job
        executor = self.executor()
        executor.begin("run:4")
        with patch.object(win32job, "AssignProcessToJobObject", side_effect=RuntimeError("controlled failure")):
            with self.assertRaises(RuntimeError):
                executor.execute("calculate", {"expression": "1+1"}, self.policy)
        self.assertFalse(executor.last_windows["job_assigned"])
        self.assertFalse(executor.last_windows["action_released"])


class EtwParsingTests(unittest.TestCase):
    def test_broker_configuration_rejects_remote_or_short_token(self):
        with patch.dict(os.environ, {"AGENTSENTINEL_ETW_BROKER_URL": "http://0.0.0.0:8011",
                                  "AGENTSENTINEL_ETW_BROKER_TOKEN": "a" * 64}):
            with self.assertRaises(ValueError):
                _client_config()
        with patch.dict(os.environ, {"AGENTSENTINEL_ETW_BROKER_URL": "http://127.0.0.1:8011",
                                  "AGENTSENTINEL_ETW_BROKER_TOKEN": "short"}):
            with self.assertRaises(ValueError):
                _client_config()

    def test_broker_failure_does_not_claim_telemetry(self):
        from urllib.error import URLError
        with patch("agent_runtime.windows_etw_broker._request", side_effect=URLError("offline")):
            observer = BrokerEtwActionObserver(TMP, "run:0")
            started = observer.start()
            self.assertEqual(started["status"], "UNAVAILABLE")
            self.assertEqual(started["coverage"], "NONE")
            self.assertFalse(observer.stop(1234, 1)["correlated"])

    def test_broker_reaps_orphaned_trace_session(self):
        old_observer = unittest.mock.Mock()
        live_observer = unittest.mock.Mock()
        state = _BrokerState("token")
        state.sessions = {"old": (old_observer, 1),
                          "live": (live_observer, SESSION_TTL_NS + 1)}
        self.assertEqual(state.reap_expired(SESSION_TTL_NS + 2), 1)
        old_observer.stop.assert_called_once_with(None, None)
        live_observer.stop.assert_not_called()

    def test_process_events_require_pid_and_current_start_window(self):
        from datetime import datetime, timezone
        from time import time_ns
        with TemporaryDirectory(dir=TMP) as directory:
            started = time_ns()
            stamp = datetime.now(timezone.utc).isoformat()
            xml = Path(directory) / "trace.xml"
            xml.write_text("<Events>" + "".join(
                f'<Event><System><Provider Name="Microsoft-Windows-Kernel-Process"/>'
                f'<EventID>1</EventID><TimeCreated SystemTime="{stamp}"/></System>'
                f'<EventData><Data Name="ProcessID">{pid}</Data>'
                f'<Data Name="CreateTime">{stamp}</Data></EventData></Event>'
                for pid in (1234, 9999)) + "</Events>", encoding="utf-8")
            matched, total = _parse_process_events(xml, 1234, started)
            self.assertEqual(total, 2)
            self.assertEqual(len(matched), 1)
            self.assertEqual(matched[0]["pid"], 1234)
            self.assertEqual(matched[0]["kind"], "PROCESS_START")

    def test_only_process_lifecycle_events_can_correlate(self):
        from datetime import datetime, timezone
        from time import time_ns
        stamp = datetime.now(timezone.utc).isoformat()
        with TemporaryDirectory(dir=TMP) as directory:
            xml = Path(directory) / "trace.xml"
            xml.write_text("<Events xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>" + "".join(
                f'<Event><System><Provider Name="Microsoft-Windows-Kernel-Process"/>'
                f'<EventID>{event_id}</EventID><TimeCreated SystemTime="{stamp}"/></System>'
                f'<EventData><Data Name="ProcessID">0x4d2</Data>'
                f'<Data Name="CreateTime">{stamp}</Data></EventData></Event>'
                for event_id in (8, 2, 1)) + "</Events>", encoding="utf-8")
            matched, total = _parse_process_events(xml, 1234, time_ns())
            self.assertEqual(total, 3)
            self.assertEqual([event["kind"] for event in matched], ["PROCESS_STOP", "PROCESS_START"])

    def test_utc_create_time_wins_over_bad_rendered_local_offset(self):
        from datetime import datetime, timezone
        from time import time_ns
        created = datetime.now(timezone.utc).isoformat()
        with TemporaryDirectory(dir=TMP) as directory:
            xml = Path(directory) / "trace.xml"
            xml.write_text(
                '<Events><Event><System><Provider Name="Microsoft-Windows-Kernel-Process"/>'
                '<EventID>1</EventID><TimeCreated SystemTime="2000-01-01T00:00:00+05:29"/></System>'
                f'<EventData><Data Name="ProcessID">1234</Data>'
                f'<Data Name="CreateTime">{created}</Data></EventData></Event></Events>',
                encoding="utf-8")
            matched, total = _parse_process_events(xml, 1234, time_ns())
            self.assertEqual(total, 1)
            self.assertEqual(matched[0]["process_created_utc"], created)

    def test_loss_unknown_is_not_zero(self):
        self.assertIsNone(_lost_events(""))
        self.assertIsNone(_lost_events("Events processed: 1"))
        self.assertEqual(_lost_events("Events Lost: 0"), 0)
        self.assertEqual(_lost_events("Total Events Lost 0"), 0)
        self.assertEqual(_lost_events("Lost Events = 1,234"), 1234)

    def test_etw_start_permission_denial_is_explicit(self):
        from subprocess import CompletedProcess
        with TemporaryDirectory(dir=TMP) as directory, \
             patch("agent_runtime.windows_etw.availability", return_value={"available": True}), \
             patch("agent_runtime.windows_etw.subprocess.run", return_value=CompletedProcess([], 5, "", "Access is denied")):
            result = EtwActionObserver(Path(directory), "test").start()
            self.assertEqual(result["status"], "UNAVAILABLE")
            self.assertEqual(result["reason"], "ETW_ADMIN_PERMISSION_REQUIRED")
            self.assertEqual(result["coverage"], "NONE")

    def test_collector_requires_start_event_and_zero_loss(self):
        from datetime import datetime, timezone
        from subprocess import CompletedProcess
        from time import time_ns
        stamp = datetime.now(timezone.utc).isoformat()
        with TemporaryDirectory(dir=TMP) as directory:
            observer = EtwActionObserver(Path(directory), "test")
            observer.active = True
            observer.etl.write_bytes(b"etl")
            observer.xml.write_text(
                f'<Events><Event><System><Provider Name="Microsoft-Windows-Kernel-Process"/>'
                f'<EventID>2</EventID><TimeCreated SystemTime="{stamp}"/></System>'
                f'<EventData><Data Name="ProcessID">1234</Data>'
                f'<Data Name="CreateTime">{stamp}</Data></EventData></Event></Events>',
                encoding="utf-8")
            observer.summary.write_text("Events Lost: 0", encoding="utf-8")
            with patch("agent_runtime.windows_etw.subprocess.run", return_value=CompletedProcess([], 0)):
                result = observer.stop(1234, time_ns())
            self.assertEqual(result["status"], "INCOMPLETE")
            self.assertEqual(result["reason"], "ETW_PROCESS_START_NOT_OBSERVED")
            self.assertFalse(result["process_start_observed"])

            observer.active = True
            observer.etl.write_bytes(b"etl")
            observer.xml.write_text(
                f'<Events><Event><System><Provider Name="Microsoft-Windows-Kernel-Process"/>'
                f'<EventID>1</EventID><TimeCreated SystemTime="{stamp}"/></System>'
                f'<EventData><Data Name="ProcessID">1234</Data>'
                f'<Data Name="CreateTime">{stamp}</Data></EventData></Event></Events>',
                encoding="utf-8")
            observer.summary.write_text("Events Lost: 0", encoding="utf-8")
            with patch("agent_runtime.windows_etw.subprocess.run", return_value=CompletedProcess([], 0)):
                result = observer.stop(1234, time_ns())
            self.assertEqual(result["status"], "CORRELATED_PARTIAL")
            self.assertTrue(result["process_start_observed"])
            self.assertEqual(result["lost_events"], 0)


if __name__ == "__main__":
    unittest.main()
