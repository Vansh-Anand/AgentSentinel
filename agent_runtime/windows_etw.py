"""Optional Windows ETW process observation correlated to one tool worker.

ETW is observation after the fact. This collector uses the documented Windows
logman/tracerpt tools. Missing privilege, events, or loss information always
produces partial or unavailable coverage, never a clean-effect assertion.
"""
from __future__ import annotations

from datetime import datetime
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import uuid
import xml.etree.ElementTree as ET


PROVIDER = "Microsoft-Windows-Kernel-Process"
PROVIDER_GUID = "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716"
PROCESS_KEYWORD = "0x10"


def availability() -> dict:
    if sys.platform != "win32":
        return {"available": False, "reason": "WINDOWS_HOST_REQUIRED"}
    if not shutil.which("logman") or not shutil.which("tracerpt"):
        return {"available": False, "reason": "ETW_COMMAND_TOOLS_UNAVAILABLE"}
    return {"available": True, "reason": "ETW_TOOLS_INSTALLED_PRIVILEGE_UNCHECKED"}


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _event_field(event: ET.Element, names: set[str]) -> str | None:
    for element in event.iter():
        if _local(element.tag).lower() == "data" and element.attrib.get("Name", "").lower() in names:
            return (element.text or "").strip()
    return None


def _event_system_field(event: ET.Element, name: str) -> str | None:
    system = next((item for item in event if _local(item.tag).lower() == "system"), None)
    if system is None:
        return None
    field = next((item for item in system if _local(item.tag).lower() == name.lower()), None)
    return (field.text or "").strip() if field is not None else None


def _utc_timestamp_ns(value: str | None) -> int | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return None
        return int(parsed.timestamp() * 1e9)
    except ValueError:
        return None


def _parse_process_events(xml_path: Path, pid: int, started_ns: int) -> tuple[list[dict], int]:
    if xml_path.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("ETW_XML_SIZE_LIMIT")
    root = ET.parse(xml_path).getroot()
    matches: list[dict] = []
    total = 0
    for event in root.iter():
        if _local(event.tag).lower() != "event":
            continue
        total += 1
        provider = next((item for item in event.iter() if _local(item.tag) == "Provider"), None)
        if provider is None or (provider.attrib.get("Name", "") != PROVIDER and
                                provider.attrib.get("Guid", "").strip("{}").lower() != PROVIDER_GUID):
            continue
        raw_pid = _event_field(event, {"processid", "process_id", "targetprocessid", "pid"})
        if raw_pid is None:
            continue
        try:
            event_pid = int(raw_pid, 0)
        except ValueError:
            continue
        if event_pid != pid:
            continue
        event_id = _event_system_field(event, "EventID")
        # This provider uses event 1 for process start and 2 for process stop.
        # A same-PID event from a different category is not process lifecycle proof.
        if event_id not in {"1", "2"}:
            continue
        # The provider's CreateTime is UTC. tracerpt may render the generic
        # TimeCreated header with a rounded local UTC offset (observed +05:29
        # for a +05:30 host), so it cannot be the correlation clock.
        created_utc = _event_field(event, {"createtime"})
        created_ns = _utc_timestamp_ns(created_utc)
        if created_ns is None or not (started_ns - 2_000_000_000 <= created_ns <= started_ns + 35_000_000_000):
            continue
        event_time = next((item.attrib.get("SystemTime") for item in event.iter()
                           if _local(item.tag) == "TimeCreated"), None)
        matches.append({"kind": "PROCESS_START" if event_id == "1" else "PROCESS_STOP",
                        "pid": pid, "event_id": event_id, "time": event_time,
                        "process_created_utc": created_utc})
        if len(matches) >= 32:
            break
    return matches, total


def _lost_events(summary: str) -> int | None:
    # tracerpt's localized/free-form summary is not a stable API. Unknown is
    # deliberately distinct from zero, including when no summary was written.
    for pattern in (r"(?:events\s+lost|lost\s+events)\s*[:=]\s*([\d,]+)",
                    r"(?:events\s+lost|lost\s+events)\s+([\d,]+)"):
        match = re.search(pattern, summary, re.I)
        if match:
            return int(match.group(1).replace(",", ""))
    return None


def _diagnostic_events(xml_path: Path) -> list[dict]:
    """Only schema and numeric IDs for an explicit local self-test; no paths/text."""
    root = ET.parse(xml_path).getroot()
    events = []
    for event in root.iter():
        if _local(event.tag).lower() != "event":
            continue
        provider = next((item for item in event.iter() if _local(item.tag) == "Provider"), None)
        stamp = next((item.attrib.get("SystemTime") for item in event.iter()
                      if _local(item.tag) == "TimeCreated"), None)
        events.append({"provider": provider.attrib.get("Name") if provider is not None else None,
                       "event_id": _event_system_field(event, "EventID"),
                       "payload_pid": _event_field(event, {"processid", "process_id", "targetprocessid", "pid"}),
                       "create_time": _event_field(event, {"createtime"}),
                       "time": stamp})
        if len(events) >= 12:
            break
    return events


class EtwActionObserver:
    def __init__(self, directory: Path, request_id: str, *, diagnostic: bool = False):
        self.directory = directory
        self.request_id = request_id
        self.name = "AgentSentinel-" + uuid.uuid4().hex
        self.etl = directory / (self.name + ".etl")
        self.xml = directory / (self.name + ".xml")
        self.summary = directory / (self.name + ".summary.txt")
        self.active = False
        self.diagnostic = diagnostic
        self.status: dict = {"status": "NOT_STARTED", "coverage": "NONE", "correlated": False}

    def start(self) -> dict:
        available = availability()
        if not available["available"]:
            self.status = {"status": "UNAVAILABLE", "reason": available["reason"],
                           "coverage": "NONE", "correlated": False}
            return self.status
        self.directory.mkdir(parents=True, exist_ok=True)
        try:
            completed = subprocess.run(
                ["logman", "start", self.name, "-p", PROVIDER, PROCESS_KEYWORD, "0x4",
                 "-o", str(self.etl), "-ets"],
                stdin=subprocess.DEVNULL, capture_output=True, text=True,
                timeout=5, check=False)
            if completed.returncode != 0:
                denied = "access is denied" in (completed.stdout + completed.stderr).lower()
                self.status = {"status": "UNAVAILABLE", "reason": "ETW_ADMIN_PERMISSION_REQUIRED" if denied else "ETW_SESSION_START_FAILED",
                               "coverage": "NONE", "correlated": False}
                return self.status
            self.active = True
            self.status = {"status": "RECORDING", "coverage": "PARTIAL_PROCESS_EVENTS", "correlated": False}
            return self.status
        except (OSError, subprocess.TimeoutExpired):
            self.status = {"status": "UNAVAILABLE", "reason": "ETW_SESSION_START_FAILED",
                           "coverage": "NONE", "correlated": False}
            return self.status

    def stop(self, pid: int | None, started_ns: int | None) -> dict:
        if not self.active:
            return self.status
        self.active = False
        try:
            stopped = subprocess.run(["logman", "stop", self.name, "-ets"],
                                     stdin=subprocess.DEVNULL, capture_output=True,
                                     timeout=5, check=False)
            if stopped.returncode != 0 or not self.etl.is_file() or pid is None or started_ns is None:
                return {"status": "INCOMPLETE", "reason": "ETW_SESSION_STOP_FAILED",
                        "coverage": "PARTIAL_PROCESS_EVENTS", "correlated": False}
            converted = subprocess.run(["tracerpt", str(self.etl), "-o", str(self.xml),
                                        "-of", "XML", "-lr", "-y", "-summary", str(self.summary)],
                                       stdin=subprocess.DEVNULL, capture_output=True,
                                       timeout=8, check=False)
            if converted.returncode != 0 or not self.xml.is_file():
                return {"status": "INCOMPLETE", "reason": "ETW_CONVERSION_FAILED",
                        "coverage": "PARTIAL_PROCESS_EVENTS", "correlated": False}
            matched, total = _parse_process_events(self.xml, pid, started_ns)
            summary = self.summary.read_text(encoding="utf-8", errors="replace") if self.summary.exists() else ""
            lost = _lost_events(summary)
            start_seen = any(event["kind"] == "PROCESS_START" for event in matched)
            correlated = start_seen and lost == 0
            result = {"status": "CORRELATED_PARTIAL" if correlated else "INCOMPLETE",
                    "reason": "ETW_PROCESS_EVENTS_CORRELATED" if correlated else
                              "ETW_EVENTS_LOST" if lost else
                              "ETW_LOSS_UNKNOWN" if lost is None else "ETW_PROCESS_START_NOT_OBSERVED",
                    "coverage": "PARTIAL_PROCESS_EVENTS", "correlated": correlated,
                    "correlation_clock": "PROCESS_CREATE_TIME_UTC",
                    "events_scanned": total, "matched_events": matched,
                    "process_start_observed": start_seen, "lost_events": lost}
            if self.diagnostic:
                result["diagnostic_events"] = _diagnostic_events(self.xml)
            return result
        except (OSError, ValueError, ET.ParseError, subprocess.TimeoutExpired):
            return {"status": "INCOMPLETE", "reason": "ETW_TRACE_UNREADABLE",
                    "coverage": "PARTIAL_PROCESS_EVENTS", "correlated": False}
        finally:
            for path in (self.etl, self.xml, self.summary):
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    pass
