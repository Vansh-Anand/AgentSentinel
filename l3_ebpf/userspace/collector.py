import time
import os
import sys
import json
import ctypes
import ipaddress
import socket
from typing import List, Callable
from common.events.schemas import SyscallEvent
from l3_ebpf.namespace.scope import AgentScopeManager
from l3_ebpf.userspace.health import TelemetryHealthMonitor

class SimulatedL3Collector:
    """
    Simulates eBPF ring buffer telemetry on a Windows host or non-root Linux environment.
    Reads from a predefined trace file and feeds SyscallEvents into the pipeline.
    """
    def __init__(self, scope_manager: AgentScopeManager, health_monitor: TelemetryHealthMonitor, trace_file: str):
        self.scope_manager = scope_manager
        self.health_monitor = health_monitor
        self.trace_file = trace_file
        self.callbacks: List[Callable[[SyscallEvent], None]] = []
        
    def register_callback(self, cb: Callable[[SyscallEvent], None]):
        self.callbacks.append(cb)
        
    def run_replay(self):
        """Simulates polling the eBPF ringbuffer"""
        if not os.path.exists(self.trace_file):
            raise FileNotFoundError(f"Simulation trace file not found: {self.trace_file}")
            
        with open(self.trace_file, 'r') as f:
            for line in f:
                if not line.strip():
                    continue
                start_t = time.time_ns()
                
                try:
                    data = json.loads(line)
                    event = SyscallEvent(**data)
                    
                    # Verify namespace scoping
                    if event.cgroup_id:
                        agent_id = self.scope_manager.resolve_cgroup(event.cgroup_id)
                        if not agent_id:
                            self.health_monitor.record_drop()
                            continue
                        event.agent_id = agent_id
                        
                    # Dispatch to callbacks (e.g., L2/L3 correlation)
                    for cb in self.callbacks:
                        cb(event)
                        
                    end_t = time.time_ns()
                    self.health_monitor.record_event((end_t - start_t) / 1_000_000)
                    
                except Exception as e:
                    self.health_monitor.record_decode_error()


class CSyscallEvent(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_uint),
        ("timestamp_ns", ctypes.c_ulonglong),
        ("pid", ctypes.c_uint),
        ("tid", ctypes.c_uint),
        ("ppid", ctypes.c_uint),
        ("uid", ctypes.c_uint),
        ("gid", ctypes.c_uint),
        ("cgroup_id", ctypes.c_ulonglong),
        ("comm", ctypes.c_char * 16),
        ("executable", ctypes.c_char * 256),
        ("ret", ctypes.c_int),
        ("arg_payload", ctypes.c_char * 256),
        ("addr_family", ctypes.c_ushort),
        ("port_be", ctypes.c_ushort),
        ("address", ctypes.c_ubyte * 16),
        ("open_flags", ctypes.c_uint),
        ("dirfd", ctypes.c_int),
        ("address_valid", ctypes.c_ubyte),
    ]

# Callback signature: void callback(const struct syscall_event_t *event, int size)
EVENT_CALLBACK = ctypes.CFUNCTYPE(None, ctypes.POINTER(CSyscallEvent), ctypes.c_int)

class NativeL3Collector:
    """
    Native libbpf-based collector using a minimal C wrapper via ctypes. 
    Requires execution on a Linux host with BPF capabilities.
    """
    def __init__(self, scope_manager: AgentScopeManager, health_monitor: TelemetryHealthMonitor):
        self.scope_manager = scope_manager
        self.health_monitor = health_monitor
        self.callbacks: List[Callable[[SyscallEvent], None]] = []
        self._lib = None
        self._handle = None
        self._callback_ref = None # Keep reference to prevent GC
        self._last_kernel_drops = 0

    def register_callback(self, cb: Callable[[SyscallEvent], None]):
        self.callbacks.append(cb)

    def _event_handler(self, event_ptr, size):
        start_t = time.time_ns()
        try:
            if size != ctypes.sizeof(CSyscallEvent):
                self.health_monitor.record_decode_error()
                return
            ce = event_ptr.contents
            
            # Verify namespace scoping
            if ce.cgroup_id and not self.scope_manager.is_monitored(ce.cgroup_id):
                self.health_monitor.record_drop()
                return
            agent_id = self.scope_manager.resolve_cgroup(ce.cgroup_id)
            if not agent_id:
                self.health_monitor.record_drop()
                return
            identity = self.scope_manager.get_agent(agent_id)
            syscall_name = {1: "execve", 2: "openat", 3: "connect"}.get(ce.type)
            if syscall_name is None:
                self.health_monitor.record_decode_error()
                return
            destination_ip = None
            destination_port = None
            if syscall_name == "connect" and ce.address_valid:
                if ce.addr_family == socket.AF_INET:
                    destination_ip = str(ipaddress.IPv4Address(bytes(ce.address[:4])))
                elif ce.addr_family == socket.AF_INET6:
                    destination_ip = str(ipaddress.IPv6Address(bytes(ce.address)))
                if destination_ip is not None:
                    destination_port = socket.ntohs(ce.port_be)
                
            # Normalize to AcademIQ schema
            event = SyscallEvent(
                event_id=f"l3-{ce.timestamp_ns}-{ce.pid}-{ce.tid}",
                timestamp_ns=time.time_ns(),
                layer="L3",
                trace_id=identity.trace_id if identity else agent_id,
                event_type="Syscall",
                monotonic_timestamp_ns=ce.timestamp_ns,
                pid=ce.pid,
                tid=ce.tid,
                ppid=ce.ppid,
                uid=ce.uid,
                gid=ce.gid,
                cgroup_id=ce.cgroup_id,
                agent_id=agent_id,
                task_id=agent_id,
                comm=ce.comm.decode('utf-8', 'replace').strip('\x00'),
                executable=ce.executable.decode('utf-8', 'replace').strip('\x00'),
                syscall_name=syscall_name,
                return_value=None,  # enter tracepoint is an attempt, not a syscall outcome
                flags=ce.open_flags if syscall_name == "openat" else None,
                arguments={"dirfd": ce.dirfd} if syscall_name == "openat" else {},
                destination_ip=destination_ip,
                destination_port=destination_port,
                telemetry_source="EBPF"
            )
            
            for cb in self.callbacks:
                cb(event)
                
            end_t = time.time_ns()
            self.health_monitor.record_event((end_t - start_t) / 1_000_000)
            
        except Exception as e:
            self.health_monitor.record_decode_error()

    def start(self):
        if sys.platform != 'linux':
            raise RuntimeError(
                "AcademIQ Native L3 Collector requires a native Linux environment. "
                "Execution on Windows/macOS is gracefully unsupported. "
                "Use SimulatedL3Collector for local testing."
            )
            
        # Load the shared library
        so_path = os.path.join(os.path.dirname(__file__), "..", "kernel", "libnative_loader.so")
        if not os.path.exists(so_path):
            raise FileNotFoundError(f"Native loader library not found at {so_path}. Please run 'make' in l3_ebpf/kernel/.")
            
        self._lib = ctypes.CDLL(so_path)
        self._lib.native_event_size.restype = ctypes.c_int
        if self._lib.native_event_size() != ctypes.sizeof(CSyscallEvent):
            raise RuntimeError("native event ABI does not match the Python collector")
        self._lib.native_event_offset.argtypes = [ctypes.c_int]
        self._lib.native_event_offset.restype = ctypes.c_int
        for index, field in enumerate(("type", "timestamp_ns", "cgroup_id", "executable",
                                       "address", "open_flags", "dirfd", "address_valid")):
            if self._lib.native_event_offset(index) != getattr(CSyscallEvent, field).offset:
                raise RuntimeError(f"native event ABI field mismatch: {field}")
        
        # Setup function signatures
        self._lib.init_bpf.argtypes = [ctypes.c_char_p]
        self._lib.init_bpf.restype = ctypes.c_void_p
        
        self._lib.start_ringbuffer.argtypes = [ctypes.c_void_p, EVENT_CALLBACK]
        self._lib.start_ringbuffer.restype = ctypes.c_int
        
        self._lib.poll_ringbuffer.argtypes = [ctypes.c_void_p, ctypes.c_int]
        self._lib.poll_ringbuffer.restype = ctypes.c_int
        
        self._lib.cleanup_bpf.argtypes = [ctypes.c_void_p]
        self._lib.update_cgroup_filter.argtypes = [ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_int]
        self._lib.update_cgroup_filter.restype = ctypes.c_int
        self._lib.read_dropped_events.argtypes = [ctypes.c_void_p]
        self._lib.read_dropped_events.restype = ctypes.c_longlong
        
        bpf_obj_path = os.path.join(os.path.dirname(__file__), "..", "kernel", "execve.bpf.o")
        if not os.path.exists(bpf_obj_path):
            raise FileNotFoundError(f"BPF object not found at {bpf_obj_path}. Please run 'make' in l3_ebpf/kernel/.")
            
        self._handle = self._lib.init_bpf(bpf_obj_path.encode('utf-8'))
        if not self._handle:
            raise RuntimeError("Failed to initialize and load BPF object natively.")
        self._last_kernel_drops = 0
            
        self._callback_ref = EVENT_CALLBACK(self._event_handler)
        if self._lib.start_ringbuffer(self._handle, self._callback_ref) != 0:
            self._lib.cleanup_bpf(self._handle)
            self._handle = None
            raise RuntimeError("Failed to start BPF ring buffer.")

    def poll(self, timeout_ms: int = 100):
        if self._handle and self._lib:
            result = self._lib.poll_ringbuffer(self._handle, timeout_ms)
            if result < 0:
                self.health_monitor.record_decode_error()
                raise RuntimeError(f"BPF ring buffer poll failed: {result}")
            drops = self._lib.read_dropped_events(self._handle)
            if drops < 0 or drops < self._last_kernel_drops:
                self.health_monitor.record_decode_error()
                raise RuntimeError("BPF dropped-event counter unavailable")
            for _ in range(drops - self._last_kernel_drops):
                self.health_monitor.record_overflow()
            self._last_kernel_drops = drops

    def register_agent(self, agent_id: str, cgroup_id: int, root_pid: int,
                       container_id: str | None = None):
        if not self._handle or not self._lib:
            raise RuntimeError("native collector is not attached")
        if cgroup_id <= 0 or self._lib.update_cgroup_filter(self._handle, cgroup_id, 1) != 0:
            raise RuntimeError("failed to install cgroup filter")
        try:
            return self.scope_manager.register_agent(agent_id, cgroup_id, root_pid, container_id)
        except Exception:
            self._lib.update_cgroup_filter(self._handle, cgroup_id, 0)
            raise

    def unregister_agent(self, agent_id: str):
        identity = self.scope_manager.get_agent(agent_id)
        if identity and self._handle and self._lib:
            if self._lib.update_cgroup_filter(self._handle, identity.cgroup_id, 0) != 0:
                raise RuntimeError("failed to remove cgroup filter")
            self.scope_manager.unregister_agent(agent_id)
            
    def stop(self):
        if self._handle and self._lib:
            self._lib.cleanup_bpf(self._handle)
            self._handle = None
