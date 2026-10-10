import time
import threading
from typing import Dict, Optional
from common.events.schemas import AgentIdentity, ProcessIdentity

class AgentScopeManager:
    """
    Manages the mapping between AcademIQ monitored agents and their Linux cgroup identities.
    Ensures that L3 eBPF telemetry is only processed/attributed for correctly registered cgroups,
    satisfying the least-privilege telemetry requirement.
    """
    def __init__(self):
        self._agents: Dict[str, AgentIdentity] = {}
        self._cgroup_to_agent: Dict[int, str] = {}
        self._registered_monotonic_ns: Dict[int, int] = {}
        self._lock = threading.RLock()
        
    def register_agent(self, agent_id: str, cgroup_id: int, root_pid: int, container_id: Optional[str] = None) -> AgentIdentity:
        import uuid
        if not agent_id or cgroup_id <= 0 or root_pid <= 0:
            raise ValueError("agent registration requires an ID, cgroup and root PID")
        with self._lock:
            if agent_id in self._agents or cgroup_id in self._cgroup_to_agent:
                raise ValueError("agent ID or cgroup is already registered")
            start_monotonic_ns = time.monotonic_ns()
            now_ns = time.time_ns()
            identity = AgentIdentity(
                event_id=f"evt-{uuid.uuid4()}",
                timestamp_ns=now_ns,
                layer="L3",
                trace_id=f"trc-{uuid.uuid4()}",
                agent_id=agent_id,
                cgroup_id=cgroup_id,
                container_id=container_id,
                root_pid=root_pid,
                start_time_ns=now_ns,
                policy_version="1.0"
            )
            self._agents[agent_id] = identity
            self._cgroup_to_agent[cgroup_id] = agent_id
            self._registered_monotonic_ns[cgroup_id] = start_monotonic_ns
            return identity
        
    def resolve_cgroup(self, cgroup_id: int) -> Optional[str]:
        """Returns the agent_id for a given cgroup_id if monitored."""
        with self._lock:
            return self._cgroup_to_agent.get(cgroup_id)

    def resolve_native_event(self, cgroup_id: int, event_monotonic_ns: int) -> Optional[AgentIdentity]:
        """Reject buffered events older than the current cgroup registration."""
        with self._lock:
            agent_id = self._cgroup_to_agent.get(cgroup_id)
            start = self._registered_monotonic_ns.get(cgroup_id)
            if (agent_id is None or start is None or event_monotonic_ns <= 0
                    or event_monotonic_ns < start):
                return None
            return self._agents.get(agent_id)
        
    def is_monitored(self, cgroup_id: int) -> bool:
        """Determines if the cgroup should be monitored by L3."""
        with self._lock:
            return cgroup_id in self._cgroup_to_agent
        
    def unregister_agent(self, agent_id: str):
        with self._lock:
            identity = self._agents.pop(agent_id, None)
            if identity is not None:
                if self._cgroup_to_agent.get(identity.cgroup_id) == agent_id:
                    del self._cgroup_to_agent[identity.cgroup_id]
                    del self._registered_monotonic_ns[identity.cgroup_id]
            
    def get_agent(self, agent_id: str) -> Optional[AgentIdentity]:
        with self._lock:
            return self._agents.get(agent_id)

    def clear(self) -> None:
        """Discard bindings when the native collector detaches or restarts."""
        with self._lock:
            self._agents.clear()
            self._cgroup_to_agent.clear()
            self._registered_monotonic_ns.clear()
