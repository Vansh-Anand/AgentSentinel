"""Optional Linux-container command demo; requires a pinned local Docker image.

Usage: python -m agent_runtime.docker_demo --image sha256:<local-image-id>
The run is deliberately small and uses only synthetic local files.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import tempfile

from .docker_executor import DockerCommandExecutor
from .gateway import AgentToolGateway, JsonlAuditSink
from .policy import TaskPolicy


SAFE_SCRIPT = "from pathlib import Path\nprint(Path('README.md').read_text().splitlines()[0])\n"
ATTACK_SCRIPT = '''from pathlib import Path
import socket
try:
    print("secret:", Path(".env").read_text())
except Exception as exc:
    print("secret read denied:", type(exc).__name__)
try:
    socket.create_connection(("192.0.2.1", 443), timeout=2)
except Exception as exc:
    print("network attempt denied:", type(exc).__name__, str(exc))
'''


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="Pinned local Linux image ID or digest")
    parser.add_argument("--attack", action="store_true", help="Run a script that attempts denied effects")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="agentsentinel-docker-demo-") as directory:
        root = Path(directory)
        (root / "README.md").write_text("# Synthetic auth module\n", encoding="utf-8")
        (root / ".env").write_text("DEMO_SECRET=synthetic-only\n", encoding="utf-8")
        (root / "summary.py").write_text(ATTACK_SCRIPT if args.attack else SAFE_SCRIPT, encoding="utf-8")
        policy = TaskPolicy(root, ("README.md", "summary.py"),
                            allowed_commands=(("python", "summary.py"),))
        gateway = AgentToolGateway(policy, DockerCommandExecutor(args.image),
                                   JsonlAuditSink(root / "audit.jsonl"))
        result = gateway.handle(run_id="docker-demo", request_id="run-script",
                                tool_name="execute_command",
                                arguments={"argv": ["python", "summary.py"]})
        print(json.dumps({
            "decision": result.decision,
            "reason_code": result.reason_code,
            "executed": result.executed,
            "output": result.output,
            "error_type": result.error,
            "effectseal": "INCOMPLETE: native collector not attached",
        }, indent=2))


if __name__ == "__main__":
    main()
