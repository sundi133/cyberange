"""Behavior-module execution adapters.

Two adapters implement the same contract so the control plane doesn't care
which one runs:

- SimulatedAdapter: emits the telemetry a module *declares* it would produce
  (synthetic events). Used when a module has no execution spec or Docker is
  unavailable.
- DockerAdapter: actually runs the module's benign, bounded command inside a
  throwaway, network-isolated container and captures its *real* stdout/stderr,
  exit code, and timing as telemetry.

Both return an ExecutionResult of telemetry "records"; the service layer turns
each record into a timeline event. Every payload carries `real: true|false`
so operators can tell genuine container output from simulated stand-ins.

Safety: DockerAdapter runs with `--network none` (no egress, matching the
spec's default-deny), constrained memory/cpu/pids, `--no-new-privileges`, no
host mounts, and `--rm`. It can only run signed modules with an explicit
execution spec — never arbitrary input.
"""

from __future__ import annotations

import subprocess
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

_MAX_OUTPUT_LINES = 200
_MAX_STDERR_CHARS = 2000


class ExecutionError(Exception):
    pass


@dataclass
class ExecutionResult:
    real: bool
    records: list[dict]          # each: {kind, technique_id?, payload}
    summary: dict = field(default_factory=dict)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def docker_available() -> bool:
    try:
        r = subprocess.run(["docker", "ps"], capture_output=True, timeout=6)
        return r.returncode == 0
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        return False


class SimulatedAdapter:
    """Emit the module's declared expected telemetry as synthetic events."""

    real = False

    def run(self, module: dict, inputs: dict, timeout: int) -> ExecutionResult:
        records = []
        for tech in module.get("technique_ids", []):
            records.append({
                "kind": "ttp-emulation",
                "technique_id": tech,
                "payload": {
                    "real": False, "adapter": "simulated",
                    "module": module["id"], "safety_class": module.get("safety_class"),
                    "inputs": inputs or {},
                },
            })
        for signal in module.get("expected_telemetry", []):
            records.append({
                "kind": "expected-telemetry",
                "technique_id": None,
                "payload": {"real": False, "signal": signal},
            })
        return ExecutionResult(
            real=False, records=records,
            summary={"real": False, "adapter": "simulated",
                     "techniques": module.get("technique_ids", [])},
        )


class DockerAdapter:
    """Actually run a benign command in an isolated throwaway container."""

    real = True

    def run(self, module: dict, inputs: dict, timeout: int) -> ExecutionResult:
        spec = module.get("execution") or {}
        image = spec.get("image")
        cmd = spec.get("cmd")
        if not image or not cmd:
            raise ExecutionError("module execution spec missing image/cmd")
        network = spec.get("network", "none")
        name = f"cr-{uuid.uuid4().hex[:10]}"

        docker_cmd = [
            "docker", "run", "--rm", "--name", name,
            f"--network={network}",
            "--memory=256m", "--cpus=1", "--pids-limit=128",
            "--security-opt=no-new-privileges",
            image, *cmd,
        ]

        started = _now()
        t0 = time.monotonic()
        try:
            proc = subprocess.run(
                docker_cmd, capture_output=True, text=True,
                timeout=max(5, min(timeout, 120)),
            )
        except subprocess.TimeoutExpired:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True)
            raise ExecutionError(f"container timed out after {timeout}s")
        except (subprocess.SubprocessError, OSError) as exc:
            raise ExecutionError(f"container execution failed: {exc}")
        duration = round(time.monotonic() - t0, 3)
        finished = _now()

        if proc.returncode == 125:  # docker itself failed (bad image/flag)
            raise ExecutionError(f"docker could not start container: {proc.stderr.strip()[:200]}")

        stdout_lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]

        records: list[dict] = []
        # One real technique-tagged event per ATT&CK ID with container context.
        for tech in module.get("technique_ids", []):
            records.append({
                "kind": "ttp-exec",
                "technique_id": tech,
                "payload": {
                    "real": True, "adapter": "docker", "image": image,
                    "cmd": cmd, "container": name, "exit_code": proc.returncode,
                    "duration_s": duration,
                },
            })
        # Real process output — the actual logs a defender would inspect.
        for line in stdout_lines[:_MAX_OUTPUT_LINES]:
            records.append({
                "kind": "process-output",
                "technique_id": None,
                "payload": {"real": True, "image": image, "line": line},
            })
        if len(stdout_lines) > _MAX_OUTPUT_LINES:
            records.append({
                "kind": "process-output",
                "technique_id": None,
                "payload": {"real": True, "image": image,
                            "line": f"… {len(stdout_lines) - _MAX_OUTPUT_LINES} more lines truncated"},
            })
        if proc.stderr.strip():
            records.append({
                "kind": "process-stderr",
                "technique_id": None,
                "payload": {"real": True, "stderr": proc.stderr[:_MAX_STDERR_CHARS]},
            })

        return ExecutionResult(
            real=True, records=records,
            summary={
                "real": True, "adapter": "docker", "image": image,
                "exit_code": proc.returncode, "duration_s": duration,
                "stdout_lines": len(stdout_lines),
                "started": started, "finished": finished,
            },
        )


def select_adapter(module: dict, *, docker_ok: bool | None = None):
    """Pick the real Docker adapter when the module opts in and Docker is up;
    otherwise fall back to simulation."""
    spec = module.get("execution") or {}
    if spec.get("adapter") == "docker":
        if docker_ok is None:
            docker_ok = docker_available()
        if docker_ok:
            return DockerAdapter()
    return SimulatedAdapter()
