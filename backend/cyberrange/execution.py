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
execution spec - never arbitrary input.
"""

from __future__ import annotations

import os
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


def docker_host() -> str | None:
    """The Docker endpoint the CLI will use (local socket if unset).

    The `docker` CLI honors DOCKER_HOST automatically, so setting it points the
    app at a remote daemon (e.g. a docker:dind sidecar) with no code change.
    """
    return os.environ.get("DOCKER_HOST")


def docker_available() -> bool:
    try:
        # `docker version --format` reaches the daemon (local or remote via
        # DOCKER_HOST) and fails fast if it is unreachable.
        r = subprocess.run(["docker", "ps"], capture_output=True, timeout=8)
        return r.returncode == 0
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        return False


def execution_mode(docker_ok: bool | None = None) -> dict:
    """Report how modules will execute, for /api/health and the dashboard."""
    if docker_ok is None:
        docker_ok = docker_available()
    host = docker_host()
    return {
        "real": bool(docker_ok),
        "mode": "docker" if docker_ok else "simulated",
        "docker_host": host or ("local socket" if docker_ok else None),
        "remote": bool(host),
    }


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

    @staticmethod
    def _cleanup(name: str) -> None:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)

    def run(self, module: dict, inputs: dict, timeout: int) -> ExecutionResult:
        spec = module.get("execution") or {}
        image = spec.get("image")
        cmd = spec.get("cmd")
        if not image or not cmd:
            raise ExecutionError("module execution spec missing image/cmd")
        network = spec.get("network", "none")
        name = f"cr-{uuid.uuid4().hex[:10]}"
        tmo = max(5, min(timeout, 120))

        # Detached run + `docker logs` rather than attached `docker run`: the
        # attached output stream is not reliably delivered when driving a REMOTE
        # daemon over DOCKER_HOST (e.g. a dind sidecar). Detached + logs works
        # for both local and remote daemons.
        run_cmd = [
            "docker", "run", "-d", "--name", name,
            f"--network={network}",
            "--memory=256m", "--cpus=1", "--pids-limit=128",
            "--security-opt=no-new-privileges",
            image, *cmd,
        ]

        started = _now()
        t0 = time.monotonic()
        try:
            started_proc = subprocess.run(run_cmd, capture_output=True, text=True, timeout=tmo)
        except subprocess.TimeoutExpired:
            self._cleanup(name)
            raise ExecutionError(f"container failed to start within {tmo}s")
        except (subprocess.SubprocessError, OSError) as exc:
            raise ExecutionError(f"container execution failed: {exc}")
        if started_proc.returncode != 0:  # bad image, pull failure, bad flag
            self._cleanup(name)
            raise ExecutionError(
                f"docker could not start container: {started_proc.stderr.strip()[:200]}")

        # Wait for the container to exit (bounded), then collect its logs.
        try:
            wait_proc = subprocess.run(
                ["docker", "wait", name], capture_output=True, text=True, timeout=tmo)
            returncode = int(wait_proc.stdout.strip() or "0") if wait_proc.returncode == 0 else 0
        except subprocess.TimeoutExpired:
            self._cleanup(name)
            raise ExecutionError(f"container timed out after {tmo}s")
        duration = round(time.monotonic() - t0, 3)
        finished = _now()

        logs = subprocess.run(["docker", "logs", name], capture_output=True, text=True, timeout=20)
        self._cleanup(name)

        class _P:
            pass
        proc = _P()
        proc.returncode = returncode
        proc.stdout = logs.stdout
        proc.stderr = logs.stderr

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
        # Real process output - the actual logs a defender would inspect.
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
                "docker_host": docker_host() or "local socket",
                "started": started, "finished": finished,
            },
        )


def build_result(module: dict, stdout: str, stderr: str, returncode: int,
                 duration: float, *, adapter: str, image: str,
                 real: bool = True) -> ExecutionResult:
    """Turn already-captured command output into telemetry records. Used by the
    live-range exec path (provisioning.exec_in_victim) so behaviors run inside a
    persistent target produce the same real events as a throwaway container."""
    stdout_lines = [ln for ln in stdout.splitlines() if ln.strip()]
    cmd = (module.get("execution") or {}).get("cmd")
    records: list[dict] = []
    for tech in module.get("technique_ids", []):
        records.append({
            "kind": "ttp-exec", "technique_id": tech,
            "payload": {"real": real, "adapter": adapter, "image": image,
                        "cmd": cmd, "exit_code": returncode, "duration_s": duration},
        })
    for line in stdout_lines[:_MAX_OUTPUT_LINES]:
        records.append({"kind": "process-output", "technique_id": None,
                        "payload": {"real": real, "image": image, "line": line}})
    if len(stdout_lines) > _MAX_OUTPUT_LINES:
        records.append({"kind": "process-output", "technique_id": None,
                        "payload": {"real": real, "image": image,
                                    "line": f"… {len(stdout_lines) - _MAX_OUTPUT_LINES} more lines truncated"}})
    if stderr.strip():
        records.append({"kind": "process-stderr", "technique_id": None,
                        "payload": {"real": real, "stderr": stderr[:_MAX_STDERR_CHARS]}})
    return ExecutionResult(
        real=real, records=records,
        summary={"real": real, "adapter": adapter, "image": image,
                 "exit_code": returncode, "duration_s": duration,
                 "stdout_lines": len(stdout_lines)},
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
