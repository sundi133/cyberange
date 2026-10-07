"""The container tier, behind the provisioner contract.

The Docker implementation itself still lives in ``cyberrange.provisioning``;
this is the adapter that presents it as a ``RangeProvisioner`` so the control
plane can hold a tier rather than importing one.
"""

from __future__ import annotations

from .. import provisioning
from .base import ExecResult, ProvisionError


class ContainerProvisioner:
    """Persistent Docker targets on an internal, egress-denied network."""

    name = "docker"

    # Logical target name -> the function that reports whether it is up.
    _PRESENCE = {
        "victim": provisioning.is_provisioned,
        "directory": provisioning.directory_provisioned,
    }
    # Logical target name -> the function that runs a command on it.
    _EXEC = {
        "victim": provisioning.exec_in_victim,
        "directory": provisioning.exec_in_directory,
    }

    def is_provisioned(self, range_id: str) -> bool:
        return provisioning.is_provisioned(range_id)

    def provision(self, range_id: str, with_directory: bool = False) -> dict:
        return provisioning.provision(range_id, with_directory=with_directory)

    def has_target(self, range_id: str, target: str) -> bool:
        probe = self._PRESENCE.get(target)
        return bool(probe and probe(range_id))

    def exec_in(self, range_id: str, target: str, cmd: list[str],
                timeout: int = 60) -> ExecResult:
        runner = self._EXEC.get(target)
        if runner is None:
            raise ProvisionError(f"container tier has no target {target!r}")
        out, err, rc, dur = runner(range_id, cmd, timeout=timeout)
        return ExecResult(out, err, rc, dur)

    def reset(self, range_id: str) -> dict:
        return provisioning.reset(range_id)

    def teardown(self, range_id: str) -> None:
        provisioning.teardown(range_id)
