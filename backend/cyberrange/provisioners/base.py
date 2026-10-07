"""The provisioner seam.

A range's targets can be supplied by more than one tier: throwaway or
persistent Docker containers today, virtual machines on a hypervisor where the
scenario needs a real Windows or Active Directory surface. Both answer the same
four questions the control plane asks - stand it up, run a command on it,
recycle it, tear it down - so everything above this layer (lifecycle,
exercises, modules, detection, scoring) is unchanged by the choice.

This module defines that contract. It deliberately holds no Docker and no
hypervisor specifics.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable


class ProvisionError(RuntimeError):
    """A tier could not satisfy a request (unreachable, timed out, refused)."""


@dataclass(frozen=True)
class ExecResult:
    """The outcome of running one command on a range target.

    Mirrors what a process actually returns, because the telemetry the blue
    team hunts is built from these fields verbatim.
    """
    stdout: str
    stderr: str
    returncode: int
    duration_s: float

    def as_tuple(self) -> tuple[str, str, int, float]:
        """Legacy call sites unpack a 4-tuple; keep that working."""
        return (self.stdout, self.stderr, self.returncode, self.duration_s)


@runtime_checkable
class RangeProvisioner(Protocol):
    """What the control plane needs from any target tier."""

    #: Short identifier recorded on timeline events, e.g. "docker" or "proxmox".
    name: str

    def is_provisioned(self, range_id: str) -> bool:
        """True once the range's primary target is up and reachable."""

    def provision(self, range_id: str, with_directory: bool = False) -> dict:
        """Create the isolated network and targets. Must be idempotent.

        Returns ``{"network": str, "targets": [{"name", "hostname", "role"}]}``.
        """

    def has_target(self, range_id: str, target: str) -> bool:
        """True if ``target`` (e.g. "victim", "directory") is up for this range."""

    def exec_in(self, range_id: str, target: str, cmd: list[str],
                timeout: int = 60) -> ExecResult:
        """Run ``cmd`` on ``target`` and capture what it really produced."""

    def reset(self, range_id: str) -> dict:
        """Return targets to a clean state, keeping the range and its network."""

    def teardown(self, range_id: str) -> None:
        """Destroy every target and the network. Best effort."""
