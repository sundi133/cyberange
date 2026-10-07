"""Target tiers, and how the control plane picks one.

Selection is by environment so a deployment's tier is an operational choice,
not a code change:

  * ``CR_PROXMOX_*`` fully configured -> the VM tier,
  * otherwise -> the container tier.

A tier that cannot be built never silently downgrades without saying so; the
resolver records why, and ``/api/health`` reports which tier is live.
"""

from __future__ import annotations

import os

from .base import ExecResult, ProvisionError, RangeProvisioner
from .containers import ContainerProvisioner

__all__ = ["ExecResult", "ProvisionError", "RangeProvisioner",
           "ContainerProvisioner", "resolve", "describe"]

_REASON = "container tier (default)"


def resolve() -> RangeProvisioner:
    """Return the tier this deployment is configured for."""
    global _REASON
    if os.environ.get("CR_PROXMOX_HOST"):
        from .proxmox import from_env          # imported lazily: optional tier
        try:
            vm = from_env()
        except Exception as exc:               # misconfiguration, not a crash
            _REASON = f"container tier (proxmox config rejected: {exc})"
            return ContainerProvisioner()
        if vm is not None:
            _REASON = "proxmox VM tier"
            return vm
        _REASON = "container tier (proxmox host set but templates/token incomplete)"
        return ContainerProvisioner()
    _REASON = "container tier (default)"
    return ContainerProvisioner()


def describe(provisioner: RangeProvisioner | None = None) -> dict:
    """What `/api/health` reports about the target tier."""
    return {"tier": getattr(provisioner, "name", "docker"), "selected": _REASON}
