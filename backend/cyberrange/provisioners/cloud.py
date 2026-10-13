"""The cloud tier, behind the provisioner contract.

The Phase 1 cloud content ships as Docker-adapter modules that emit cloud
flavoured telemetry markers; the detection engine scores them with log-basis
rules. That is enough to run the cloud scenarios on commodity hardware, no
cloud account required, and matches how the Linux-real modules work.

Phase 2 - running the modules for real against a customer-owned cloud sandbox
account - plugs in here. This file defines the shape (``CloudProvisioner``,
same four methods as every other tier so nothing above this layer changes),
plus a ``MarkerCloudProvisioner`` reference implementation that satisfies the
protocol by routing every ``exec_in`` through the module's declared command.
That is deliberately not a real cloud SDK: the control plane is standard
library only, and we have no business embedding SigV4 or token exchange here.
A customer wiring their own cloud adapter subclasses this and overrides
``exec_in`` to call the SDK of their choice.

Selection: ``CR_CLOUD_PROVIDER`` (``aws``/``azure``/``gcp``) picks the cloud
tier via ``provisioners.resolve()``. Nothing silently downgrades: if the env
is set but required credentials are missing, the resolver falls back to the
container tier and ``/api/health`` reports the reason.
"""

from __future__ import annotations

import os
import subprocess
import time
import uuid
from typing import ClassVar

from .base import ExecResult, ProvisionError


SUPPORTED_PROVIDERS: tuple[str, ...] = ("aws", "azure", "gcp")


class MarkerCloudProvisioner:
    """A cloud tier that emits marker telemetry via the local Docker daemon.

    The provisioner contract wants ``exec_in`` to produce an ``ExecResult``.
    This implementation runs the module's declared command inside a short
    throwaway container (``alpine``), capturing real stdout - identical to the
    DockerAdapter path. The container is a bounded, egress-denied process that
    only emits ``echo`` lines, so detection training is end-to-end real while
    no cloud account is touched.

    A production cloud adapter subclasses this and overrides ``exec_in`` to
    call the SDK the customer wants (boto3, azure-sdk, google-cloud-storage).
    The rest of this class stays usable, including ``provision``/``reset``/
    ``teardown`` which operate on the cloud-sandbox-identity concept rather
    than on VMs.
    """

    name: ClassVar[str] = "cloud"

    def __init__(self, provider: str, *, sandbox: str | None = None):
        if provider not in SUPPORTED_PROVIDERS:
            raise ProvisionError(f"unknown cloud provider: {provider!r}; "
                                 f"supported: {SUPPORTED_PROVIDERS}")
        self.provider = provider
        self.sandbox = sandbox or f"cr-sandbox-{uuid.uuid4().hex[:8]}"

    # -- lifecycle ---------------------------------------------------------
    def is_provisioned(self, range_id: str) -> bool:
        # The marker tier is always available; a real cloud subclass would
        # probe its sandbox principal and return False if the keys expired.
        return True

    def provision(self, range_id: str, with_directory: bool = False) -> dict:
        # The marker tier has no real resources to allocate; it reports a
        # logical sandbox identity so timeline events can tag the audit
        # stream the modules would otherwise write to.
        return {
            "network": f"cloud:{self.provider}",
            "targets": [{
                "name": self.sandbox,
                "hostname": f"{self.sandbox}.{self.provider}",
                "role": f"cloud:{self.provider}",
            }],
        }

    def has_target(self, range_id: str, target: str) -> bool:
        # One logical cloud target per range: the sandbox identity.
        return target in ("cloud", "sandbox", self.sandbox)

    def exec_in(self, range_id: str, target: str, cmd: list[str],
                timeout: int = 60) -> ExecResult:
        """Run ``cmd`` in a short alpine container, capturing its stdout.

        A production cloud adapter overrides this with its SDK. The signature
        is the one the control plane expects.
        """
        tmo = max(5, min(timeout, 120))
        name = f"cr-cloud-{uuid.uuid4().hex[:10]}"
        docker_cmd = [
            "docker", "run", "--rm", "--name", name,
            "--network=none",
            "--memory=256m", "--cpus=1", "--pids-limit=128",
            "--security-opt=no-new-privileges",
            "alpine:3.19", *cmd,
        ]
        t0 = time.monotonic()
        try:
            result = subprocess.run(docker_cmd, capture_output=True,
                                    text=True, timeout=tmo)
        except subprocess.TimeoutExpired:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True)
            raise ProvisionError(f"cloud marker container timed out after {tmo}s")
        except (subprocess.SubprocessError, FileNotFoundError, OSError) as exc:
            raise ProvisionError(f"cloud marker tier unavailable: {exc}") from exc
        return ExecResult(
            stdout=result.stdout, stderr=result.stderr,
            returncode=result.returncode,
            duration_s=round(time.monotonic() - t0, 3),
        )

    def reset(self, range_id: str) -> dict:
        # Nothing to roll back for the marker tier. A real cloud adapter
        # revokes any sessions the range created and recycles sandbox keys.
        return self.provision(range_id)

    def teardown(self, range_id: str) -> None:
        # Marker tier has no persistent cloud state. A real cloud adapter
        # removes any resources (keys, roles, buckets) the range created in
        # the sandbox, best effort.
        return None


def from_env() -> MarkerCloudProvisioner | None:
    """Build the cloud tier from environment, or None when it is not configured.

    Required: ``CR_CLOUD_PROVIDER`` set to one of SUPPORTED_PROVIDERS. The
    sandbox identity is taken from ``CR_CLOUD_SANDBOX`` when set, else a
    stable random one is picked per process. A production cloud subclass
    would also require ``CR_AWS_PROFILE`` / ``CR_AZURE_TENANT`` / etc. and
    refuse to build without them; the marker tier accepts the single var.
    """
    provider = (os.environ.get("CR_CLOUD_PROVIDER") or "").lower()
    if not provider:
        return None
    if provider not in SUPPORTED_PROVIDERS:
        raise ProvisionError(f"CR_CLOUD_PROVIDER={provider!r} not in "
                             f"{SUPPORTED_PROVIDERS}")
    return MarkerCloudProvisioner(
        provider,
        sandbox=os.environ.get("CR_CLOUD_SANDBOX") or None,
    )
