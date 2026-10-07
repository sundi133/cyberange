"""The VM tier, on Proxmox VE.

What containers cannot give you is a real Windows endpoint or a real Active
Directory domain controller: Kerberos, SMB, GPO, NTLM. Those need full virtual
machines, which need a hypervisor. This tier drives Proxmox VE's REST API to
clone templates into a per-range, VLAN-isolated set of VMs, run commands on
them through the QEMU guest agent, roll them back to a snapshot on reset, and
destroy them on teardown.

Transport is ``urllib`` on purpose: the control plane installs nothing, and
that property should not be given up for one adapter.

STATUS: the API surface here is written to the documented Proxmox VE API and
is exercised by unit tests against a stubbed transport. It has NOT been run
against a live hypervisor in this repository, because none is present. Treat it
as unverified against real infrastructure until ``scripts/proxmox_conformance.py``
passes against your own host.
"""

from __future__ import annotations

import json
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from .base import ExecResult, ProvisionError

# Guest-agent exec polls at this cadence, bounded by the caller's timeout.
_POLL_S = 1.0
# A Proxmox task (clone, rollback, destroy) is asynchronous; wait this long.
_TASK_TIMEOUT_S = 600


class ProxmoxClient:
    """Thin Proxmox VE API client: token auth, JSON in, ``data`` out."""

    def __init__(self, host: str, token_id: str, token_secret: str, *,
                 node: str, verify_tls: bool = True, opener=None):
        self.base = host.rstrip("/") + "/api2/json"
        self.node = node
        self._auth = f"PVEAPIToken={token_id}={token_secret}"
        if opener is not None:          # tests inject a stub transport here
            self._opener = opener
        else:
            ctx = ssl.create_default_context()
            if not verify_tls:
                # Proxmox ships a self-signed cert by default. Opt-in only, and
                # the conformance script warns when it is used.
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            self._opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=ctx))

    def request(self, method: str, path: str, params: dict | None = None):
        url = self.base + path
        body = None
        if params and method in ("POST", "PUT"):
            body = urllib.parse.urlencode(params, doseq=True).encode()
        elif params:
            url += "?" + urllib.parse.urlencode(params, doseq=True)
        req = urllib.request.Request(url, data=body, method=method)
        req.add_header("Authorization", self._auth)
        if body:
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
        try:
            with self._opener.open(req, timeout=30) as resp:
                payload = json.loads(resp.read().decode() or "{}")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")[:300]
            raise ProvisionError(f"proxmox {method} {path} -> {exc.code}: {detail}") from exc
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            raise ProvisionError(f"proxmox unreachable at {self.base}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise ProvisionError(f"proxmox returned non-JSON for {path}: {exc}") from exc
        return payload.get("data")

    # -- helpers -----------------------------------------------------------
    def node_path(self, *parts: str) -> str:
        return "/nodes/" + self.node + ("/" + "/".join(parts) if parts else "")

    def wait_for_task(self, upid: str, timeout: int = _TASK_TIMEOUT_S) -> None:
        """Block until an async task finishes, raising if it failed."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status = self.request("GET", self.node_path("tasks", upid, "status")) or {}
            if status.get("status") == "stopped":
                exit_status = status.get("exitstatus", "")
                if exit_status != "OK":
                    raise ProvisionError(f"proxmox task {upid} failed: {exit_status}")
                return
            time.sleep(_POLL_S)
        raise ProvisionError(f"proxmox task {upid} did not finish within {timeout}s")


class ProxmoxProvisioner:
    """Per-range VM targets cloned from templates and isolated by VLAN."""

    name = "proxmox"
    SNAPSHOT = "cyberrange-clean"

    def __init__(self, client: ProxmoxClient, templates: dict[str, int], *,
                 bridge: str = "vmbr0", vlan_base: int = 1000,
                 vmid_base: int = 9000, guest_user: str | None = None):
        if not templates:
            raise ProvisionError("proxmox tier needs at least one template VMID")
        self.client = client
        self.templates = templates           # logical target -> template VMID
        self.bridge = bridge
        self.vlan_base = vlan_base
        self.vmid_base = vmid_base
        self.guest_user = guest_user

    # -- identity ----------------------------------------------------------
    @staticmethod
    def _slot(range_id: str) -> int:
        """Stable small integer per range, for VMID and VLAN assignment."""
        digits = "".join(ch for ch in range_id if ch.isalnum())
        return abs(hash(digits)) % 500

    def vlan_tag(self, range_id: str) -> int:
        return self.vlan_base + self._slot(range_id)

    def vmid_for(self, range_id: str, target: str) -> int:
        offset = sorted(self.templates).index(target)
        return self.vmid_base + self._slot(range_id) * 10 + offset

    def vm_name(self, range_id: str, target: str) -> str:
        return f"cr-{range_id.replace('range-', '')[:12]}-{target}"

    # -- lifecycle ---------------------------------------------------------
    def _vm_exists(self, vmid: int) -> bool:
        try:
            self.client.request("GET", self.client.node_path("qemu", str(vmid), "status", "current"))
            return True
        except ProvisionError:
            return False

    def _vm_running(self, vmid: int) -> bool:
        try:
            cur = self.client.request(
                "GET", self.client.node_path("qemu", str(vmid), "status", "current")) or {}
            return cur.get("status") == "running"
        except ProvisionError:
            return False

    def _clone(self, range_id: str, target: str, template_id: int, vmid: int) -> None:
        upid = self.client.request("POST", self.client.node_path("qemu", str(template_id), "clone"), {
            "newid": vmid,
            "name": self.vm_name(range_id, target),
            "full": 1,
            "description": f"cyberrange={range_id} target={target}",
        })
        if upid:
            self.client.wait_for_task(upid)
        # Pin the clone onto this range's VLAN. Default-deny between ranges is
        # the hypervisor's job; the tag is what makes that enforceable.
        self.client.request("POST", self.client.node_path("qemu", str(vmid), "config"), {
            "net0": f"virtio,bridge={self.bridge},tag={self.vlan_tag(range_id)}",
        })

    def _start(self, vmid: int) -> None:
        upid = self.client.request(
            "POST", self.client.node_path("qemu", str(vmid), "status", "start"))
        if upid:
            self.client.wait_for_task(upid)

    def _snapshot_clean(self, vmid: int) -> None:
        """Take the baseline snapshot `reset` rolls back to."""
        upid = self.client.request("POST", self.client.node_path("qemu", str(vmid), "snapshot"), {
            "snapname": self.SNAPSHOT,
            "description": "CyberRange clean baseline",
            "vmstate": 0,
        })
        if upid:
            self.client.wait_for_task(upid)

    def is_provisioned(self, range_id: str) -> bool:
        primary = "victim" if "victim" in self.templates else sorted(self.templates)[0]
        return self._vm_running(self.vmid_for(range_id, primary))

    def has_target(self, range_id: str, target: str) -> bool:
        if target not in self.templates:
            return False
        return self._vm_running(self.vmid_for(range_id, target))

    def provision(self, range_id: str, with_directory: bool = False) -> dict:
        targets = []
        for target, template_id in sorted(self.templates.items()):
            if target == "directory" and not with_directory:
                continue
            vmid = self.vmid_for(range_id, target)
            if not self._vm_exists(vmid):
                self._clone(range_id, target, template_id, vmid)
                self._start(vmid)
                self._await_agent(vmid)
                self._snapshot_clean(vmid)
            elif not self._vm_running(vmid):
                self._start(vmid)
                self._await_agent(vmid)
            targets.append({
                "name": self.vm_name(range_id, target),
                "hostname": target,
                "role": f"vm:{target}",
                "vmid": vmid,
            })
        return {"network": f"vlan{self.vlan_tag(range_id)}", "targets": targets}

    def _await_agent(self, vmid: int, timeout: int = 300) -> None:
        """A freshly started VM answers the API long before the guest agent is
        up; commands sent in between fail confusingly."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                self.client.request("GET", self.client.node_path("qemu", str(vmid), "agent", "ping"))
                return
            except ProvisionError:
                time.sleep(_POLL_S * 2)
        raise ProvisionError(f"guest agent on vmid {vmid} not responding within {timeout}s")

    # -- exec --------------------------------------------------------------
    def exec_in(self, range_id: str, target: str, cmd: list[str],
                timeout: int = 60) -> ExecResult:
        if target not in self.templates:
            raise ProvisionError(f"proxmox tier has no target {target!r}")
        vmid = self.vmid_for(range_id, target)
        params: dict = {"command": cmd}
        if self.guest_user:
            params["username"] = self.guest_user

        t0 = time.monotonic()
        started = self.client.request(
            "POST", self.client.node_path("qemu", str(vmid), "agent", "exec"), params) or {}
        pid = started.get("pid")
        if pid is None:
            raise ProvisionError(f"guest agent on vmid {vmid} returned no pid")

        deadline = time.monotonic() + max(5, timeout)
        while time.monotonic() < deadline:
            status = self.client.request(
                "GET", self.client.node_path("qemu", str(vmid), "agent", "exec-status"),
                {"pid": pid}) or {}
            if status.get("exited"):
                return ExecResult(
                    stdout=status.get("out-data", "") or "",
                    stderr=status.get("err-data", "") or "",
                    returncode=int(status.get("exitcode", 0) or 0),
                    duration_s=round(time.monotonic() - t0, 3),
                )
            time.sleep(_POLL_S)
        raise ProvisionError(f"guest command on vmid {vmid} did not exit within {timeout}s")

    # -- recycle / destroy -------------------------------------------------
    def reset(self, range_id: str) -> dict:
        for target in sorted(self.templates):
            vmid = self.vmid_for(range_id, target)
            if not self._vm_exists(vmid):
                continue
            upid = self.client.request(
                "POST",
                self.client.node_path("qemu", str(vmid), "snapshot", self.SNAPSHOT, "rollback"))
            if upid:
                self.client.wait_for_task(upid)
            if not self._vm_running(vmid):
                self._start(vmid)
        return self.provision(range_id, with_directory="directory" in self.templates)

    def teardown(self, range_id: str) -> None:
        for target in sorted(self.templates):
            vmid = self.vmid_for(range_id, target)
            if not self._vm_exists(vmid):
                continue
            try:
                upid = self.client.request(
                    "POST", self.client.node_path("qemu", str(vmid), "status", "stop"))
                if upid:
                    self.client.wait_for_task(upid, timeout=120)
            except ProvisionError:
                pass            # already stopped, or stopping raced the destroy
            try:
                upid = self.client.request(
                    "DELETE", self.client.node_path("qemu", str(vmid)), {"purge": 1})
                if upid:
                    self.client.wait_for_task(upid, timeout=300)
            except ProvisionError:
                pass            # teardown is best effort, as in the container tier


def from_env() -> ProxmoxProvisioner | None:
    """Build the tier from environment, or None when it is not configured."""
    host = os.environ.get("CR_PROXMOX_HOST")
    token_id = os.environ.get("CR_PROXMOX_TOKEN_ID")
    secret = os.environ.get("CR_PROXMOX_TOKEN_SECRET")
    node = os.environ.get("CR_PROXMOX_NODE")
    if not all((host, token_id, secret, node)):
        return None

    templates: dict[str, int] = {}
    for target, var in (("victim", "CR_PROXMOX_TEMPLATE_VICTIM"),
                        ("win-endpoint", "CR_PROXMOX_TEMPLATE_WINDOWS"),
                        ("directory", "CR_PROXMOX_TEMPLATE_DC")):
        raw = os.environ.get(var)
        if raw and raw.strip().isdigit():
            templates[target] = int(raw)
    if not templates:
        return None

    client = ProxmoxClient(
        host, token_id, secret, node=node,
        verify_tls=os.environ.get("CR_PROXMOX_VERIFY_TLS", "1").lower() not in ("0", "false", "no"),
    )
    return ProxmoxProvisioner(
        client, templates,
        bridge=os.environ.get("CR_PROXMOX_BRIDGE", "vmbr0"),
        vlan_base=int(os.environ.get("CR_PROXMOX_VLAN_BASE", "1000")),
        vmid_base=int(os.environ.get("CR_PROXMOX_VMID_BASE", "9000")),
        guest_user=os.environ.get("CR_PROXMOX_GUEST_USER") or None,
    )
