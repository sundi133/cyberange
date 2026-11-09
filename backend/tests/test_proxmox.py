"""Proxmox VM tier, against a stubbed API.

No hypervisor is present in this repository, so the transport is stubbed and
these tests pin the *contract*: which endpoints are called, in what order, with
what parameters, and how responses are turned into an ExecResult. They prove
the adapter speaks the documented Proxmox VE API shape - they do not prove it
works against a real host. That is what scripts/proxmox_conformance.py is for.
"""

import io
import json
import unittest
import urllib.error
import urllib.parse

from cyberrange.provisioners import ContainerProvisioner, resolve
from cyberrange.provisioners.base import ExecResult, ProvisionError
from cyberrange.provisioners.proxmox import ProxmoxClient, ProxmoxProvisioner


class _Resp(io.BytesIO):
    """Minimal stand-in for an http.client.HTTPResponse in a with-block."""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class StubOpener:
    """Records requests and replays canned responses keyed by 'METHOD path'."""

    def __init__(self, routes=None):
        self.routes = routes or {}
        self.calls = []            # [(method, path, body)]

    def open(self, req, timeout=None):
        path = req.full_url.split("/api2/json", 1)[1]
        bare = path.split("?", 1)[0]
        body = req.data.decode() if req.data else ""
        self.calls.append((req.get_method(), bare, body))
        if "Authorization" not in dict(req.header_items()):
            raise AssertionError("request sent without an API token header")
        key = f"{req.get_method()} {bare}"
        if key not in self.routes:
            raise urllib.error.HTTPError(req.full_url, 404, "not found", {}, io.BytesIO(b"{}"))
        value = self.routes[key]
        data = value.pop(0) if isinstance(value, list) else value
        return _Resp(json.dumps({"data": data}).encode())

    def paths(self, method=None):
        return [p for m, p, _ in self.calls if method is None or m == method]


def _client(routes):
    stub = StubOpener(routes)
    return ProxmoxClient("https://pve.example:8006", "svc@pve!cr", "secret",
                         node="pve1", opener=stub), stub


class ProxmoxClientTest(unittest.TestCase):
    def test_sends_token_and_unwraps_data(self):
        client, stub = _client({"GET /nodes/pve1/qemu/9000/status/current": {"status": "running"}})
        self.assertEqual(client.request("GET", "/nodes/pve1/qemu/9000/status/current"),
                         {"status": "running"})
        self.assertEqual(stub.calls[0][0], "GET")

    def test_post_params_are_form_encoded(self):
        client, stub = _client({"POST /nodes/pve1/qemu/9000/config": None})
        client.request("POST", "/nodes/pve1/qemu/9000/config", {"net0": "virtio,tag=1001"})
        self.assertIn("net0=virtio", stub.calls[0][2])

    def test_http_error_becomes_provision_error(self):
        client, _ = _client({})
        with self.assertRaises(ProvisionError):
            client.request("GET", "/nodes/pve1/qemu/1/status/current")

    def test_failed_task_raises(self):
        client, _ = _client({
            "GET /nodes/pve1/tasks/UPID:x/status": {"status": "stopped", "exitstatus": "clone failed"},
        })
        with self.assertRaises(ProvisionError) as ctx:
            client.wait_for_task("UPID:x")
        self.assertIn("clone failed", str(ctx.exception))

    def test_successful_task_returns(self):
        client, _ = _client({
            "GET /nodes/pve1/tasks/UPID:ok/status": {"status": "stopped", "exitstatus": "OK"},
        })
        client.wait_for_task("UPID:ok")          # must not raise


class ProxmoxProvisionerTest(unittest.TestCase):
    TEMPLATES = {"victim": 100, "win-endpoint": 101}

    def _provisioner(self, routes):
        client, stub = _client(routes)
        return ProxmoxProvisioner(client, dict(self.TEMPLATES), vlan_base=1000,
                                  vmid_base=9000), stub

    def test_ids_are_stable_and_distinct_per_target(self):
        p, _ = self._provisioner({})
        a1 = p.vmid_for("range-abc", "victim")
        self.assertEqual(a1, p.vmid_for("range-abc", "victim"))         # stable
        self.assertNotEqual(a1, p.vmid_for("range-abc", "win-endpoint"))  # per target
        self.assertNotEqual(p.vlan_tag("range-abc"), p.vlan_tag("range-zzz"))  # per range

    def test_slot_is_deterministic_across_processes(self):
        # Python's hash() is salted per process; the slot must not use it.
        # These values are what the stable algorithm must produce, so a
        # change in the algorithm (and thus the VMIDs of existing ranges)
        # will trip this test rather than quietly re-point exec/reset at
        # the wrong VMs after a control-plane restart.
        p, _ = self._provisioner({})
        self.assertEqual(p._slot("range-abc"), 23)
        self.assertEqual(p._slot("range-xyz"), 374)

    def test_provision_clones_starts_and_snapshots(self):
        p, stub = self._provisioner({})
        v = p.vmid_for("range-abc", "victim")
        w = p.vmid_for("range-abc", "win-endpoint")
        # No status/current route: both VMs read as absent, so both are cloned.
        stub.routes = {
            "POST /nodes/pve1/qemu/100/clone": "UPID:clone1",
            "POST /nodes/pve1/qemu/101/clone": "UPID:clone2",
            "GET /nodes/pve1/tasks/UPID:clone1/status": {"status": "stopped", "exitstatus": "OK"},
            "GET /nodes/pve1/tasks/UPID:clone2/status": {"status": "stopped", "exitstatus": "OK"},
            f"POST /nodes/pve1/qemu/{v}/config": None,
            f"POST /nodes/pve1/qemu/{w}/config": None,
            f"POST /nodes/pve1/qemu/{v}/status/start": None,
            f"POST /nodes/pve1/qemu/{w}/status/start": None,
            f"GET /nodes/pve1/qemu/{v}/agent/ping": {},
            f"GET /nodes/pve1/qemu/{w}/agent/ping": {},
            f"POST /nodes/pve1/qemu/{v}/snapshot": None,
            f"POST /nodes/pve1/qemu/{w}/snapshot": None,
        }
        info = p.provision("range-abc")
        self.assertEqual(len(info["targets"]), 2)
        self.assertEqual(info["network"], f"vlan{p.vlan_tag('range-abc')}")
        self.assertIn("POST /nodes/pve1/qemu/100/clone",
                      [f"{m} {path}" for m, path, _ in stub.calls])
        # the clone must be pinned to this range's VLAN before it is used
        cfg = [urllib.parse.unquote_plus(body)
               for _, path, body in stub.calls if path.endswith(f"/{v}/config")]
        self.assertTrue(any(f"tag={p.vlan_tag('range-abc')}" in b for b in cfg),
                        f"clone was not pinned to the range VLAN: {cfg}")

    def test_exec_polls_until_exit_and_returns_real_output(self):
        p, stub = self._provisioner({})
        v = p.vmid_for("range-abc", "victim")
        stub.routes = {
            f"POST /nodes/pve1/qemu/{v}/agent/exec": {"pid": 42},
            f"GET /nodes/pve1/qemu/{v}/agent/exec-status": [
                {"exited": 0},
                {"exited": 1, "out-data": "uid=0(root)\n", "err-data": "", "exitcode": 0},
            ],
        }
        res = p.exec_in("range-abc", "victim", ["id"], timeout=10)
        self.assertIsInstance(res, ExecResult)
        self.assertEqual(res.stdout, "uid=0(root)\n")
        self.assertEqual(res.returncode, 0)
        self.assertGreaterEqual(res.duration_s, 0)
        # polled at least twice: once not exited, once exited
        self.assertGreaterEqual(
            sum(1 for _, path, _ in stub.calls if path.endswith("exec-status")), 2)

    def test_exec_surfaces_guest_exit_code(self):
        p, stub = self._provisioner({})
        v = p.vmid_for("range-abc", "victim")
        stub.routes = {
            f"POST /nodes/pve1/qemu/{v}/agent/exec": {"pid": 7},
            f"GET /nodes/pve1/qemu/{v}/agent/exec-status": {
                "exited": 1, "out-data": "", "err-data": "denied", "exitcode": 13},
        }
        res = p.exec_in("range-abc", "victim", ["whoami"])
        self.assertEqual(res.returncode, 13)
        self.assertEqual(res.stderr, "denied")

    def test_exec_on_unknown_target_refuses(self):
        p, _ = self._provisioner({})
        with self.assertRaises(ProvisionError):
            p.exec_in("range-abc", "nope", ["id"])

    def test_exec_without_pid_raises(self):
        p, stub = self._provisioner({})
        v = p.vmid_for("range-abc", "victim")
        stub.routes = {f"POST /nodes/pve1/qemu/{v}/agent/exec": {}}
        with self.assertRaises(ProvisionError):
            p.exec_in("range-abc", "victim", ["id"])

    def test_reset_rolls_back_to_the_clean_snapshot(self):
        p, stub = self._provisioner({})
        v = p.vmid_for("range-abc", "victim")
        w = p.vmid_for("range-abc", "win-endpoint")
        snap = [{"name": p.SNAPSHOT}]
        stub.routes = {
            f"GET /nodes/pve1/qemu/{v}/status/current": {"status": "running"},
            f"GET /nodes/pve1/qemu/{w}/status/current": {"status": "running"},
            # snapshot present (reset checks, then provision re-checks)
            f"GET /nodes/pve1/qemu/{v}/snapshot": [snap, snap],
            f"GET /nodes/pve1/qemu/{w}/snapshot": [snap, snap],
            f"POST /nodes/pve1/qemu/{v}/status/stop": None,
            f"POST /nodes/pve1/qemu/{w}/status/stop": None,
            f"POST /nodes/pve1/qemu/{v}/snapshot/{p.SNAPSHOT}/rollback": None,
            f"POST /nodes/pve1/qemu/{w}/snapshot/{p.SNAPSHOT}/rollback": None,
        }
        p.reset("range-abc")
        rollbacks = [path for _, path, _ in stub.calls if "rollback" in path]
        self.assertEqual(len(rollbacks), 2)
        # a running guest must be stopped before the (RAM-less) rollback
        stops = [path for m, path, _ in stub.calls
                 if m == "POST" and path.endswith("/status/stop")]
        self.assertEqual(len(stops), 2)

    def test_reset_snapshots_when_baseline_missing(self):
        p, stub = self._provisioner({})
        v = p.vmid_for("range-abc", "victim")
        w = p.vmid_for("range-abc", "win-endpoint")
        snap = [{"name": p.SNAPSHOT}]
        stub.routes = {
            f"GET /nodes/pve1/qemu/{v}/status/current": {"status": "running"},
            f"GET /nodes/pve1/qemu/{w}/status/current": {"status": "running"},
            # absent first (reset), present after it is taken (provision re-check)
            f"GET /nodes/pve1/qemu/{v}/snapshot": [[], snap],
            f"GET /nodes/pve1/qemu/{w}/snapshot": [[], snap],
            f"POST /nodes/pve1/qemu/{v}/snapshot": None,
            f"POST /nodes/pve1/qemu/{w}/snapshot": None,
        }
        p.reset("range-abc")
        snaps = [path for m, path, _ in stub.calls
                 if m == "POST" and path.endswith("/snapshot")]
        rolls = [path for _, path, _ in stub.calls if "rollback" in path]
        self.assertEqual(len(snaps), 2)   # baseline created, not rolled back
        self.assertEqual(len(rolls), 0)

    def test_provision_refuses_a_slot_collision(self):
        p, stub = self._provisioner({})
        v = p.vmid_for("range-abc", "victim")
        stub.routes = {
            f"GET /nodes/pve1/qemu/{v}/status/current": {"status": "running"},
            f"GET /nodes/pve1/qemu/{v}/config":
                {"description": "cyberrange=range-other target=victim"},
        }
        with self.assertRaises(ProvisionError) as cm:
            p.provision("range-abc")
        self.assertIn("owned by range", str(cm.exception))

    def test_preflight_passes_on_a_ready_host(self):
        p, stub = self._provisioner({})
        stub.routes = {
            "GET /version": {"version": "8.1.4"},
            "GET /nodes/pve1/status": {"uptime": 1},
            "GET /nodes/pve1/qemu/100/config": {"template": 1, "agent": "enabled=1"},
            "GET /nodes/pve1/qemu/101/config": {"template": 1, "agent": "1"},
            "GET /nodes/pve1/network/vmbr0": {"bridge_vlan_aware": 1},
        }
        levels = {name: lvl for lvl, name, _ in p.preflight()}
        self.assertTrue(all(v == "pass" for v in levels.values()), levels)

    def test_preflight_flags_missing_agent_and_bridge(self):
        p, stub = self._provisioner({})
        stub.routes = {
            "GET /version": {"version": "8.1.4"},
            "GET /nodes/pve1/status": {"uptime": 1},
            "GET /nodes/pve1/qemu/100/config": {"template": 1},          # no agent
            "GET /nodes/pve1/qemu/101/config": {"template": 1, "agent": "1"},
            "GET /nodes/pve1/network/vmbr0": {"bridge_vlan_aware": 0},   # not VLAN-aware
        }
        levels = {name: lvl for lvl, name, _ in p.preflight()}
        self.assertEqual(levels["Template 'victim'"], "fail")
        self.assertEqual(levels["VLAN-aware bridge (range isolation)"], "warn")

    def test_teardown_is_best_effort(self):
        p, stub = self._provisioner({})
        v = p.vmid_for("range-abc", "victim")
        stub.routes = {
            f"GET /nodes/pve1/qemu/{v}/status/current": {"status": "running"},
            f"POST /nodes/pve1/qemu/{v}/status/stop": None,
            f"DELETE /nodes/pve1/qemu/{v}": None,
        }
        p.teardown("range-abc")        # the other VM 404s throughout; must not raise
        self.assertIn("DELETE", [m for m, _, _ in stub.calls])

    def test_requires_at_least_one_template(self):
        client, _ = _client({})
        with self.assertRaises(ProvisionError):
            ProxmoxProvisioner(client, {})


class TierSelectionTest(unittest.TestCase):
    def test_defaults_to_containers(self):
        self.assertIsInstance(resolve(), ContainerProvisioner)

    def test_incomplete_proxmox_config_falls_back_without_crashing(self):
        import os
        os.environ["CR_PROXMOX_HOST"] = "https://pve.example:8006"
        try:
            tier = resolve()          # no token / node / templates set
            self.assertIsInstance(tier, ContainerProvisioner)
        finally:
            os.environ.pop("CR_PROXMOX_HOST", None)


if __name__ == "__main__":
    unittest.main()
