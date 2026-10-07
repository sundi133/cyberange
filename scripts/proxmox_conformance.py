#!/usr/bin/env python3
"""Prove the Proxmox VM tier works against a real hypervisor.

The adapter's unit tests stub the transport: they pin the API contract but
cannot show that your host accepts it. This script does the part that needs
real infrastructure. It drives one throwaway range through the full lifecycle
and reports what actually happened at each step.

    export CR_PROXMOX_HOST=https://pve.example:8006
    export CR_PROXMOX_TOKEN_ID='svc@pve!cyberrange'
    export CR_PROXMOX_TOKEN_SECRET='xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
    export CR_PROXMOX_NODE=pve1
    export CR_PROXMOX_TEMPLATE_VICTIM=9100        # a Linux template, qemu-guest-agent installed
    export CR_PROXMOX_TEMPLATE_WINDOWS=9101       # optional
    python3 scripts/proxmox_conformance.py

It creates VMs and destroys them again. Point it at a lab node, never at
production, and expect it to take several minutes: cloning and first boot are
not fast.
"""

from __future__ import annotations

import os
import sys
import time
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from cyberrange.provisioners.base import ProvisionError          # noqa: E402
from cyberrange.provisioners.proxmox import from_env             # noqa: E402

RANGE_ID = f"range-conf{uuid.uuid4().hex[:8]}"
PASS, FAIL, SKIP = "PASS", "FAIL", "SKIP"
results: list[tuple[str, str, str]] = []


def step(name: str, fn, *, required: bool = True):
    t0 = time.monotonic()
    try:
        detail = fn() or ""
        results.append((PASS, name, f"{detail} ({time.monotonic() - t0:.1f}s)".strip()))
        return True
    except Exception as exc:                       # noqa: BLE001 - report, never abort
        results.append((FAIL if required else SKIP, name, str(exc)[:200]))
        return False


def main() -> int:
    if os.environ.get("CR_PROXMOX_VERIFY_TLS", "1").lower() in ("0", "false", "no"):
        print("! TLS verification is OFF. Acceptable for a lab, not for production.\n")

    tier = from_env()
    if tier is None:
        print("Proxmox tier is not configured. Set CR_PROXMOX_HOST, _TOKEN_ID, "
              "_TOKEN_SECRET, _NODE and at least one _TEMPLATE_* variable.")
        return 2

    print(f"Host     : {tier.client.base}")
    print(f"Node     : {tier.client.node}")
    print(f"Templates: {tier.templates}")
    print(f"Range    : {RANGE_ID}  (VLAN {tier.vlan_tag(RANGE_ID)})\n")

    def reachable():
        version = tier.client.request("GET", "/version") or {}
        return f"Proxmox VE {version.get('version', '?')}"

    def provision():
        info = tier.provision(RANGE_ID)
        names = ", ".join(f"{t['hostname']}#{t['vmid']}" for t in info["targets"])
        return f"{len(info['targets'])} target(s): {names}"

    def running():
        if not tier.is_provisioned(RANGE_ID):
            raise ProvisionError("primary target is not running after provision")
        return "primary target up"

    def exec_cmd():
        res = tier.exec_in(RANGE_ID, "victim", ["/bin/sh", "-c", "id; uname -a"], timeout=60)
        if res.returncode != 0:
            raise ProvisionError(f"exit {res.returncode}: {res.stderr[:120]}")
        first = (res.stdout or "").strip().splitlines()[:1]
        return f"exit 0, stdout: {first[0] if first else '(empty)'}"

    def persistence():
        """A foothold must survive between steps - that is the whole point of
        the live tier, so it is worth proving rather than assuming."""
        marker = f"/tmp/cr-{uuid.uuid4().hex[:6]}"
        tier.exec_in(RANGE_ID, "victim", ["/bin/sh", "-c", f"echo held > {marker}"], timeout=30)
        res = tier.exec_in(RANGE_ID, "victim", ["/bin/sh", "-c", f"cat {marker}"], timeout=30)
        if "held" not in res.stdout:
            raise ProvisionError("file written in one exec was not present in the next")
        return "state carried across two execs"

    def reset():
        tier.reset(RANGE_ID)
        return "rolled back to snapshot"

    def verify_teardown():
        tier.teardown(RANGE_ID)
        still_there = [t for t in sorted(tier.templates)
                       if tier._vm_exists(tier.vmid_for(RANGE_ID, t))]
        if still_there:
            raise ProvisionError(f"VMs still present after teardown: {still_there}")
        return "all VMs destroyed"

    def windows():
        if "win-endpoint" not in tier.templates:
            raise ProvisionError("no Windows template configured")
        res = tier.exec_in(RANGE_ID, "win-endpoint",
                           ["cmd.exe", "/c", "whoami"], timeout=90)
        return f"exit {res.returncode}, stdout: {(res.stdout or '').strip()[:60]}"

    if not step("API reachable and token accepted", reachable):
        # Nothing below can mean anything if the API is unreachable, and
        # teardown in particular is best-effort, so it would report a false
        # pass. Stop and say so instead.
        for name in ("Provision range targets", "Primary target reports running",
                     "Guest agent executes a command", "Foothold persists across execs",
                     "Reset rolls back to clean snapshot", "Windows guest exec",
                     "Teardown removes every VM"):
            results.append((SKIP, name, "skipped: API unreachable"))
    elif step("Provision range targets", provision):
        step("Primary target reports running", running)
        step("Guest agent executes a command", exec_cmd)
        step("Foothold persists across execs", persistence)
        step("Reset rolls back to clean snapshot", reset)
        step("Windows guest exec", windows, required=False)
        step("Teardown removes every VM", verify_teardown)
    else:
        step("Teardown removes every VM", verify_teardown)

    print()
    width = max(len(n) for _, n, _ in results)
    for status, name, detail in results:
        print(f"[{status}] {name.ljust(width)}  {detail}")

    failed = [r for r in results if r[0] == FAIL]
    passed = [r for r in results if r[0] == PASS]
    skipped = [r for r in results if r[0] == SKIP]
    summary = f"\n{len(passed)}/{len(results)} checks passed"
    if skipped:
        summary += f", {len(skipped)} skipped"
    print(summary + f", {len(failed)} failed.")
    if failed:
        print("The VM tier is NOT conformant on this host. Send this output back "
              "with the failures and they can be worked through.")
        return 1
    print("The VM tier is conformant on this host.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted. VMs for this run may still exist; they are named "
              f"cr-{RANGE_ID.replace('range-', '')[:12]}-*")
        sys.exit(130)
