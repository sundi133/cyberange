# VM tier - real Windows / Active Directory targets

CyberRange's live container ranges provide **real, connected Linux targets**
today (`provisioning.py`): a persistent victim host, a reachable webapp target,
and - for identity scenarios - a **real LDAP directory** (an AD-*style* identity
attack surface, seeded with domain users you can enumerate over LDAP).

What containers **cannot** give you is a real **Windows** endpoint or a real
**Windows Active Directory domain controller** (Kerberos, SMB, GPO, NTLM, the
Windows attack surface). That needs full virtual machines, which need a
**hypervisor** - and therefore your own infrastructure. This directory
documents that tier and the integration seam; it is **not runnable on the app
host alone** and is intentionally not faked in code.

## The seam it plugs into

Container provisioning already defines the exact interface a VM tier implements
(`cyberrange/provisioning.py`):

| Container provisioner | VM-tier equivalent |
|---|---|
| `provision(range_id)` - create network + containers | create an isolated VLAN + clone VM templates |
| `exec_in_victim(range_id, cmd)` | run a command on a VM (WinRM / SSH / guest agent) |
| `reset(range_id)` | revert VMs to a clean snapshot |
| `teardown(range_id)` | destroy the VMs + network |

That seam is now an explicit contract rather than a description:
`cyberrange/provisioners/base.py` defines `RangeProvisioner`, the container
tier implements it (`containers.py`), and the Proxmox tier implements it
(`proxmox.py`). The control plane holds whichever tier is configured and is
otherwise unchanged. Windows modules carry
`"execution": {"adapter": "vm", "target": "win-endpoint", …}`.

## What a real deployment needs (operator-provided)

- A **hypervisor**: KVM/libvirt, Proxmox VE, VMware ESXi, or a cloud (AWS EC2 /
  Azure - Azure is natural for real Windows/AD).
- **Windows images**: e.g. Windows Server / Windows 11 **evaluation** ISOs,
  sysprepped into templates. (Licensing is the customer's responsibility.)
- **Isolation**: per-range VLAN/VXLAN, default-deny like the container `--internal`
  network.
- A guest-exec path: WinRM or a guest agent for module execution + snapshots for
  `reset`.

### Reference approaches

- **libvirt/KVM**: `virt-clone` from a sysprepped template → `virsh snapshot-create`
  for reset → WinRM (`pywinrm`) for exec → `virsh destroy/undefine` for teardown.
- **Proxmox**: clone via the API (`/nodes/{n}/qemu/{vmid}/clone`), rollback to a
  snapshot for reset, QEMU guest agent `exec` for commands.

## Configuring the Proxmox tier

Step-by-step operator setup - API token and privileges, building the Linux
and Windows templates, VLAN isolation, and proving it works:
**[PROXMOX_SETUP.md](PROXMOX_SETUP.md)**. The variables themselves:

The tier activates when these are set; otherwise the container tier is used and
`GET /api/health` reports which one is live under `targets`.

| Variable | Meaning |
|---|---|
| `CR_PROXMOX_HOST` | e.g. `https://pve.example:8006` |
| `CR_PROXMOX_TOKEN_ID` | e.g. `svc@pve!cyberrange` |
| `CR_PROXMOX_TOKEN_SECRET` | the token's UUID secret |
| `CR_PROXMOX_NODE` | node name, e.g. `pve1` |
| `CR_PROXMOX_TEMPLATE_VICTIM` | VMID of a Linux template with qemu-guest-agent |
| `CR_PROXMOX_TEMPLATE_WINDOWS` | VMID of a sysprepped Windows template (optional) |
| `CR_PROXMOX_TEMPLATE_DC` | VMID of a domain controller template (optional) |
| `CR_PROXMOX_BRIDGE` | bridge for range NICs, default `vmbr0` |
| `CR_PROXMOX_VLAN_BASE` | first VLAN tag to allocate, default `1000` |
| `CR_PROXMOX_VMID_BASE` | first VMID to allocate, default `9000` |
| `CR_PROXMOX_VERIFY_TLS` | `0` to accept Proxmox's self-signed cert (lab only) |

Each range gets its own VLAN tag and its own VMIDs, both derived from the range
id. **Inter-VLAN default-deny is the hypervisor's job** - the tag makes it
enforceable, it does not enforce it. Configure that on your switch or SDN zone,
or ranges will be able to reach each other.

Guest exec uses the QEMU guest agent, so **every template must have
qemu-guest-agent installed and enabled**, and snapshots named
`cyberrange-clean` are what `reset` rolls back to (the tier takes that snapshot
itself on first provision).

## Honest status

- **Available today (real, verified):** Linux container ranges + an **LDAP
  directory identity tier** you can attack (account discovery over LDAP).
- **Proxmox VM tier:** the adapter is **written and unit-tested against a
  stubbed API** (16 tests in `backend/tests/test_proxmox.py`), which pins the
  request contract - endpoints, ordering, parameters, how guest output becomes
  an `ExecResult`. It has **not been run against a live hypervisor**, because
  none is present in this repository.
- **Before claiming this tier works**, run it against your own host:

  ```bash
  python3 scripts/proxmox_conformance.py
  ```

  It drives one throwaway range through provision → exec → persistence →
  reset → teardown and prints a pass/fail line per step. Until that passes on
  your infrastructure, the tier is unverified and should be described that way.
- **Windows modules** still carry no `vm` execution specs, so Windows behaviour
  remains simulated even with the tier configured. Wiring those is the next
  step after conformance passes.

## Decisions and TODO

**Chosen path: Proxmox on GCP.** Where there is no spare hardware, the VM tier
runs against Proxmox VE on a nested-virtualization GCP instance. This drives the
existing, tested `ProxmoxProvisioner` unchanged — see
[PROXMOX_SETUP.md](PROXMOX_SETUP.md), including the GCP appendix.

Open work, in priority order:

- [ ] **Write `vm` execution specs for the Windows modules.** All 11 Windows
      modules simulate today because none carry a command for the tier to run.
      This is the blocker for real Windows/AD telemetry, and the next step once
      `scripts/proxmox_conformance.py` passes on a real node.
- [ ] **Run the conformance script against a live Proxmox node** and record the
      result. The adapter is unit-tested against a stubbed API but unverified on
      hardware until this passes.
- [ ] **(Optional, if GCP becomes the permanent home) a native `GCEProvisioner`.**
      The provisioner seam (`cyberrange/provisioners/base.py`) makes this a
      drop-in third tier alongside Docker and Proxmox: create instances from
      images, snapshot/revert for reset, guest-agent or OS Login for exec — no
      nested virtualization, likely cheaper and faster than Proxmox-on-GCP.
      Not started; only worth it if GCP is the target rather than a stopgap.
      Would need the same stub-tests-plus-conformance treatment.
