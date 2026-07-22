# VM tier - real Windows / Active Directory targets (roadmap)

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

A `VMProvisioner` mirrors these four operations against a real hypervisor; the
control plane above (lifecycle, exercises, modules, detection, SIEM) is
unchanged. `execute_module` already selects the runner by adapter, so Windows
modules would carry `"execution": {"adapter": "vm", "target": "win-endpoint", …}`.

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

## Honest status

- **Available today (real, verified):** Linux container ranges + an **LDAP
  directory identity tier** you can attack (account discovery over LDAP).
- **This VM tier (real Windows/AD):** roadmap. It requires a hypervisor and
  Windows images, so it is authored as an interface/seam and operator guidance
  rather than shipped and "verified" against infrastructure that isn't present.
  Nothing in the product claims a running Windows VM until this adapter is wired
  to your hypervisor.
