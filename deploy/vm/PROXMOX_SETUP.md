# Setting up the Proxmox VM tier

Step by step, from a bare Proxmox node to CyberRange running exercises on real
virtual machines. Budget about an hour for the Linux path, plus however long a
Windows install takes you.

Work through it in order and run the conformance script at the end. Until that
passes, the tier is not verified on your infrastructure and should not be
described as working.

---

## 0. What you need first

- **Proxmox VE 7.x or 8.x**, one node is enough to start.
- Enough storage for one full clone per target, per concurrent range. A Linux
  target is a few GB; a Windows Server template is 20–40 GB. Full clones are
  used deliberately, so ranges cannot affect each other through a shared base
  disk.
- A network bridge (usually `vmbr0`) that is **VLAN aware**.
- The CyberRange host must be able to reach the Proxmox API on port **8006**.

---

## 1. Create a dedicated API user and token

Do not use `root@pam`. Make a service account scoped to what the tier needs.

On the Proxmox node:

```bash
# A user for CyberRange, in the built-in PVE realm
pveum user add svc-cyberrange@pve --comment "CyberRange control plane"

# A role with exactly the privileges the adapter uses
pveum role add CyberRange --privs "\
VM.Allocate,VM.Clone,VM.Config.Disk,VM.Config.CPU,VM.Config.Memory,\
VM.Config.Network,VM.Config.Options,VM.Monitor,VM.PowerMgmt,\
VM.Snapshot,VM.Snapshot.Rollback,VM.Audit,\
Datastore.AllocateSpace,Datastore.Audit,Sys.Audit"

pveum acl modify / --user svc-cyberrange@pve --role CyberRange

# The token the adapter authenticates with
pveum user token add svc-cyberrange@pve cyberrange --privsep 0
```

That last command prints the secret **once**. Copy it now; Proxmox will not
show it again.

```
┌──────────────┬──────────────────────────────────────┐
│ full-tokenid │ svc-cyberrange@pve!cyberrange        │
│ value        │ 1a2b3c4d-5e6f-7890-abcd-ef1234567890 │
└──────────────┴──────────────────────────────────────┘
```

Why these privileges:

| Privilege | Used for |
|---|---|
| `VM.Clone`, `VM.Allocate`, `Datastore.AllocateSpace` | cloning templates into range VMs |
| `VM.Config.Network` | pinning each clone to its range VLAN |
| `VM.PowerMgmt` | start and stop |
| `VM.Monitor` | **guest agent exec** — module execution fails without it |
| `VM.Snapshot`, `VM.Snapshot.Rollback` | the clean baseline and `reset` |
| `Sys.Audit` | the `/version` reachability check |

`--privsep 0` makes the token inherit the user's permissions. If you prefer
privilege separation, set `--privsep 1` and grant the role to the token as
well with `pveum acl modify / --tokens 'svc-cyberrange@pve!cyberrange' --role CyberRange`.

---

## 2. Build the Linux target template

The guest agent is not optional. Module execution goes through it, so a
template without it produces a tier that provisions fine and then cannot run
anything.

Using a Debian cloud image:

```bash
VMID=9100
wget https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2

qm create $VMID --name cyberrange-linux --memory 2048 --cores 2 \
  --net0 virtio,bridge=vmbr0 --scsihw virtio-scsi-pci --ostype l26
qm importdisk $VMID debian-12-genericcloud-amd64.qcow2 local-lvm
qm set $VMID --scsi0 local-lvm:vm-$VMID-disk-0
qm set $VMID --boot order=scsi0 --serial0 socket --vga serial0
qm set $VMID --ide2 local-lvm:cloudinit --agent enabled=1
qm set $VMID --ciuser rangeadmin --cipassword 'change-me' --ipconfig0 ip=dhcp
```

Boot it once and install the agent inside the guest, because the cloud image
does not ship it:

```bash
qm start $VMID
# then, in the guest console:
apt-get update && apt-get install -y qemu-guest-agent
systemctl enable --now qemu-guest-agent
poweroff
```

Confirm the agent answers before going further:

```bash
qm start $VMID && sleep 30
qm agent $VMID ping && echo "agent OK"
qm stop $VMID
qm template $VMID
```

If `qm agent ping` fails, stop here and fix it. Everything downstream depends
on it.

---

## 3. Build the Windows template (optional)

This is what the whole tier exists for — Kerberos, SMB, GPO, NTLM — but it is
the slow part, and the Linux path works without it.

1. Create a VM with `--ostype win11` (or `win10`/`win2k22`), attach the Windows
   ISO and the **virtio-win** ISO.
2. Install Windows. Load the virtio SCSI driver from the second ISO when the
   installer finds no disk.
3. In the guest, run `virtio-win-guest-tools.exe` from the virtio ISO. This
   installs **qemu-guest-agent** along with the drivers.
4. Enable the agent on the VM: `qm set <vmid> --agent enabled=1`.
5. Verify from the node: `qm agent <vmid> ping`.
6. Sysprep and generalise, shut down, then `qm template <vmid>`.

**Licensing is yours to handle.** Evaluation ISOs are fine for a lab and expire
on Microsoft's schedule.

---

## 4. Isolate the ranges

The tier assigns each range its own VLAN tag, derived from the range id, and
pins every clone's NIC to it. **That tag makes isolation enforceable; it does
not enforce it.** Without a corresponding rule, two ranges on the same bridge
can still reach each other.

Pick one:

- **Switch VLANs** — trunk the tags to the Proxmox node and set your switch to
  deny inter-VLAN routing for the range block. Make sure `vmbr0` is VLAN aware
  (`Datacenter → node → Network → vmbr0 → VLAN aware`).
- **Proxmox SDN** — create a zone for the range block with no gateway, so the
  VLANs have no route out or between each other.

Also decide on egress. The container tier uses `--internal` (no internet at
all). The closest equivalent here is a VLAN with no gateway. If your range
VLANs can reach the internet, say so in your scenario design, because it is a
different safety posture from what the container tier gives.

Default VLAN block is `1000`–`1499` (`CR_PROXMOX_VLAN_BASE` plus a per-range
slot of 0–499). Move it with `CR_PROXMOX_VLAN_BASE` if that collides with
something.

---

## 5. Point CyberRange at it

On the CyberRange host:

```bash
export CR_PROXMOX_HOST=https://pve.example.com:8006
export CR_PROXMOX_TOKEN_ID='svc-cyberrange@pve!cyberrange'
export CR_PROXMOX_TOKEN_SECRET='1a2b3c4d-5e6f-7890-abcd-ef1234567890'
export CR_PROXMOX_NODE=pve1
export CR_PROXMOX_TEMPLATE_VICTIM=9100
export CR_PROXMOX_TEMPLATE_WINDOWS=9101     # optional
export CR_PROXMOX_TEMPLATE_DC=9102          # optional
export CR_PROXMOX_BRIDGE=vmbr0
```

Keep the secret out of shell history and out of git — a systemd unit's
`EnvironmentFile` with `chmod 600`, or your platform's secret store.

If Proxmox still has its self-signed certificate, add
`CR_PROXMOX_VERIFY_TLS=0`. That disables certificate checking for API calls, so
it is a lab-only shortcut; the proper fix is a real certificate on the node.

---

## 6. Prove it works

```bash
python3 scripts/proxmox_conformance.py
```

It creates one throwaway range, runs it through the whole lifecycle, and
destroys it:

```
[PASS] API reachable and token accepted    Proxmox VE 8.1.4 (0.4s)
[PASS] Provision range targets             2 target(s): victim#9050, win-endpoint#9051 (94.2s)
[PASS] Primary target reports running      primary target up (0.2s)
[PASS] Guest agent executes a command      exit 0, stdout: uid=0(root) gid=0(root) (1.1s)
[PASS] Foothold persists across execs      state carried across two execs (1.8s)
[PASS] Reset rolls back to clean snapshot  rolled back to snapshot (22.6s)
[PASS] Windows guest exec                  exit 0, stdout: range\administrator (3.4s)
[PASS] Teardown removes every VM           all VMs destroyed (11.9s)

8/8 checks passed, 0 failed.
The VM tier is conformant on this host.
```

Anything short of that, the tier is not ready. Send me the output and I'll work
through the failures.

---

## 7. Confirm it in the product

```bash
curl -s localhost:8080/api/health | python3 -m json.tool
```

```json
"targets": { "tier": "proxmox", "selected": "proxmox VM tier" }
```

`"tier": "docker"` means the configuration was incomplete and it silently fell
back — `selected` says which variable is missing.

Then create a range in the UI and watch VMs named `cr-<range>-victim` appear in
the Proxmox console.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| `tier: docker` after configuring | A required variable is unset. `selected` names the gap. |
| `proxmox unreachable` | Firewall between CyberRange and port 8006, or a wrong scheme. The host needs `https://`. |
| `401` / `403` on every call | Token id must include the realm and token name: `user@pve!tokenname`. With `--privsep 1`, the token needs its own ACL entry. |
| `guest agent not responding` | Agent not installed in the guest, or `--agent enabled=1` not set on the template. `qm agent <vmid> ping` on the node is the fastest check. |
| Clone succeeds, exec fails | Almost always the `VM.Monitor` privilege. |
| Ranges can reach each other | VLAN tags are set but nothing enforces them. See step 4. |
| Reset does nothing | The `cyberrange-clean` snapshot is missing. The tier takes it on first provision; if a VM was created another way, snapshot it manually with that name. |

---

## What still does not work

**Windows modules remain simulated even with the tier running.** All 11 of them
ship without a `vm` execution spec, so there is nothing for the tier to
execute. Getting real Windows telemetry needs those specs written and tested
against a live template — the next piece of work after conformance passes on
your host, not something to assume is already there.
