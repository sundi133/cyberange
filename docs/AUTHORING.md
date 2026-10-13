# Authoring scenarios

A scenario is a curated selection of modules plus a story — objectives, mode,
difficulty. The catalog ships 10, but a scenario is cheap to make because the
hard content (the modules) already exists: authoring is composition, not new
attack content. This is how a catalog grows from 10 to 100.

## The config format

Write a compact config (YAML or JSON) and the builder turns it into a full,
validated scenario. The minimum is a name, a mode, and the modules to run:

```yaml
name: Linux web-to-root
mode: red-blue              # red-blue | solo | purple
difficulty: intermediate    # introductory | intermediate | advanced
modules:
  - CR-MOD-WEBAPP-001
  - CR-MOD-EXEC-LNX-001
  - CR-MOD-PRIVESC-LNX-001
```

Everything else is derived or defaulted:

| Field | Default |
|---|---|
| `id` | generated from the name (`CR-CUSTOM-…`), made unique |
| `technique_ids` | the union of the modules' techniques |
| `topology_id` | `TOPO-DOCKER` if any module is docker, else `TOPO-STD5` |
| `safety_class` | the highest (most restrictive) of the modules' |
| `duration_min` | `[60, 90]` |
| `objectives` | a sensible pair for the mode (red/blue, or solo, or purple) |

Override any of them by adding the field. A file may hold one config (a mapping)
or several (a list). See `examples/scenario-configs/` for working examples.

## Building

```bash
python3 scripts/build_scenarios.py examples/scenario-configs/   # a directory
python3 scripts/build_scenarios.py my-scenario.yaml             # one file
python3 scripts/build_scenarios.py configs/ --merge             # add to existing
```

Output goes to `backend/cyberrange/seed/scenarios.staged.json`, which the
catalog loads alongside the curated seed. Built scenarios show in the catalog
marked **✎ Custom** and are launchable on the next server start. YAML configs
need PyYAML (a venv — see [IMPORTING.md](IMPORTING.md)); JSON configs need
nothing.

## The safety boundary

Validation is strict and it is the point: **every module a scenario references
must exist and be signed.** A scenario cannot be built on unsigned or imported
content. So a customer can author scenarios freely — and compose only modules a
reviewer already trusted. A scenario is safe by construction, which is why it
needs no separate signing of its own.

The builder rejects, with a message, any config that: has no name, uses an
invalid mode or difficulty, lists no modules, or references an unknown or
unsigned module.

## Letting customers author

This config format is the customer authoring path today: hand them the format,
they write configs, you (or they) run the builder. Because the builder refuses
unsigned modules, a customer cannot author their way around module review.

### In-product authoring (built)

Instructors and admins can also author without touching files. The Catalog has
a **✎ New scenario** button (shown to holders of the `scenario:author`
permission) that opens a form — name, mode, difficulty, and a picker of signed
modules. It posts to `POST /api/scenarios`, which runs the **same validation**
as the builder, so the UI can no more compose unsigned content than the config
path can. The scenario appears in the catalog immediately, marked Custom.

So there are two authoring paths on one validation layer: config files for bulk
and version control, the form for quick in-product creation.

### Still open

- [ ] Optional `learning` block (briefing, concepts, quiz) in both paths, so
      authored scenarios can be assigned as guided lessons, not just launched.
- [ ] Objectives and injects in the in-product form (the config path already
      takes them; the form currently uses the mode defaults).

---

## Production content roadmap (planned)

Priority order for production content, from a coverage review of the catalog
(33 modules spanning 13 of 14 ATT&CK Enterprise tactics - breadth is there,
these fill depth and the high-value surfaces):

- [x] **1. Finish the Windows VM tier.** DONE: the 9 existing Windows modules
      now carry `adapter:vm` execution specs that route through the Proxmox
      guest agent (and simulate off-tier); four new AD attack modules shipped
      - Kerberoasting (T1558.003), AS-REP (T1558.004), replication-rights
      exposure (T1003.006), NTLM lateral (T1550.002); 12 new detection rules
      (log-basis + sim fallback); the flagship CR-ADATTACK-001 scenario; and
      proxmox_conformance.py checks PowerShell + DC reachability. Still open:
      a Golden Ticket module (needs KRBTGT material - not safe to ship as
      marker, waiting on real sign-off batch below).
- [x] **2. Review and sign a depth batch from the importer.** DONE on the
      tooling side: `scripts/sign_modules.py` (list / preview / sign / batch /
      unsign / audit) with safety rails (PROHIBITED refused, S2 needs
      `--acknowledge-s2`, missing-fields refused, placeholder reviewer
      refused), append-only signing log, and three batch templates in
      `examples/sign-batches/`. Still open on the content side: run the batches
      against the real 1,862-module import on the operator machine (the
      staged file is gitignored, so this happens outside the repo).
- [x] **3. Curate a flagship ransomware chain.** DONE: three new Impact-stage
      modules in the marker-emission pattern - CR-MOD-INHIBIT-RECOVERY-001
      (T1490), CR-MOD-SVCSTOP-001 (T1489), CR-MOD-RANSOM-NOTE-001 (T1486);
      five new detection rules; and the flagship CR-RANSOM-FLAG-001 scenario
      chaining 8 stages from recon through canary-impact with timed injects
      and a lesson that teaches the inhibit-recovery / service-stop
      containment window.
- [x] **4. Cloud TTPs.** DONE: six starter cloud modules on the Docker-real
      tier (metadata-cred theft T1552.005, OAuth consent T1528, account
      manipulation T1098, cloud-storage access T1530, exfil-to-cloud
      T1567.002, mail-forward rule T1114.003); 12 detection rules
      (log-basis + sim fallback); flagship CR-CLOUD-FLAG-001 scenario; the
      CloudProvisioner adapter seam (`backend/cyberrange/provisioners/cloud.py`,
      MarkerCloudProvisioner + from_env + resolver precedence); and
      `docs/CLOUD_SETUP.md` showing how a customer plugs their cloud SDK
      into the seam for Phase 2 real-tier execution.
