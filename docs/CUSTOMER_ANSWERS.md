# CyberRange — Customer Capability Answers

This document answers the nine questions a customer most often asks when
evaluating CyberRange. Every figure below is drawn directly from the shipping
catalog (29 modules, 10 scenarios) and the platform configuration, not from a
roadmap. Where something is simulated rather than executed for real, it says so
plainly.

---

## 1. Description of each module and its features

A **module** is one atomic adversary behavior, mapped to MITRE ATT&CK, carrying
a **safety class** (S0–S2 / PROHIBITED) and an **execution tier**. Modules that
ship with an `execution` spec run *for real* on disposable lab assets when a
container/VM target is available; the rest emit **declared synthetic telemetry**
("sim") that the detection engine still scores. A module only runs if it is
**signed** — the hard execution gate the service enforces for every role,
including admin.

The catalog ships **36 modules**. **16 execute real on Docker** (commodity
hardware). **16 more carry a `vm` execution spec** that runs them for real on
the Proxmox VM tier when it is provisioned with licensed Windows/DC templates;
off the VM tier they simulate automatically. Across the catalog: **14 Linux,
18 Windows, 4 Docker**.

| Module | Class | Platform | Tier | ATT&CK | What it does |
|---|---|---|---|---|---|
| CR-MOD-RECON-001 | S1 | Linux | real | T1595, T1018 | Lab service/host discovery scan |
| CR-MOD-PHISH-001 | S0 | Windows | sim | T1566, T1204 | Phishing attachment delivery to a seeded mailbox |
| CR-MOD-EXEC-WIN-001 | S1 | Windows | sim | T1059 | PowerShell interpreter execution behavior |
| CR-MOD-EXEC-LNX-001 | S1 | Linux | real | T1059 | Bash interpreter execution |
| CR-MOD-PERSIST-WIN-001 | S1 | Windows | sim | T1053 | Scheduled-task persistence |
| CR-MOD-PERSIST-LNX-001 | S1 | Linux | real | T1053 | Cron-job persistence |
| CR-MOD-PRIVESC-WIN-001 | S2 | Windows | sim | T1548 | Local misconfiguration privilege path |
| CR-MOD-PRIVESC-LNX-001 | S2 | Linux | real | T1548 | SUID/sudo misconfiguration escalation |
| CR-MOD-EVADE-WIN-001 | S1 | Windows | sim | T1070 | Benign Windows event-log tamper |
| CR-MOD-EVADE-LNX-001 | S1 | Linux | real | T1070 | Benign Linux log/artifact manipulation |
| CR-MOD-CRED-WIN-001 | S1 | Windows | sim | T1003 | Synthetic credential-dump simulation |
| CR-MOD-DISC-WIN-001 | S0 | Windows | sim | T1087 | Active Directory account discovery |
| CR-MOD-DISC-LNX-001 | S0 | Linux | real | T1018 | Remote-system discovery |
| CR-MOD-LATERAL-WIN-001 | S1 | Windows | sim | T1021 | Remote-service lateral movement |
| CR-MOD-COLLECT-001 | S1 | Windows | sim | T1005, T1560 | Tagged synthetic file collection |
| CR-MOD-C2-001 | S0 | Linux | sim | T1071 | Internal C2 beacon simulation |
| CR-MOD-EXFIL-001 | S1 | Linux | sim | T1041 | Synthetic exfiltration to an internal sink |
| CR-MOD-DOCKER-DISC-001 | S1 | Docker | real | T1613 | Container/image/network enumeration |
| CR-MOD-DOCKER-SECRET-001 | S1 | Docker | real | T1552, T1613 | Exposed synthetic secret access |
| CR-MOD-DOCKER-RUNTIME-001 | S1 | Docker | real | T1610 | Abnormal container runtime activity |
| CR-MOD-DOCKER-ESCAPE-001 | S2 | Docker | real | T1611 | Container-to-host **boundary test** (safe; boundary holds) |
| CR-MOD-WEBAPP-001 | S1 | Linux | real | T1190, T1059 | Vulnerable web-app entry to host |
| CR-MOD-IMPACT-001 | S2 | Windows | sim | T1486 | **Canary-file** encryption simulation |
| CR-MOD-IDENT-001 | S1 | Windows | sim | T1078, T1021 | Seeded password-reuse remote logon |
| CR-MOD-AD-DISC-001 | S0 | Linux | real | T1087 | Directory account discovery (LDAP) |
| CR-MOD-INGRESS-001 | S1 | Linux | real | T1105 | Ingress tool transfer from a staging host |
| CR-MOD-ARCHIVE-001 | S1 | Linux | real | T1560 | Archive collected data for staging |
| CR-MOD-DECODE-001 | S1 | Linux | real | T1140, T1204 | Deobfuscate and run an encoded stage |
| CR-MOD-PERSIST-SVC-001 | S1 | Linux | real | T1543 | Startup-service (systemd) persistence (benign) |
| CR-MOD-KERBEROAST-001 | S2 | Windows | vm | T1558.003 | Kerberoasting telemetry pattern (service-ticket request on DC) |
| CR-MOD-ASREP-001 | S1 | Windows | vm | T1558.004 | AS-REP roasting enumeration pattern (preauth-disabled accounts) |
| CR-MOD-REPL-EXPOSURE-001 | S2 | Windows | vm | T1003.006 | Replication-rights exposure audit (DCSync precursor — audit only) |
| CR-MOD-NTLM-LATERAL-001 | S2 | Windows | vm | T1550.002 | NTLM remote-logon lateral pattern (seeded lab credential) |
| CR-MOD-INHIBIT-RECOVERY-001 | S2 | Windows | vm | T1490 | Shadow-copy / recovery-point deletion telemetry pattern |
| CR-MOD-SVCSTOP-001 | S2 | Windows | vm | T1489 | Backup/EDR service-stop telemetry pattern |
| CR-MOD-RANSOM-NOTE-001 | S2 | Windows | vm | T1486 | Ransom-note drop pattern (lab-only canary directory) |

**Shared features of every module:** ATT&CK technique mapping; a safety class
with a defined approval authority; signed/unsigned execution gating; automatic
cleanup/rollback on S1/S2; detection rules bound to the behavior (log-basis
regex over real output, plus technique-basis); and MTTD measurement when a
detection fires.

> **Honest scope note.** Windows and Active Directory modules declare an
> `adapter: vm` execution spec that runs on the Proxmox VM tier via the QEMU
> guest agent (customer-provided Windows/DC templates); when no VM tier is
> provisioned, those modules simulate automatically — nothing is faked as
> real. Docker-escape is a **posture check** that proves the boundary holds —
> it is not a real escape. The Impact module encrypts **canary files only**,
> in a lab directory, rollable via snapshot. Every module runs benign,
> telemetry-generating commands; the point of a cyber range is the detection
> training on the resulting telemetry, not weaponized intrusion.

---

## 2. Scenarios to be included and their descriptions

A **scenario** curates signed modules into a story with objectives, timed
injects, difficulty, duration, and (for guided labs) a lesson + quiz. **10 ship
today:**

| Scenario | Mode | Difficulty | Duration | Description |
|---|---|---|---|---|
| **Reconnaissance and discovery** (CR-RECON-001) | Solo | Introductory | 30–45 min | First lab — run two discovery techniques (T1595, T1018) and learn to spot them in telemetry. |
| **Phish to foothold** (CR-PHISH-001) | Red-Blue | Intermediate | 60–90 min | Trace a phishing intrusion from lure to code execution; blue validates the user report and contains the endpoint. |
| **Identity compromise** (CR-IDENT-001) | Red-Blue | Intermediate | 90 min | Investigate seeded password reuse and remote logons; revoke sessions and reset identities (T1078). |
| **Linux server intrusion** (CR-LINUX-001) | Red-Blue | Intermediate | 60–90 min | A full Linux kill chain that runs for real — recon → execution → cron persistence → discovery; blue reconstructs it from host logs. |
| **Privilege escalation and evasion** (CR-PRIVESC-001) | Red-Blue | Intermediate | 60–90 min | Red runs SUID/sudo enumeration then log tampering; blue catches both (T1548, T1070). |
| **Insider collection** (CR-INSIDER-001) | Solo | Intermediate | 60–90 min | Distinguish legitimate access from abnormal synthetic-data collection and exfiltration (T1005/T1560/T1041). |
| **Ransomware precursor** (CR-RANSOM-001) | Red-Blue | Advanced | 90–120 min | Detect discovery → staging → safe canary encryption and contain *before* impact (T1486). |
| **Web app intrusion** (CR-WEBAPP-001) | Red-Blue | Advanced | 120 min | Exploit a vulnerable Linux web app (T1190) and trace the app-spawned process tree to data access. |
| **Docker compromise** (CR-DOCKER-001) | Red-Blue | Advanced | 90–120 min | Real container behaviors — enumeration, exposed secret, abnormal runtime, safe host-boundary test; detections fire on live telemetry with measured MTTD. |
| **Purple detection sprint** (CR-PURPLE-001) | Purple | Advanced | 120–240 min | Replay Windows/Linux/Docker behaviors; tune rules and measure coverage improvement baseline → replay (never win/lose). |
| **Active Directory attack path** (CR-ADATTACK-001) | Red-Blue | Advanced | 120–180 min | A realistic AD kill chain — account discovery, AS-REP enumeration, service-ticket requests, NTLM lateral logons, and a replication-rights exposure audit. Blue detects each stage on the DC and endpoint; executes real on the VM tier, simulates off it. |
| **Ransomware kill chain (flagship)** (CR-RANSOM-FLAG-001) | Red-Blue | Advanced | 150–240 min | The complete ransomware chain — recon → persistence → discovery → collection → **inhibit-recovery** → **service-stop** → canary-impact → ransom-note drop. The **containment window** for blue is inhibit-recovery and service-stop; both fire minutes before the encryption burst. Scoped to a lab canary directory. |

Customers extend this set without engineering: author new scenarios from a short
YAML/JSON config (`scripts/build_scenarios.py`) or in-product
(`POST /api/scenarios`). Authoring validates that **every referenced module
exists and is signed** — so a customer can only compose content a reviewer
already trusted.

---

## 3. Latest attack vectors across the world covered

The catalog maps to **31 ATT&CK techniques across 13 of the 14 Enterprise
tactics** (only Resource Development is unmapped). Coverage reflects the TTPs
that dominate current real-world incident reporting, including a full
Active-Directory attack path (Kerberoasting, AS-REP roasting, DCSync-rights
exposure, pass-the-hash) and the full ransomware kill chain through the
containment window (inhibit-recovery, service-stop) to canary-impact:

| Tactic | Techniques covered | Current-threat relevance |
|---|---|---|
| Reconnaissance | T1595, T1018 | Pre-intrusion scanning |
| Initial Access | T1566 (phishing), T1190 (public-facing app), T1078 (valid accounts) | The three most common breach entry points today |
| Execution | T1059, T1204, T1610 | Script interpreters; container exec |
| Persistence | T1053, T1543, T1078 | Scheduled tasks/cron, systemd services |
| Privilege Escalation | T1548, T1611 | SUID/sudo abuse; **container escape** |
| Defense Evasion | T1070, T1140, T1078 | Log tampering; encoded-payload deobfuscation |
| Credential Access | T1003 (+ T1003.006 DCSync-exposure), T1552, T1558.003 (Kerberoasting), T1558.004 (AS-REP) | Credential dumping; cloud-native secret exposure; **the full Kerberos abuse chain** |
| Discovery | T1018, T1087, T1613 | AD enumeration; **container & resource discovery** |
| Lateral Movement | T1021, T1550.002 (NTLM pass-the-hash) | Remote services; **NTLM lateral movement** |
| Collection | T1005, T1560 | Data staging + archiving |
| Command & Control | T1071, T1105 | Beaconing; ingress tool transfer |
| Exfiltration | T1041 | Exfil over C2 channel |
| Impact | T1486, T1489 (service stop), T1490 (inhibit recovery) | **Full ransomware chain** including the containment window stages |

**Modern/high-signal vectors explicitly represented:** phishing-to-execution,
web-app exploitation (T1190), identity/credential-reuse abuse (T1078),
**full container attack surface** (discovery, exposed secrets, runtime abuse,
host-boundary escape — T1613/T1552/T1610/T1611), encoded-payload staging
(T1140), and the **ransomware precursor chain** culminating in a safe canary
T1486 impact event.

---

## 4. Complete training flow

```
 Instructor/Admin                Red                 Blue                System
 ───────────────                 ───                 ────                ──────
 1. Select scenario ─────────────────────────────────────────────▶ Validate (signed modules)
 2. Launch range ───────────────────────────────────────────────▶ Provision + seed lab assets
                                                                     (REQUESTED→…→READY)
 3.                            Execute modules ──────────────────▶ Run (real) / declare (sim)
                                in ATT&CK order                      telemetry → sensors
 4.                                               Investigate ◀──── Fog-of-war log view
                                                  (redacted)         (answer-keys stripped)
 5.                                               Detect + respond ─▶ Detection engine scores
                                                                     rules, records MTTD
 6. Inject events (user report, escalation, decoy) at timed marks ─▶ Timeline
 7. Complete ───────────────────────────────────────────────────▶ EVIDENCE_LOCKED
 8. Scored report (5 dimensions, explainable) ◀──────────────────── Scoring + audit ledger
 9. Purple review / debrief ◀───────────────────────────────────── Coverage delta
```

**Step by step:**
1. **Scenario selection** — instructor picks from the catalog (or a custom one).
2. **Range launch** — platform provisions disposable targets and seeds them;
   lifecycle runs REQUESTED → PREFLIGHT → PROVISIONING → SEEDING → READY.
3. **Red execution** — red runs signed modules in kill-chain order; real tiers
   execute on lab assets, simulated tiers declare telemetry.
4. **Blue investigation under fog of war** — blue's log view is redacted at the
   query layer (answer-key telemetry stripped, attacker source relabeled to the
   victim host), so blue works from evidence, not the answer sheet.
5. **Detection & response** — Sigma-style rules evaluate real output; MTTD and
   MTTR are recorded.
6. **Injects** — timed events (synthetic user reports, escalations, decoys)
   drive realism and communication.
7. **Completion & evidence lock** — range moves to EVIDENCE_LOCKED; nothing can
   be altered after.
8. **Scored, explainable report** — five weighted dimensions (below); every
   score cites its evidence, and overrides are audited.
9. **Debrief / purple review** — coverage-improvement delta and timeline review.

**Scoring dimensions:** Red execution 25%, Detection 25%, Investigation 20%,
Response 20%, Collaboration 10% — each with defined metrics (objective
completion, MTTD, scope accuracy, MTTR/containment, handoffs).

---

## 5. Types of training

- **Red-Blue (adversarial):** live red vs. blue on one range under fog of war —
  the core format (6 of 10 scenarios).
- **Solo (self-paced):** one learner plays both sides; ideal for onboarding and
  introductory labs (recon, insider).
- **Purple (collaborative):** red and blue work together to replay behaviors and
  **tune detection**, scored on coverage improvement (baseline → replay), never
  win/lose.
- **Guided lessons:** every scenario ships an overview, key concepts,
  step-by-step instructions, observe-this cues, and a **quiz** — usable as
  instructor-led or fully self-serve courseware.
- **By difficulty:** Introductory → Intermediate → Advanced, so a program can
  build a curriculum from a 30-minute first lab to a 4-hour purple sprint.

**Roles supported (RBAC, server-enforced):** admin, instructor, red, blue,
purple, solo, security_leader — 7 roles, each with distinct permissions.

---

## 6. Technical specifications

| Area | Specification |
|---|---|
| **Control plane** | Python 3.10+ standard library only (no framework); stdlib HTTP server |
| **Data store** | SQLite (single-node) or PostgreSQL/Supabase (multi-user) |
| **Frontend** | Static HTML/CSS/JS — no build step, no Node toolchain |
| **Execution model** | Pluggable `RangeProvisioner` seam: ContainerProvisioner (Docker) today, ProxmoxProvisioner (VM tier) in progress |
| **Real vs. simulated** | Modules with an `execution` spec run on live targets when Docker/VM is available; otherwise declared telemetry |
| **Detection engine** | Sigma-style rules; log-basis (regex over real output) + technique-basis; records MTTD |
| **Fog of war** | Query-layer redaction of blue's log view (answer-key kinds stripped, source relabeled) |
| **Scoring** | 5 weighted, explainable dimensions; every override written to an audit ledger |
| **Safety model** | S0/S1/S2/PROHIBITED classes; `signed` flag is the hard execution gate; S2 gated to admin/instructor; PROHIBITED never executable |
| **RBAC** | 7 roles; permissions enforced server-side (`AuthorizationError` → HTTP 403); audit read gated behind `admin:audit` |
| **Content extensibility** | Config-driven + in-product scenario authoring; Atomic Red Team / CALDERA importer (imports land **unsigned**, pending review) |
| **Catalog scale** | Verified to load 1,000+ modules in ~13 ms (staged catalog, lru-cached) |

**Detection sensor stack (reference build):** Windows — Wazuh + Sysmon +
PowerShell/Defender logs; Linux — Wazuh + auditd/journald (optional osquery);
Docker host — Wazuh Docker listener + daemon/container logs; container runtime —
Falco; network — Suricata (+ Zeek where resources permit); unified
evidence/timeline API fed by all sensors.

**Lifecycle states (12):** REQUESTED, PREFLIGHT, PROVISIONING, SEEDING, READY,
RUNNING, PAUSED, COMPLETING, EVIDENCE_LOCKED, ARCHIVED, DESTROYED, QUARANTINED.

---

## 7. Deployment models

| Model | Description |
|---|---|
| **Local / developer** | Single host, SQLite, simulated tier — authoring, demos, evaluation. No Docker required. |
| **Docker-enabled single node** | Adds real execution for Linux + container (Docker) modules on one machine. |
| **Managed cloud (Railway/Supabase)** | Hosted control plane + PostgreSQL for distributed teams. |
| **Customer-hosted (on-prem/private cloud)** | Air-gapped-friendly; customer owns all data and lab assets. |
| **VM tier (Proxmox)** | Adds real Windows/AD/multi-VM topologies via the ProxmoxProvisioner; documented running Proxmox on GCP nested virtualization (Windows/AD execution is in progress). |

**Reference capacity profiles:**
- *Developer-demo* — 1 host, 64–128 GB RAM, 16–32 cores, 2–4 TB NVMe; 1–3
  concurrent ranges.
- *Team appliance* — 2–4 hypervisor nodes, 256–512 GB/node, 10/25 GbE; 5–20
  concurrent ranges.
- *Enterprise cluster* — HA control plane, elastic hypervisor pools, shared
  image/evidence storage; 20+ concurrent ranges.

---

## 8. License requirements

**CyberRange platform:** no third-party runtime license is needed for the
control plane — it is Python standard library only, with SQLite built in.

| Component | License / requirement |
|---|---|
| Control plane (Python stdlib, SQLite) | None beyond the platform license |
| PostgreSQL / Supabase (multi-user) | PostgreSQL License (open source); Supabase per its own terms if hosted |
| PyYAML (only for YAML scenario configs) | BSD — optional; JSON configs need nothing |
| Detection stack — Wazuh, Sysmon, Falco, Suricata, Zeek, osquery | Open source (Sysmon is a free Microsoft Sysinternals tool) |
| Atomic Red Team content (importer) | MIT |
| MITRE CALDERA content (importer) | Apache-2.0 |
| **Windows / Active Directory lab VMs (VM tier)** | **Customer-provided Microsoft licensing** — evaluation ISOs or the customer's volume/MSDN licenses. CyberRange ships no Windows media. |
| Proxmox VE | Open source (optional paid enterprise repo/support subscription) |

> The only paid licensing a customer must supply is **Microsoft Windows/AD** for
> the VM tier. Everything in the shipping Linux/Docker path is open source or
> stdlib.

---

## 9. Hardware requirements

| Tier | Minimum | Notes |
|---|---|---|
| **Evaluation (simulated only)** | 2 cores, 4 GB RAM, ~2 GB disk, Python 3.10+ | Runs the full control plane, catalog, scoring, and simulated scenarios. No Docker. |
| **Real Linux + Docker execution** | 4 cores, 8–16 GB RAM, Docker Engine | Executes the 16 real-tier modules and all Docker scenarios. ~4 GB extra if running a Wazuh indexer/sensor locally. |
| **Full detection stack** | +4 GB RAM for Wazuh indexer/manager | Add per-sensor overhead (Suricata/Zeek) by network volume. |
| **VM tier (Proxmox-on-GCP, documented)** | `n2-standard-8` (8 vCPU, 32 GB RAM), ~150 GB SSD, Intel Haswell+ with **nested virtualization enabled** | Hosts Proxmox + Windows/AD lab VMs. N1/N2/C2/C3/M-series all support nesting. |
| **Team / enterprise** | See §7 capacity profiles | 2–4+ hypervisor nodes, 256 GB+/node, 10/25 GbE. |

**Baseline across all tiers:** Python 3.10+; a modern browser for the UI; Docker
Engine only if you want real (non-simulated) execution.

---

### One-line summary for the customer

> CyberRange is an **emulation-class** range: 36 ATT&CK-mapped modules (16 real
> on Docker; 16 real on the Proxmox VM tier; 4 simulated) and 12 scenarios —
> including a full **Active Directory attack path** (Kerberoasting, AS-REP,
> NTLM lateral, DCSync-exposure audit) and a **flagship ransomware kill
> chain** (recon → persistence → discovery → collection → inhibit-recovery →
> service-stop → canary-impact → ransom-note), spanning 13 of 14 Enterprise
> tactics. Delivered through red-blue, solo, purple, and guided-lesson
> formats, with a signed-content safety model, fog-of-war investigation, and
> explainable five-dimension scoring. It runs from a 4 GB laptop (simulated)
> up to an enterprise hypervisor cluster, needs no paid license except
> customer-supplied Windows media for the VM tier, and lets customers author
> their own trusted content without engineering.
