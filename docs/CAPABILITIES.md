# CyberRange - Technical Capabilities

**Product:** CyberRange, a Red / Blue / Purple team training and control-validation platform
**Document version:** 1.0
**Status of contents:** describes the shipping product as built in this repository. Items on the delivery roadmap are marked **[Roadmap]** and are not claimed as shipping capability.

---

## 1. Executive summary

CyberRange gives security teams and academic programs a safe, repeatable environment in which
adversary behavior is actually executed, telemetry is actually produced, detections actually
fire, and readiness is measured with an explainable score. It is not a slide-deck simulator and
not a video course: a red operator launches a technique, that technique runs a real command
inside an isolated target, the output becomes real log lines, and a defender hunts those log
lines in a SOC-style search console without being told what was run.

The platform covers the full exercise loop in one product:

| Stage | What the platform does |
|---|---|
| Plan | Scenario and TTP catalog mapped to MITRE ATT&CK, with topology templates |
| Provision | Lifecycle state machine stands up an isolated, egress-denied range |
| Execute | Signed behavior modules run for real (container-backed) or degrade to simulation |
| Observe | Synchronized UTC evidence timeline, hash-stamped, plus SOC log search |
| Detect | Versioned Sigma-style rules fire automatically and record MTTD |
| Measure | Weighted, explainable, override-audited scoring across five dimensions |
| Improve | Purple baseline-to-replay coverage delta, never win/lose |
| Report | After-action report exportable as JSON, CSV, HTML, and DOCX |
| Govern | Role-based access control, safety classes, append-only audit ledger |

The whole control plane runs on the Python standard library with SQLite by default. There is no
build step and no mandatory external dependency, which means an evaluation deployment is
minutes of work rather than a project.

---

## 2. Architecture

```
┌──────────────────┐    REST / JSON      ┌───────────────────────────────────────────┐
│  Operator web    │ ──────────────────► │  Control plane (stdlib HTTP server)        │
│  dashboard       │                     │  catalog · lifecycle · RBAC · scoring ·    │
│  (no build step) │ ◄────────────────── │  detection engine · reporting · audit      │
└──────────────────┘                     └───────────────┬───────────────────────────┘
                                                         │
                            ┌────────────────────────────┼────────────────────────────┐
                            ▼                            ▼                            ▼
                   Persistence layer            Execution adapter              Telemetry sinks
                   SQLite (default)             DockerAdapter (real)           Internal timeline
                   PostgreSQL / Supabase        SimulatedAdapter (fallback)    Wazuh SIEM (optional)
                                                VM/hypervisor **[Roadmap]**
```

Three deliberate seams make the platform portable into a customer environment:

1. **Persistence** is behind one interface, so SQLite (evaluation) and PostgreSQL/Supabase
   (production) are interchangeable with an environment variable and no code change.
2. **Execution** is behind an adapter interface. Container-backed execution ships today; the
   same interface is what hypervisor-backed VM targets plug into.
3. **Identity** is behind the RBAC layer. Local login ships today; swapping in SSO/OIDC does not
   change a single role or permission rule.

---

## 3. Content library (shipping today)

| Asset | Count | Detail |
|---|---|---|
| Launch scenarios | **10** | 1 introductory, 5 intermediate, 4 advanced |
| Exercise modes | 3 | red-blue (7 scenarios), solo (2), purple (1) |
| Behavior modules | **25** | all cryptographically signed; unsigned modules are refused at execution |
| Modules with real execution | **12** | run a genuine command inside an isolated container |
| ATT&CK techniques covered | **22** | T1003, T1005, T1018, T1021, T1041, T1053, T1059, T1070, T1071, T1078, T1087, T1190, T1204, T1486, T1548, T1552, T1560, T1566, T1595, T1610, T1611, T1613 |
| Detection rules | **15** | 12 log-basis (regex over real output), 3 technique-basis; 8 high / 5 medium / 2 low severity |
| Topology templates | 2 | five-VM enterprise range, container range |
| Guided lessons | **10 of 10 scenarios** | briefing, concepts, hands-on steps, auto-graded quiz |

### Module coverage by platform and safety class

| | Windows | Linux | Docker | Total |
|---|---|---|---|---|
| **S0** simulation | 2 | 3 | 0 | 5 |
| **S1** atomic emulation | 7 | 5 | 4 | 16 |
| **S2** high-impact lab action | 2 | 1 | 1 | 4 |
| **Total** | **11** | **10** | **4** | **25** |

Tactic coverage spans the full chain: Reconnaissance, Initial Access, Execution, Persistence,
Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement,
Collection, Command & Control, Exfiltration, Impact, plus container-specific Container
Discovery and Escape-to-Host.

### Scenarios

| ID | Scenario | Mode | Difficulty |
|---|---|---|---|
| CR-RECON-001 | Reconnaissance and discovery | solo | introductory |
| CR-PHISH-001 | Phish to foothold | red-blue | intermediate |
| CR-IDENT-001 | Identity compromise | red-blue | intermediate |
| CR-LINUX-001 | Linux server intrusion | red-blue | intermediate |
| CR-PRIVESC-001 | Privilege escalation and evasion | red-blue | intermediate |
| CR-INSIDER-001 | Insider collection | solo | intermediate |
| CR-RANSOM-001 | Ransomware precursor | red-blue | advanced |
| CR-WEBAPP-001 | Web app intrusion | red-blue | advanced |
| CR-DOCKER-001 | Docker compromise | red-blue | advanced |
| CR-PURPLE-001 | Purple detection sprint | purple | advanced |

Every scenario carries versioned content, a topology binding, role-specific objectives with
point values, timed instructor injects, an expected-evidence list, and a safety class.

---

## 4. Execution model - what "real" means here

Behavior modules run through an execution adapter, and every timeline event records which mode
produced it. The dashboard tags each event **real** or **sim**, so an operator is never in doubt
about the fidelity of what they are looking at.

### 4.1 Container-backed real execution

When a Docker daemon is reachable and a module carries an execution spec, the module's benign
command runs for real inside a throwaway container that is:

- **network-isolated** (`--network none` for atomic runs),
- memory-, CPU-, and PID-capped,
- started with `--no-new-privileges`,
- given **no host mounts**,
- removed on exit (`--rm`),
- bounded by a per-module timeout (60 to 600 seconds depending on the module).

The container's actual stdout, stderr, exit code, and timing are captured as timeline events.
This is genuine telemetry from a genuine process, not a scripted transcript.

### 4.2 Live container ranges - a persistent, connected target set

With live ranges enabled, provisioning stands up a per-range internal network with **no egress**
plus persistent hosts, and modules execute *inside* the victim host rather than in a throwaway
container. Two consequences matter operationally:

- **A foothold persists across steps.** Files and processes written in one step are still there
  in the next, so an exercise is a real kill chain rather than a series of disconnected atomic
  actions.
- **Targets are reachable across the range network.** The victim can reach a web application
  target, so behaviors traverse a connected environment.

Identity scenarios additionally stand up a **real LDAP directory** seeded with synthetic domain
users, giving a genuine directory-enumeration attack surface (T1087) rather than a simulated
one. This is a Linux identity stand-in and is described as such, not as a Windows AD domain
controller.

Range operations: `reset` recycles targets to a clean state while keeping the range and its
network; `destroy` removes all containers and the network. Every artifact is labelled by range
ID, runs non-privileged, and is resource-capped.

### 4.3 Graceful degradation

Modules without an execution spec, and any deployment without a Docker daemon, fall back to the
simulated adapter, which emits the telemetry the module declares it would produce. The platform
never fails an exercise because the execution tier is unavailable; it degrades and labels the
degradation.

### 4.4 **[Roadmap]** Full VM and Windows/Active Directory targets

Real Windows endpoints and a real Active Directory domain (Kerberos, SMB, GPO) require full VMs
and a hypervisor. That tier is a documented integration seam against KVM/Proxmox/VMware and is
operator-hosted. It is on the delivery roadmap and is not part of the shipping container tier.

---

## 5. Detection, telemetry, and the SOC experience

### 5.1 Automatic detection engine

When a module runs, the detection engine evaluates versioned, Sigma-style rules against the
timeline, including the real container output, and records verdicts without human input:

- **Log-basis rules** (12 of 15) regex-match real captured log lines, for example a rule that
  fires on `uid=0(root)` or on a nested shell spawn produced by an actual container. These are
  marked `real` on the timeline.
- **Technique-basis rules** (3 of 15) provide coverage for behaviors that are simulated rather
  than executed.

Each detection records **which rule fired, which evidence line matched, the severity, and the
latency from activity to verdict (MTTD)**. Detections land on the shared timeline and feed both
detected-coverage reporting and scoring. A blue analyst can still add a manual verdict, but the
automatic baseline exists whether or not anyone touches it.

### 5.2 SOC log search with fog of war

Blue analysts work from a SIEM-style search console over the exercise log store, with free-text
matching across the log line, source, actor, and event kind, plus filters by source and kind.

Critically, the defender view is **redacted**. Blue does not see "red ran module
CR-MOD-DOCKER-RUNTIME-001 (T1610)". The platform strips technique attribution, module IDs,
executed command lines, safety class, and adapter metadata from the defender's view, and
relabels the event source from the attacker's tooling to the **affected asset**
(`host:victim`, `host:web-app`, `host:directory`). Blue sees a host emitting log lines and an
alert firing, and has to work out the rest. That is the difference between an exercise and a
demonstration.

### 5.3 Evidence timeline

All activity lands on one synchronized UTC timeline with integrity hashes, shared across roles,
covering module execution, real process output, detections, instructor injects, and analyst
evidence submissions. Evidence can be locked at exercise completion, giving an immutable record
for after-action review or accreditation.

### 5.4 Real SIEM integration (optional, shipping)

For customers who want detection to happen in a real SIEM rather than the built-in engine, the
platform ships a full Wazuh deployment (manager, indexer, dashboard). With SIEM ingest enabled,
every event is streamed as JSON to a file a Wazuh agent tails, the Wazuh manager evaluates
CyberRange detection rules and raises genuine alerts, and a forwarder posts those alerts back
onto the exercise timeline as `basis=siem` detections. The alerts are simultaneously visible in
the Wazuh dashboard.

This requires a Docker host with roughly 4 GB of RAM for the indexer. The telemetry contract is
normalized, so substituting Elastic, Sentinel, Splunk, or a customer's existing SOC stack is an
adapter exercise rather than a redesign.

---

## 6. Scoring and reporting

### 6.1 Explainable scoring

Score is a weighted sum of five dimensions, minus safety and policy penalties:

| Dimension | Weight | Measures |
|---|---|---|
| Red execution | 25% | Objective completion, evidence quality, path efficiency, operational discipline |
| Detection | 25% | Coverage, signal quality, MTTD, correct technique attribution |
| Investigation | 20% | Scope accuracy, hypothesis quality, timeline completeness, evidence handling |
| Response | 20% | MTTR, containment correctness, service impact, recovery validation |
| Collaboration | 10% | Communication, handoffs, documentation, rules-of-engagement compliance |

The scoring response returns every dimension's raw score, its weight, and its contribution,
alongside each penalty and each override. **Every input is explainable and every instructor
override is audited** with a named instructor and a written justification. The platform also
derives dimension scores directly from observed exercise activity, so a score exists before any
human judgement is applied.

### 6.2 Purple replay comparison

Purple exercises are reported as a **baseline-to-replay coverage delta per technique and in
aggregate**, never as win/lose. The question the report answers is "did the control improvement
change detection coverage for this technique", which is the only question that drives tuning.

### 6.3 After-action reporting

Reports cover technique coverage, detection gaps, evidence inventory, and recommendations, and
export in four formats:

| Format | Endpoint | Use |
|---|---|---|
| JSON | `/api/exercises/{id}/report.json` | Machine ingestion, downstream analytics |
| CSV | `/api/exercises/{id}/report.csv` | Spreadsheet analysis |
| HTML | `/api/exercises/{id}/report.html` | Share or print |
| DOCX | `/api/exercises/{id}/report.docx` | Formal deliverable for management or accreditation |

Class gradebooks export to CSV separately.

---

## 7. Roles and access control

Seven roles, each mapped to an explicit permission set enforced server-side on every API call.
The live matrix is served by the API and rendered in the product.

| Role | Permissions | Summary |
|---|---|---|
| `admin` | 20 | Full control plane: user provisioning, image management, any lifecycle step, S2 execution, score override, audit ledger, emergency pause/kill, **sole authority to release a quarantined range** |
| `instructor` | 11 | Create ranges, drive lifecycle, launch exercises, publish injects, execute S2, override scores with justification. Cannot manage users or release quarantine |
| `red` | 8 | Participate, execute S0/S1 modules (**S2 blocked**), submit evidence, read catalog and reports |
| `blue` | 8 | Participate, submit evidence, read scoring detail and reports. Cannot execute attacker modules |
| `purple` | 8 | Participate, execute modules for deterministic replay, view scoring and reports |
| `solo` | 8 | Guided single learner running both attacker and defender phases on one timeline |
| `security_leader` | 5 | Read-only oversight of catalog, ranges, exercises, scoring, and reports. Cannot change any state |

### Authentication

- Passwords stored as **PBKDF2-HMAC-SHA256 with a per-user random salt**, never in plaintext.
- Login issues an opaque random **session token with a 12-hour TTL**.
- Login failures return a generic error whether the username is unknown, the password is wrong,
  or the account is disabled, so the endpoint does not enumerate accounts.
- Disabling a user **immediately revokes all live sessions** for that user.
- Unauthenticated API calls are rejected with 401. The header-identity developer shortcut is
  **off by default**, so a public deployment is not open by accident.
- **[Roadmap]** SSO/OIDC replaces local login. The RBAC layer downstream is unchanged, so this
  is an identity swap, not a permissions redesign.

---

## 8. Learning and delivery platform

Students learn inside the product; no external LMS is required.

- **Classes and rosters.** An instructor creates a class and bulk-enrolls students from CSV
  (`username, display name, password`). Missing accounts are created as learners and generated
  passwords are returned for distribution.
- **Assignments.** Any scenario with a lesson can be assigned to a class. All 10 scenarios have
  lessons.
- **Guided lessons.** Each lesson carries a briefing, key concepts, ordered hands-on steps that
  run a real or simulated module on the learner's own auto-provisioned range with explicit
  guidance on what to watch for, and a knowledge check that is auto-graded with explanations.
  The platform runs curated S2 steps on the learner's behalf, so students get the full
  experience without holding S2 authority themselves.
- **Progress and gradebook.** Per-student status and score are tracked; instructors see class
  completion and average score, exportable as CSV for accreditation evidence.

### Framework crosswalks

Techniques used in the platform are crosswalked to **NIST CSF 2.0**, the **NICE Workforce
Framework (NIST SP 800-181r1)**, **CIS Critical Security Controls v8**, and **NSA/DHS CAE-CD
Knowledge Units**, and served through the API for curriculum mapping and accreditation
evidence. This is a curated, indicative alignment for curriculum purposes, not an official
MITRE mapping dataset, and is presented that way in the product.

---

## 9. Safety and governance

The platform emulates **observable adversary behavior inside owned lab assets**. The catalog
deliberately favors atomic, deterministic emulation and benign stand-ins over live malware.

| Class | Meaning | Approval required |
|---|---|---|
| **S0** Simulation | Synthetic telemetry or a benign endpoint call | Scenario author |
| **S1** Atomic emulation | Bounded behavior on disposable assets, auto-cleanup | Security content reviewer |
| **S2** High-impact lab action | May disrupt a lab VM or change identity state | Admin plus explicit scenario policy |
| **Prohibited** | Self-propagation, external targeting, real credential theft, live malware | **Never permitted, not executable** |

Enforcement is in the service layer, not in documentation:

- Unsigned modules are **refused at execution**. All 25 shipping modules are signed.
- The prohibited class **cannot be executed** by any role, including admin.
- S2 execution is gated to instructor and admin, except for curated S2 steps the platform runs
  on a learner's behalf inside a guided lesson.
- Ranges default to **egress-deny**; the reference topology places the control plane on a
  network that is never reachable from tenant workloads.
- Any anomalous workload transitions to **QUARANTINED**, and only an administrator can release
  or destroy it.
- Every state change is written to an **append-only audit ledger**, readable by admins.

### Range lifecycle

```
REQUESTED → PREFLIGHT → PROVISIONING → SEEDING → READY → RUNNING ⇄ PAUSED
          → COMPLETING → EVIDENCE_LOCKED → ARCHIVED → DESTROYED
                                  ↘ QUARANTINED (admin-only release)
```

Illegal transitions are rejected with a 409 rather than silently tolerated, so the lifecycle is
a real state machine and not a status label.

---

## 10. Deployment

### Options

| Option | Command / method | Notes |
|---|---|---|
| Local | `make serve` | Python 3.10+, no pip install, no build step |
| Docker | `docker compose up` | Single service on port 8080 |
| Railway | Dockerfile + `railway.json` | Public HTTPS URL, managed TLS |
| Customer-hosted | Any Docker host | Recommended when real container execution is required |

### Requirements

- **Control plane:** Python 3.10 or later. Standard library only; no mandatory dependencies.
- **Real container execution:** a reachable Docker daemon, local or remote.
- **PostgreSQL backend:** the `psycopg` driver, already present in the Docker image.
- **Bundled Wazuh SIEM:** a Docker host with approximately 4 GB RAM.

### Data persistence

SQLite by default with zero configuration. Setting a PostgreSQL connection string switches the
backend automatically, with Supabase supported directly. Tables are created on boot; a
standalone schema file is provided for customers who prefer to provision the schema and add
row-level security ahead of time. The same code is verified against real PostgreSQL in test.

### Configuration

| Variable | Purpose |
|---|---|
| `CR_ADMIN_PASSWORD` | Seeded administrator password. **Set this on any deployment reachable by others.** |
| `DATABASE_URL` / `SUPABASE_DB_URL` | PostgreSQL DSN; unset means SQLite |
| `DOCKER_HOST` | Remote Docker daemon for real execution |
| `CR_LIVE_RANGES` | Enable persistent, connected live container ranges |
| `WAZUH_INGEST_ENABLED` | Stream events to the Wazuh SIEM |
| `CR_DEV_AUTH` | Developer header identity. **Leave unset in production** |

### Hosted-platform caveat, stated plainly

A hosted platform that provides no Docker daemon inside the application container cannot run
real container execution. In that configuration, modules fall back to simulation and detection
uses technique-basis rules. Everything else, including the full lifecycle, scoring, reporting,
learning platform, and audit, works normally. Real execution requires a Docker host; the common
pattern is the lightweight control plane on a hosted platform with an execution host alongside
it.

---

## 11. API surface

A complete REST/JSON API sits under `/api`, with bearer-token authentication. Everything the
dashboard does is available programmatically, which means the platform integrates with existing
LMS, ticketing, and reporting pipelines rather than requiring operators to live in its UI.

| Area | Representative endpoints |
|---|---|
| Auth and users | `POST /api/login`, `GET /api/me`, `GET /api/roles`, `POST /api/users`, `POST /api/users/{u}/active` |
| Catalog | `GET /api/scenarios`, `/api/modules`, `/api/tactics`, `/api/detection-rules`, `/api/topologies`, `/api/frameworks` |
| Ranges | `GET|POST /api/ranges`, `POST /api/ranges/{id}/actions` |
| Exercises | `POST /api/exercises`, `GET /api/exercises/{id}/timeline`, `POST /api/exercises/{id}/modules`, `POST /api/exercises/{id}/injects` |
| SOC / blue | `GET /api/exercises/{id}/logs`, `GET /api/exercises/{id}/log-sources` |
| Evidence and detection | `GET|POST /api/exercises/{id}/evidence`, `GET|POST /api/exercises/{id}/detections` |
| Scoring | `POST /api/exercises/{id}/score`, `GET /api/exercises/{id}/derived-scores` |
| Reporting | `GET /api/exercises/{id}/report[.json|.csv|.html|.docx]` |
| Purple | `POST /api/purple/compare` |
| Learning | `GET|POST /api/cohorts`, `/api/cohorts/{id}/roster`, `/api/cohorts/{id}/assignments`, `/api/cohorts/{id}/gradebook[.csv]`, `/api/learn/lesson/{id}`, `/api/learn/start`, `/api/learn/step`, `/api/learn/quiz` |
| SIEM and admin | `POST /api/siem/alert`, `GET /api/audit` |

Errors are structured with meaningful status codes: 400 bad request, 401 unauthenticated,
403 forbidden, 404 not found, 409 illegal lifecycle transition, 500 internal.

Scenario and module catalog queries support filtering by role, tactic, difficulty, technique,
platform, safety class, and free text.

---

## 12. Quality assurance

The platform ships with an automated test suite of **132 tests** covering the API surface,
catalog, database layer including PostgreSQL migration, detection engine, execution adapters,
framework crosswalks, learning platform, lifecycle state machine, log search and redaction,
provisioning, reporting formats, scoring, service orchestration, SIEM integration, and user
management. The suite runs against the standard library with no external services required;
tests that need Docker or PostgreSQL skip cleanly when those are unavailable.

---

## 13. Roadmap

The following are documented integration seams, not shipping capability. They are listed so
that scope is unambiguous.

| Item | Status |
|---|---|
| Hypervisor provisioning (KVM / Proxmox / VMware) | Seam defined via topology templates; adapter to be built |
| Real Windows endpoints and Active Directory domain | Requires the VM tier above |
| Kernel-level runtime sensing (Falco), network IDS (Suricata) | Telemetry contract defined; sensors to be integrated |
| SSO / OIDC identity | RBAC layer already isolated from the identity layer |
| Kubernetes-managed hypervisor pools, cloud-hosted ranges | Control plane designed to scale to this |

---

## 14. Why this architecture matters commercially

1. **Evidence, not assertion.** Detections carry the rule that fired, the matched line, the
   severity, and the measured latency. Reports are built from a hash-stamped timeline. This is
   the material an auditor, an accreditation body, or a board asks for.
2. **Honest fidelity labelling.** Every event says whether it is real or simulated. Customers
   are never in a position to discover after purchase that "execution" meant a canned script.
3. **Fog of war by construction.** The defender view is redacted at the query layer, not by
   asking participants not to look. That is what makes measured detection performance mean
   something.
4. **Degrades instead of failing.** No Docker, no problem: the exercise still runs, still
   scores, still reports, and says so.
5. **Portable by design.** SQLite to PostgreSQL, built-in detection to a real SIEM, local login
   to SSO, containers to VMs. Each is an adapter swap behind an interface that already exists.

---

*Prepared for customer technical evaluation. Counts and capabilities in this document reflect
the current shipping build and were verified against the platform's content catalog and test
suite at the time of writing.*
