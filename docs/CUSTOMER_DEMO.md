# End-to-end test cases for a customer demonstration

Numbered cases you can run in front of a customer, or hand over as acceptance
criteria for them to run themselves. Each one states what to do, what should
happen, and **what it proves** — because in a demo the second question is
always "how do I know that was real?"

Allow about 45 minutes for the full set, or 15 for the short path
(TC-R-01 → TC-R-03 → TC-B-01 → TC-B-03 → TC-G-01).

---

## Setup

```bash
make serve     # terminal 1
make seed      # terminal 2 — creates the accounts and a running exercise
```

`make seed` prints the credentials and the execution mode.

| Account | Password | Role |
|---|---|---|
| `admin` | `admin` | admin |
| `prof` | `profpass` | instructor |
| `red1` | `redpass` | red |
| `blue1` | `bluepass` | blue |

Sign red and blue in from **two different browsers** (or one normal and one
private window) so both sides are live side by side. That contrast is most of
the demo.

### Pre-flight — do this before the customer is watching

```bash
curl -s localhost:8080/api/health | python3 -m json.tool
```

**`"mode": "docker"` is required.** If it says `simulated`, Docker is not
running, and the blue-team cases will not work: simulated runs emit only the
event kinds the defender view redacts, so blue will have alerts but nothing
underneath them to investigate. Start Docker Desktop and restart the server.

---

## Red team

### TC-R-01 — Red launches a technique and it executes for real
**As** `red1`

1. The **Exercise** view opens by default — red lands on its work, not a menu.
2. In **Attack console**, select *Abnormal container runtime activity*.
3. Press **Launch attack**.

**Expected:** the result box reports **Real** (not Simulated), names the image
`alpine:3.19`, an exit code, the event count generated and the detections
fired.

**Proves:** adversary behaviour is executed, not replayed. The customer is
watching a container start, run, and exit.

---

### TC-R-02 — The telemetry is genuine process output
**As** `red1`, immediately after TC-R-01

1. Read the **Live timeline** on the right.

**Expected:** a `ttp-exec` event carrying image, exit code and duration, then
`process-output` events tagged **real**, containing lines like:

```
--- writing binary to /tmp ---
-rwxr-xr-x 1 root root 23 /tmp/payload.sh
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon)...
```

**Proves:** those strings came from a process, not from a script in the
product. Invite the customer to pick any line and ask where it came from.

---

### TC-R-03 — A foothold persists across steps
**Requires** `CR_LIVE_RANGES=1`
**As** `red1`

1. Run *Abnormal container runtime activity* (writes `/tmp/payload.sh`).
2. Run a second technique that lists `/tmp`.

**Expected:** the file written by the first technique is present in the second
technique's output.

**Proves:** this is a kill chain, not a series of disconnected one-shot
actions. State carries, as it would on a real compromised host.

---

### TC-R-04 — Red cannot run high-impact actions
**As** `red1`

1. Select a module marked **S2** (e.g. *Container-to-host boundary test*).
2. Press **Launch attack**.

**Expected:** refused with
`S2 modules require administrator or instructor approval`.

3. Sign in as `prof` and run the same module. It executes.

**Proves:** the safety class is enforced in the service layer, per role — not
a label in documentation. Worth doing in front of any security buyer.

---

### TC-R-05 — Red declares its attack path
**As** `red1`

1. In **Log your attack path**, enter what was done, e.g.
   `Wrote /tmp/payload.sh and executed it as root on victim`.
2. Press **Submit**.

**Expected:** recorded with an integrity hash.

**Proves:** the report can compare what red *did* against what blue *caught*.
That gap is the coverage finding — the output the exercise exists to produce.

---

## Blue team

### TC-B-01 — Blue starts from alerts, not from raw logs
**As** `blue1`

1. The **Exercise** view opens on the **SOC console**.

**Expected:** the **Alerts** chip shows a count. Each alert carries the rule
that fired, a severity, and **MTTD** — the measured time from activity to
detection.

**Proves:** detection is automatic and measured. Nobody marked these by hand.

---

### TC-B-02 — Blue cannot see what red did
**As** `blue1`, with `prof` open alongside

1. As blue, switch to **All activity** and read the event sources.
2. As `prof`, open the same exercise timeline.

**Expected:** blue's rows are attributed to **`host:victim`** and carry no
technique ID and no module name. The instructor's timeline shows the same
activity as `module:CR-MOD-DOCKER-RUNTIME-001` with `T1610` attached.

Prove it at the API if the customer wants it airtight:

```bash
# as instructor
curl -s -H "Authorization: Bearer $PROF_TOKEN" \
  "localhost:8080/api/exercises/$EX/logs" | python3 -m json.tool | head -20
# as blue
curl -s -H "Authorization: Bearer $BLUE_TOKEN" \
  "localhost:8080/api/exercises/$EX/logs" | python3 -m json.tool | head -20
```

Blue's response reports `"redacted": true` and is missing the `ttp-exec`,
`ttp-emulation` and `expected-telemetry` events entirely.

**Proves:** the fog of war is enforced **server-side at the query layer**, not
hidden in the interface. This is the case that separates an exercise from a
demonstration — and the one to run if the customer is evaluating competitors.

---

### TC-B-03 — Blue hunts the raw logs
**As** `blue1`

1. Switch to **All activity**.
2. Press the **`/tmp`** hunt button, then **`root`**.

**Expected:** matching log lines, with the search term highlighted. The field
summary shows which sources and event types are present, with counts, and
clicking one filters to it. The histogram shows when activity clustered.

**Proves:** this is an investigation surface, not a log dump. Pivot on a field
in front of the customer.

---

### TC-B-04 — Blue raises a finding from evidence
**As** `blue1`

1. Hover a damning log line and press **Use as evidence**.
2. The text drops into the finding box. Add wording and **Submit**.

**Expected:** recorded with an integrity hash, visible on the shared timeline.

**Proves:** evidence is captured from the actual record, with a chain of
custody — the material an auditor asks for.

---

### TC-B-05 — Blue attributes the technique
**As** `blue1`

1. In **Attribute the technique**, enter the ATT&CK ID blue believes it saw
   (writing and executing a binary inside a container is `T1610`).
2. Set the verdict to `detected` and press **Record**.

**Expected:** the detection is recorded against the exercise.

**Proves:** blue reached the technique **from the evidence**, never having been
told it. Red ran `T1610`; blue had to work it out.

---

## Governance and reporting

### TC-G-01 — The after-action report
**As** `prof`

1. Press **End exercise**, then **Report**.

**Expected:** ATT&CK coverage as expected vs observed vs detected with the gaps
named, the framework crosswalk (NIST CSF, NICE, CIS, CAE), the evidence
inventory, and the score with every dimension's weight and contribution shown.
Export as **DOCX**, **HTML**, **CSV** and **JSON** — all four should download.

**Proves:** the exercise produces accreditation-grade evidence, not a number.

---

### TC-G-02 — Scoring is explainable and overrides are audited
**As** `prof`

1. Open the score panel. Note `red_execution` and `detection` are marked
   **auto** — derived from the timeline.
2. Override a dimension with a justification.

**Expected:** the response shows each dimension's raw score, weight and
contribution; the override is recorded with the instructor's name and reason.

**Proves:** no unexplainable numbers. Every input can be traced.

---

### TC-G-03 — Role boundaries hold
Try each of these and expect a refusal:

| As | Action | Expected |
|---|---|---|
| `blue1` | Execute any module | `Role 'blue' is not permitted to perform 'module:execute'` |
| `blue1` | Create a range | `Role 'blue' is not permitted to perform 'range:create'` |
| `red1` | Run an S2 module | `S2 modules require administrator or instructor approval` |
| `blue1` | Override a score | `Role 'blue' is not permitted to perform 'exercise:score_override'` |

**Proves:** RBAC is enforced on every API call, not just hidden in the UI.

---

### TC-G-04 — The audit ledger
**As** `admin`

1. Open the **Audit** tab.

**Expected:** an append-only record of every action with actor, role, target
and timestamp — including the module executions and any score override from
TC-G-02.

> **Known issue, disclose it rather than be caught by it.** `GET /api/audit`
> does not currently enforce the `admin:audit` permission, so any authenticated
> role can read the ledger over the API. The tab is hidden from non-admins, but
> the endpoint is open. If the customer's evaluator tests it, they will find
> it. See [TESTING.md](TESTING.md).

---

## What not to claim

Keep the demo honest; a buyer who catches an overstatement discounts
everything else.

- **Windows and Active Directory are simulated.** Every Windows module emits
  declared telemetry rather than executing. Real Windows/AD needs the VM tier
  ([deploy/vm](../deploy/vm/PROXMOX_SETUP.md)), which is written but unverified
  against hardware until the conformance script passes on a host.
- **Container escape is probed, not performed.** `CR-MOD-DOCKER-ESCAPE-001`
  tests for the condition inside an isolated container; it does not cross the
  boundary.
- **These are containers, not VMs.** Real Linux processes sharing the host
  kernel — genuine emulation for the Linux and container surface, not isolated
  guests.
- **Without Docker, there is no blue exercise.** Say so rather than
  demonstrating a thin version of it.
