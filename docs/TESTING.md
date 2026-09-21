# Testing CyberRange — tester's guide

How to verify the platform, from a thirty-second smoke test to a full
red-versus-blue exercise. Every command and expected result in this document was
run against the current build.

Testing happens in four layers. Work down them in order; each one assumes the
one above it passed.

| Layer | What it proves | Time |
|---|---|---|
| 1. Automated suite | The logic is correct | ~5 s |
| 2. Smoke tests | The build runs and the content loaded | ~10 s |
| 3. API tests | The contract holds, including refusals | ~1 min |
| 4. Manual exercise | The product works for real users | ~20 min |

---

## What you need

| Requirement | For | Without it |
|---|---|---|
| Python 3.10+ | Everything | Nothing runs |
| Docker | Real container execution, live ranges | 11 tests skip; modules simulate |
| PostgreSQL | Postgres backend testing | SQLite is used instead |
| ~4 GB RAM Docker host | Wazuh SIEM path | SIEM tests are not exercised |

No `pip install` is required for the control plane or the test suite. The
platform is standard library only.

---

## Layer 1 — the automated suite

```bash
make test                       # 132 tests, verbose
cd backend && python3 -m unittest discover -s tests -q     # quiet
```

Expected on a machine **without** Docker:

```
Ran 132 tests in ~5s
OK (skipped=11)
```

Expected **with** Docker: `OK` with fewer or no skips. **Any failure is a
regression** — the suite is green on every supported configuration.

### What each file covers

| File | Tests | Area |
|---|---|---|
| `test_users.py` | 13 | Provisioning, password hashing, sessions, disable-revokes |
| `test_scoring.py` | 11 | Weights, penalties, overrides, explainability |
| `test_detection.py` | 11 | Rule matching, MTTD, log vs technique basis |
| `test_learning.py` | 10 | Classes, rosters, lessons, quizzes, gradebook |
| `test_siem.py` | 10 | Wazuh ingest and alert forwarding |
| `test_api.py` | 9 | HTTP routing, status codes, auth enforcement |
| `test_catalog.py` | 9 | Scenario/module search and filters |
| `test_db.py` | 9 | Persistence layer |
| `test_provisioning.py` | 9 | Live range provisioning, teardown |
| `test_service.py` | 8 | Orchestration, evidence, audit |
| `test_execution.py` | 7 | Execution adapters, isolation flags |
| `test_logsearch.py` | 7 | Log search **and defender redaction** |
| `test_lifecycle.py` | 6 | State machine, illegal transitions |
| `test_reporting.py` | 5 | JSON, CSV, HTML, DOCX export |
| `test_frameworks.py` | 5 | NIST/NICE/CIS/CAE crosswalks |
| `test_migration.py` | 3 | In-place schema upgrade from an older DB |

### Running a subset

```bash
cd backend
python3 -m unittest tests.test_logsearch -v                       # one file
python3 -m unittest tests.test_scoring.ScoringTest -v             # one class
python3 -m unittest tests.test_lifecycle -v -k illegal            # by name
```

---

## Layer 2 — smoke tests

```bash
make demo        # drives a whole exercise end to end, in memory
make catalog     # prints the seeded content
```

`make demo` should walk the lifecycle and print a score:

```
Created range range-xxxxxxxx for CR-PHISH-001 (REQUESTED)
  -> PREFLIGHT
  -> PROVISIONING
  -> SEEDING
  -> READY
Started exercise run-xxxxxxxx
Score: 64.18 (weighted 64.18)
--- REPORT --- { ... }
```

`make catalog` must list **10 scenarios** and **25 modules**. A short list means
seed data did not load.

### Check the execution mode

This is the first thing to check on any deployment, because it determines
whether attacks run for real:

```bash
make serve                                    # then, in another shell:
curl -s localhost:8080/api/health | python3 -m json.tool
```

```json
{
  "status": "ok",
  "service": "cyberrange",
  "execution": { "real": false, "mode": "simulated", "docker_host": null, "remote": false }
}
```

`"mode": "docker"` means modules execute for real. `"simulated"` means no Docker
daemon was reachable — expected on a hosted deployment, a defect on a Docker
host.

---

## Layer 3 — API tests

Run the server against a **throwaway database** so testing never touches your
working data:

```bash
cd backend
CR_ADMIN_PASSWORD=testpw python3 -m cyberrange serve --port 8099 --db /tmp/cr-test.db
```

### Full lifecycle

```bash
BASE=http://127.0.0.1:8099/api
TOK=$(curl -s -d '{"username":"admin","password":"testpw"}' $BASE/login \
      | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")
A="Authorization: Bearer $TOK"

RID=$(curl -s -H "$A" -H 'Content-Type: application/json' \
      -d '{"scenario_id":"CR-DOCKER-001"}' $BASE/ranges \
      | python3 -c "import sys,json;print(json.load(sys.stdin)['id'])")

for a in preflight provision seed ready; do
  curl -s -H "$A" -H 'Content-Type: application/json' \
       -d "{\"action\":\"$a\"}" $BASE/ranges/$RID/actions
done

EX=$(curl -s -H "$A" -H 'Content-Type: application/json' \
     -d "{\"range_id\":\"$RID\"}" $BASE/exercises \
     | python3 -c "import sys,json;print(json.load(sys.stdin)['id'])")

curl -s -H "$A" -H 'Content-Type: application/json' \
     -d '{"module_id":"CR-MOD-DOCKER-RUNTIME-001"}' $BASE/exercises/$EX/modules
curl -s -H "$A" $BASE/exercises/$EX/timeline
curl -s -H "$A" -H 'Content-Type: application/json' \
     -d '{"raw_scores":{"detection":80,"red_execution":70}}' $BASE/exercises/$EX/score
curl -s -H "$A" $BASE/exercises/$EX/report
```

Checks:

- Each lifecycle action returns the **next state**: `PREFLIGHT`, `PROVISIONING`,
  `SEEDING`, `READY`.
- Module execution returns `real`, `adapter`, `events_recorded` and
  `detections_fired`. On a Docker host `real` must be `true` for the twelve
  modules that carry an execution spec.
- The score response carries `total`, `weighted_before_penalty`, `dimensions`,
  `penalties`, `overrides` and `derived`. Every dimension must show its raw
  score, weight and contribution — **if a number cannot be explained, that is a
  bug**.
- All four report formats return HTTP 200:
  `report.json`, `report.csv`, `report.html`, `report.docx`.

### The fog of war — the most important test

The defender's redacted view is the product's core claim. Verify it at the API,
not in the UI, because the UI is not where it is enforced.

```bash
# as admin/instructor
curl -s -H "$A" "$BASE/exercises/$EX/logs" | python3 -m json.tool
# as blue
curl -s -H "Authorization: Bearer $BLUE_TOK" "$BASE/exercises/$EX/logs" | python3 -m json.tool
```

| | Instructor view | Blue view |
|---|---|---|
| `redacted` | `false` | **`true`** |
| Event kinds | includes `ttp-exec`, `ttp-emulation`, `expected-telemetry` | those kinds absent |
| `technique_id` on events | present | **absent** |
| Payload `module`, `cmd`, `safety_class`, `adapter` | present | **stripped** |
| Event `source` | `module:CR-MOD-...` | relabelled `host:victim` etc. |

If blue can see a module ID or a technique ID anywhere, the exercise is
worthless and the finding is critical.

---

## Layer 4 — manual exercise

The full walkthrough is [LAB_GUIDE.md](LAB_GUIDE.md). In short:

1. Sign in as `admin`, create `prof` (instructor), `red1` (red), `blue1` (blue).
2. As `prof`: create a range for **Docker compromise**, prepare it, start the
   exercise.
3. As `red1`: run **Abnormal container runtime activity** from the attack
   console. Confirm the result box reports a real run, the image, the exit code,
   the event count and the detections fired.
4. As `blue1`: open the SOC console. Filter to `detection` for alerts, then
   search the logs (`root`, `/tmp`, `payload`, `secret`). Submit a finding and
   attribute the technique.
5. As `prof`: end the exercise, open the report, export each format.

Use two browsers (or one private window) so red and blue can be signed in at
once.

---

## Negative and security tests

These matter more than the happy path. All results below were verified against
the current build.

| Test | Expected | Verified response |
|---|---|---|
| API call with no token | 401 | `{"error": "authentication required"}` |
| Login with wrong password | 401 | `{"error": "invalid credentials"}` |
| Login with unknown username | 401 | same generic message (no account enumeration) |
| Repeat a completed lifecycle action | 409 | illegal transition rejected |
| Unknown module ID | 404 | `{"error": "Unknown module: NOPE"}` |
| Blue executes any module | 403 | `Role 'blue' is not permitted to perform 'module:execute'` |
| Blue creates a range | 403 | `Role 'blue' is not permitted to perform 'range:create'` |
| Blue overrides a score | 403 | `Role 'blue' is not permitted to perform 'exercise:score_override'` |
| **Red executes an S2 module** | 403 | `S2 modules require administrator or instructor approval` |
| Admin executes the same S2 module | 200 | executes |
| Disable a user, reuse their token | 401 | `{"error": "invalid or expired session"}` |

Also confirm, from the suite or by inspection:

- An **unsigned** module is refused at execution.
- The **Prohibited** safety class cannot be executed by any role, admin included.
- Releasing a **QUARANTINED** range requires admin.

---

## Known issue — audit ledger is not permission-checked

**`GET /api/audit` returns the full audit ledger to any authenticated role.**

`rbac.py` defines an `admin:audit` permission and grants it only to `admin`, but
the route in `server.py` never checks it. Reproduce:

```bash
# as blue1
curl -s -H "Authorization: Bearer $BLUE_TOK" "$BASE/audit?limit=100"
```

Expected 403. Actual 200, including entries like:

```json
{"actor": "admin", "role": "admin", "action": "module:execute",
 "target": "run-853406a2e6d1", "detail": "CR-MOD-DOCKER-ESCAPE-001 (simulated)"}
```

This **defeats the fog of war**: the module ID that `/exercises/{id}/logs`
carefully strips from the defender's view is handed to the same defender by the
audit endpoint. Any blue analyst can read the answer key mid-exercise.

Until it is fixed, the fog-of-war test above passes at the log endpoint and
fails at the audit endpoint. Treat a blue-readable audit ledger as a defect, not
as expected behaviour.

---

## Testing real execution (Docker)

With a Docker daemon reachable:

```bash
curl -s localhost:8080/api/health          # expect "mode": "docker"
make test                                  # expect no Docker skips
```

Then run a module with an execution spec (for example
`CR-MOD-DOCKER-RUNTIME-001`) and confirm:

- The response reports `real: true` and `adapter: docker`.
- The timeline carries genuine `process-output` lines with real stdout.
- Log-basis detection rules fire against that output, with a recorded latency.
- The container is gone afterwards (`docker ps -a` shows no leftovers).
- Isolation held: no host mounts, no egress, memory and PID caps applied.

### Live ranges

```bash
CR_LIVE_RANGES=1 make serve
```

Verify:

- Provisioning creates a per-range internal network with **no egress**.
- A file written by one module is still present when the next module runs
  (persistent foothold).
- The victim can reach the web app target over the range network.
- `reset` returns targets to a clean state and keeps the range.
- `destroy` removes every container and the network — check with
  `docker ps -a --filter label=cyberrange`.

---

## Testing the PostgreSQL backend

```bash
export DATABASE_URL='postgresql://user:pw@host:5432/db?sslmode=require'
cd backend && python3 -m cyberrange serve
```

The same test suite runs against Postgres. Also verify the **migration path**
(`test_migration.py` covers it): a database created by an older build must be
upgraded in place on boot rather than erroring on a missing column.

---

## Environment-dependent skips

Skips are expected, not failures. Eleven tests skip without Docker, in
`test_detection.py`, `test_execution.py`, `test_learning.py` and
`test_provisioning.py`. One further test in `test_provisioning.py` skips itself
if the LDAP directory image does not bootstrap in your environment.

To see exactly what skipped:

```bash
cd backend && python3 -m unittest discover -s tests -v 2>&1 | grep -i skip
```

---

## Housekeeping

Running the server writes `backend/data/cyberrange.db`. Use `--db` to point at a
scratch file when testing, and `make clean` to remove runtime databases and
caches.

Do not restore `backend/data/` from git while a database exists — the SQLite
write-ahead log and the main database file must match, and mixing them silently
invalidates the data (a restored WAL against a live DB will, for example, make
the admin login fail).

---

## Filing a bug

Include:

1. The command or API call, verbatim.
2. Expected versus actual, with the full JSON response and status code.
3. `GET /api/health` output — especially `execution.mode`, since real and
   simulated behave differently.
4. The role you were acting as. Most defects here are role-specific.
5. Whether `make test` is green. A green suite plus a broken behaviour means a
   missing test, which is worth reporting on its own.
