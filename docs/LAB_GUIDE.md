# Running a Red vs Blue lab exercise

A step-by-step walkthrough for testing both sides of CyberRange. Follow it once
end to end and you will have seen the whole loop: red launches a real attack,
that attack writes real logs, blue hunts those logs and proves what happened.

## The core idea

```
   RED launches a technique          BLUE hunts what it left behind
   ─────────────────────────         ──────────────────────────────
   Attack console                    SOC console (log search)
        │                                     ▲
        │ runs a real command                 │ searches host logs + alerts
        ▼                                     │
   target container  ──── real stdout ────────┘
                     ──── detection rules ──► ALERT
```

Red's tooling is **hidden from blue**. Blue does not see "red ran
CR-MOD-DOCKER-RUNTIME-001 (T1610)". Blue sees `host:victim` emitting log lines
and an alert firing, and has to work out the rest. That is what makes it an
exercise rather than a demo.

## 0. Start the platform

```bash
make serve                 # http://127.0.0.1:8080
```

Docker Desktop should be running. Check the mode:

```bash
curl -s localhost:8080/api/health | python3 -m json.tool
```

`"mode": "docker"` means attacks execute for real. `"simulated"` means no
Docker was found, and blue will see fewer real log lines.

## 1. Create the accounts (as `admin`)

Sign in as `admin` / `admin`, open the **Admin** tab, and create:

| Username | Role | Password |
|---|---|---|
| `prof` | instructor | your choice |
| `red1` | red | your choice |
| `blue1` | blue | your choice |

Tip: to run both sides at once, use two browsers (or one normal window and one
private window) so red and blue can be logged in simultaneously.

## 2. Start the exercise (as `prof` or `admin`)

1. **Ranges** tab, select scenario **Docker compromise**, press **Create range**.
2. Press **Prepare range** (this runs preflight, provision, seed, ready in one
   click) and wait for the stepper to reach **Prepared**.
3. Press **Start exercise**. The range is now RUNNING and red and blue can join.

## 3. Red: launch the attack (as `red1`)

Open **Exercise**. You get a brief ("You are RED") and the **Attack console**.

1. Choose **Abnormal container runtime activity** in the dropdown.
2. Press **Launch attack**.
3. Read the result box. It confirms whether it ran for real, on which image,
   the exit code, how many log events it generated, and how many detections
   fired.

What just happened: a command really executed inside the target container. It
spawned a shell, wrote `/tmp/payload.sh`, made it executable, and ran it. Every
line of that output is now in the log store.

Run a second technique to build a chain, for example **Container/image/network
enumeration** or **Exposed synthetic secret access**.

## 4. Blue: hunt it down (as `blue1`)

Open **Exercise**. You get the **SOC console** instead of the raw timeline.

### 4a. Start from the alerts
Set **All event types** to `detection`. These are the rules that fired
automatically. Each shows the rule name, severity, and how long after the
activity it triggered (MTTD). This is your lead, not your answer.

### 4b. Search the logs
Clear the filter and search. Use the **Quick hunts** buttons or type your own:

| Search | What you are looking for |
|---|---|
| `root` | processes running as uid 0 |
| `/tmp` | files dropped in a world-writable directory |
| `shell` | a shell spawned inside a service container |
| `payload` | a suspicious file name |
| `secret` | credential access |
| `curl` | download or exfil attempts |

Filter by **source** (`host:victim`) to scope to one asset, or by **event
type** (`process-output`) to see raw host output.

You should find lines like:

```
host:victim  process-output   --- writing binary to /tmp ---
host:victim  process-output   -rwxr-xr-x 1 root root 23 /tmp/payload.sh
host:victim  process-output   uid=0(root) gid=0(root) ...
```

That is the attack, in evidence form.

### 4c. Raise a finding
Press **Use as evidence** on a damning line. It drops into the finding box.
Add your own wording, for example "Binary written to /tmp and executed as root
on host:victim", and press **Submit**. Each finding is hashed for integrity.

### 4d. Attribute the technique
In **Attribute the technique**, enter the ATT&CK ID you believe it maps to
(writing and executing a binary inside a container is `T1610`), set the verdict
to `detected`, and press **Record**.

Check yourself against the **Reference** tab, which lists every technique with
its lab behaviour and expected evidence.

## 5. Close it out (as `prof`)

1. Press **End exercise**.
2. Open **Report**. You get the score, ATT&CK coverage (expected vs observed vs
   detected, with gaps), the framework crosswalk (NIST CSF, NICE, CIS, CAE),
   evidence, and recommendations.
3. Export it as **DOCX**, **PDF/HTML**, **CSV**, or **JSON**.

## Testing it from the API instead

Everything above is also reachable over REST. Blue's log search is:

```bash
BASE=http://127.0.0.1:8080/api
TOK=$(curl -s -d '{"username":"blue1","password":"<pw>"}' $BASE/login \
      | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")

# search the logs as blue (redacted view)
curl -s -H "Authorization: Bearer $TOK" \
  "$BASE/exercises/<EXERCISE_ID>/logs?q=/tmp" | python3 -m json.tool

# what filters are available
curl -s -H "Authorization: Bearer $TOK" \
  "$BASE/exercises/<EXERCISE_ID>/log-sources"
```

Compare the same call with an instructor token: the instructor response
includes `ttp-exec` events with module ids and technique ids, and
`"redacted": false`. Blue's is `"redacted": true` with none of that. That is the
fog of war, enforced server side, not just hidden in the UI.

## What each role sees

| | Red | Blue | Purple | Instructor |
|---|---|---|---|---|
| Attack console | yes | no | yes | yes |
| Raw timeline (with technique labels) | yes | **no** | yes | yes |
| SOC log search | no | **yes** | no | no |
| Sees red's module ids / technique ids | yes | **no** | yes | yes |
| Submit evidence | yes | yes | no | no |
| Inject events | no | no | no | yes |
| Score and end exercise | no | no | no | yes |

## Troubleshooting

**Blue's log search is empty.** Red has not run anything yet, or the filters are
too narrow. Clear the search box and set both dropdowns back to "All".

**Attacks say `simulated` instead of real.** Docker is not reachable. Start
Docker Desktop and restart the server. Check `/api/health`.

**Blue sees no alerts, only raw logs.** Not every technique has a log-basis
detection rule. That is a genuine coverage gap and it will show up in the
report as a gap, which is the point of the exercise.
