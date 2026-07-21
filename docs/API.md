# CyberRange API reference

Base path: `/api`. Authenticated requests carry a session token:

```
Authorization: Bearer <token>      # from POST /api/login
```

For API/testing convenience, requests without a Bearer token fall back to
identity headers (disable before real deployment):

```
X-CR-Role: admin | instructor | red | blue | purple | solo | security_leader
X-CR-User: <username>
```

## Auth & users (FR-12)

| Method | Path | Body | Notes |
|---|---|---|---|
| POST | `/api/login` | `{username, password}` | public; returns `{token, role, permissions, …}` |
| POST | `/api/logout` | — | revokes the caller's session |
| GET | `/api/me` | — | current identity + permissions |
| GET | `/api/roles` | — | role → summary + capabilities matrix |
| GET | `/api/users` | — | list users (`admin:manage_users`) |
| POST | `/api/users` | `{username, password, role, display_name?}` | provision (`admin:manage_users`) |
| POST | `/api/users/{username}/active` | `{active}` | enable/disable + revoke sessions |

Login returns generic `invalid credentials` (401) whether the username is
unknown, the password is wrong, or the account is disabled. Passwords are
stored PBKDF2-HMAC-SHA256 with a per-user salt. See [ROLES.md](ROLES.md).

Responses are JSON. Errors return `{"error": "..."}` with an appropriate
status (400 bad request, 401 unknown role, 403 forbidden, 404 not found,
409 illegal lifecycle transition, 500 internal).

## Catalog (FR-01)

| Method | Path | Notes |
|---|---|---|
| GET | `/api/health` | liveness |
| GET | `/api/tactics` | ATT&CK tactic/technique table |
| GET | `/api/reference` | scoring weights, safety classes, lifecycle states, detection stack |
| GET | `/api/scenarios` | filter: `role, tactic, difficulty, technique, platform, q` |
| GET | `/api/scenarios/{id}` | one scenario |
| GET | `/api/modules` | filter: `platform, safety_class, technique, tactic` |
| GET | `/api/modules/{id}` | one behavior module |
| GET | `/api/topologies` / `/api/topologies/{id}` | topology templates |

## Ranges (FR-03)

| Method | Path | Body | Permission |
|---|---|---|---|
| GET | `/api/ranges` | — | `range:read` |
| GET | `/api/ranges/{id}` | — | — |
| POST | `/api/ranges` | `{scenario_id, tenant?, ttl_hours?}` | `range:create` |
| POST | `/api/ranges/{id}/actions` | `{action}` | `range:lifecycle` |

`action` ∈ `preflight, provision, seed, ready, start, pause, resume,
complete, lock_evidence, archive, quarantine, destroy`. Illegal transitions
return 409. Releasing/destroying a `QUARANTINED` range requires `admin`.

## Exercises

| Method | Path | Body |
|---|---|---|
| POST | `/api/exercises` | `{range_id}` — starts a run (auto-advances READY→RUNNING) |
| GET | `/api/exercises` / `/api/exercises/{id}` | list / detail |
| GET | `/api/exercises/{id}/timeline` | synchronized UTC event list (FR-07) |
| POST | `/api/exercises/{id}/injects` | `{text, type?}` — needs `exercise:inject` |
| POST | `/api/exercises/{id}/modules` | `{module_id, inputs?}` — needs `module:execute` |
| POST | `/api/exercises/{id}/evidence` | `{description, classification?, linked_event?}` |
| GET | `/api/exercises/{id}/evidence` | list evidence with integrity hashes |
| POST | `/api/exercises/{id}/detections` | `{technique_id, verdict, rule_version?, latency_s?}` |
| GET | `/api/exercises/{id}/detections` | list detection results |
| POST | `/api/exercises/{id}/score` | `{raw_scores, penalties?, overrides?}` (FR-09) |
| POST | `/api/exercises/{id}/end` | ends run, completes + locks evidence |
| GET | `/api/exercises/{id}/report` | after-action report (FR-11) |

## Purple replay (FR-10)

| Method | Path | Body |
|---|---|---|
| POST | `/api/purple/compare` | `{baseline: {tech: cov}, replay: {tech: cov}}` |

Returns per-technique and aggregate baseline→replay coverage delta.

## Admin

| Method | Path | Notes |
|---|---|---|
| GET | `/api/audit?limit=N` | append-only audit ledger |

## Scoring payloads

`raw_scores` maps dimension → 0..100 quality score. Dimensions and default
weights: `red_execution` 0.25, `detection` 0.25, `investigation` 0.20,
`response` 0.20, `collaboration` 0.10.

```json
{
  "raw_scores": {"red_execution": 80, "detection": 70, "investigation": 65,
                 "response": 60, "collaboration": 75},
  "penalties": [{"reason": "unapproved egress attempt", "points": 15}],
  "overrides": [{"dimension": "detection", "old_raw": 70, "new_raw": 85,
                 "instructor": "inst-1", "justification": "manual review"}]
}
```

The response lists every dimension's raw score, weight, and contribution,
plus penalties and overrides — every scoring input is explainable and audited
(spec §7). Overrides require `exercise:score_override`.
