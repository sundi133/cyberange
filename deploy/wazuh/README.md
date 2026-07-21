# CyberRange + real Wazuh SIEM (Docker)

This brings up a **real Wazuh SIEM** (manager + indexer + dashboard) next to
CyberRange, all in Docker, and wires them together so red-team TTPs produce
**real Wazuh alerts** that flow back onto the CyberRange timeline.

```
 red runs a TTP ─► CyberRange writes events.json ─► wazuh.agent tails it
                                                        │
     CyberRange timeline ◄── forwarder ◄── alerts.json ◄── wazuh.manager
        (basis=siem detection)                             (local_rules.xml)
                                                        └─► wazuh.dashboard (UI)
```

## Why this isn't a single Dockerfile / not on vanilla Railway

Wazuh is a **multi-container** stack. The **Wazuh Indexer** (OpenSearch) needs
the host sysctl `vm.max_map_count=262144` and **~4 GB RAM**, which Railway's
managed containers don't provide. So run this stack on a **Docker host with
≥4 GB RAM** (your laptop, a VM/VPS, EC2, Fly.io machine, etc.). Railway remains
a fine home for the **CyberRange app alone**, pointed at a Wazuh you host here
(see "Railway split" below).

## Requirements

- Docker + Docker Compose v2
- ≥ 4 GB RAM free
- `sudo sysctl -w vm.max_map_count=262144` (Linux host; on Docker Desktop it's
  set inside the VM automatically)

## Run it

```bash
cd deploy/wazuh
cp .env.example .env && edit .env          # set CR_ADMIN_PASSWORD

./setup.sh                                  # fetch Wazuh single-node + gen certs

docker compose \
  -f wazuh-single-node/docker-compose.yml \
  -f docker-compose.override.yml \
  --env-file .env up -d --build
```

Give the indexer a minute to start, then:

- **CyberRange:** http://localhost:8080  (admin / `CR_ADMIN_PASSWORD`)
- **Wazuh dashboard:** https://localhost:443  (admin / the Wazuh default in the
  upstream `.env`, e.g. `SecretPassword` — change it)

### Verify the SIEM path end-to-end

```bash
CR_ADMIN_PASSWORD=... ./verify.sh
```
It runs a real container TTP (T1610) in CyberRange and waits for a **basis=siem**
detection — i.e. a genuine Wazuh alert forwarded back to the timeline. You'll
also see the alert in the Wazuh dashboard under *Threat Hunting* (rule ids
`100100`–`100122`, group `cyberrange`).

## How the pieces connect

| Component | Role |
|---|---|
| `cyberrange` | App. `WAZUH_INGEST_ENABLED=1` makes it also append every event as a JSON line to `/var/log/cyberrange/events.json` (shared volume). |
| `wazuh.agent` | Tails that file (`custom/agent-ossec.conf`, `log_format json`) and ships events to the manager. |
| `wazuh.manager` | Evaluates `custom/local_rules.xml` against the decoded JSON and raises alerts to `alerts.json`. |
| `forwarder` | Tails `alerts.json`, keeps `cyberrange`-group alerts, and POSTs them to `/api/siem/alert` → a `basis=siem` detection. |
| `wazuh.indexer` / `wazuh.dashboard` | Store and visualize the alerts (standard Wazuh UI). |

Detection rules live in [`custom/local_rules.xml`](custom/local_rules.xml) —
edit them to tune coverage; they key on the CyberRange fields `kind`,
`technique_id`, and real `payload.line` content.

## Railway split

Deploy the **CyberRange app** on Railway (see `../../docs/DEPLOY.md`) and set:

```
WAZUH_INGEST_ENABLED=0     # or forward over syslog to your Wazuh host
```

Host the **Wazuh stack** here (VM/VPS). If you want Railway's app to feed this
Wazuh, expose the manager's syslog/agent port and run the forwarder alongside
Wazuh pointed at the Railway app's public URL (`CYBERRANGE_URL`). The app and
SIEM don't need to be co-located — only the forwarder needs to reach both.

## Verification status

The CyberRange side (event sink → Wazuh-ready JSON, and `/api/siem/alert` →
`basis=siem` detection) and the forwarder's alert parsing are covered by unit
tests. The full 4 GB Wazuh stack is meant to be brought up on a suitable host
with the commands above; `verify.sh` confirms the end-to-end path there. The two
Wazuh touchpoints to sanity-check on first run are (1) the agent enrolling with
the manager and (2) `local_rules.xml` loading (`/var/ossec/bin/wazuh-logtest`).
