#!/usr/bin/env bash
# End-to-end check: run a red-team TTP in CyberRange and confirm a REAL Wazuh
# alert comes back as a basis=siem detection on the timeline.
set -euo pipefail

CR="${CYBERRANGE_URL:-http://127.0.0.1:8080}"
PW="${CR_ADMIN_PASSWORD:-admin}"

jqget() { python3 -c "import sys,json;print(json.load(sys.stdin)$1)"; }

echo "==> Logging in to CyberRange at $CR"
TOK=$(curl -s -d "{\"username\":\"admin\",\"password\":\"$PW\"}" "$CR/api/login" | jqget "['token']")
AUTH="Authorization: Bearer $TOK"

echo "==> Provisioning a Docker range and starting an exercise"
RID=$(curl -s -H "$AUTH" -H 'Content-Type: application/json' -d '{"scenario_id":"CR-DOCKER-001"}' "$CR/api/ranges" | jqget "['id']")
for a in preflight provision seed ready; do
  curl -s -H "$AUTH" -H 'Content-Type: application/json' -d "{\"action\":\"$a\"}" "$CR/api/ranges/$RID/actions" >/dev/null
done
EX=$(curl -s -H "$AUTH" -H 'Content-Type: application/json' -d "{\"range_id\":\"$RID\"}" "$CR/api/exercises" | jqget "['id']")

echo "==> Red-team: executing CR-MOD-DOCKER-RUNTIME-001 (T1610)"
curl -s -H "$AUTH" -H 'Content-Type: application/json' -d '{"module_id":"CR-MOD-DOCKER-RUNTIME-001"}' "$CR/api/exercises/$EX/modules" >/dev/null

echo "==> Waiting for Wazuh to alert and the forwarder to post it back…"
for i in $(seq 1 30); do
  N=$(curl -s -H "$AUTH" "$CR/api/exercises/$EX/detections" | python3 -c "import sys,json;print(sum(1 for d in json.load(sys.stdin) if d.get('basis')=='siem'))")
  if [ "$N" -gt 0 ]; then
    echo "PASS: $N Wazuh (basis=siem) detection(s) on exercise $EX"
    curl -s -H "$AUTH" "$CR/api/exercises/$EX/detections" \
      | python3 -c "import sys,json;[print('   rule',d['rule_version'],d['technique_id'],d['severity'],'-',d['detail'][:60]) for d in json.load(sys.stdin) if d.get('basis')=='siem']"
    exit 0
  fi
  sleep 5
done
echo "TIMEOUT: no basis=siem detection after ~150s."
echo "Check:  docker compose ... logs wazuh.agent wazuh.manager forwarder"
exit 1
