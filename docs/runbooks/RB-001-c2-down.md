# RB-001 — C2 Server Down

**Alert:** `C2Down`  
**Severity:** CRITICAL  
**MTTR target:** < 10 minutes  
**Owner:** On-call operator

---

## Symptom

The AEGIS C2 server (`aegis-c2-1` or `aegis-c2-2`) is not responding to health
checks.  All SSE streams are dropped, the dashboard shows "Disconnected", and
operators cannot issue commands.

---

## Immediate triage (2 min)

```bash
# 1. Is the container running?
docker ps --filter name=aegis-c2

# 2. Check recent logs (last 100 lines)
docker logs aegis-c2-1 --tail 100

# 3. Is the process still responding to /health?
curl -s http://localhost:5000/health | jq .

# 4. Check readiness — which dependency failed?
curl -s http://localhost:5000/ready | jq .
```

---

## Decision tree

### Case A — Container exited / not running

```bash
docker compose up -d c2-1
# Wait for healthcheck to pass:
docker compose ps c2-1
```

If it immediately exits again:
```bash
docker logs aegis-c2-1 | tail -50
# Look for: ImportError, SyntaxError, FATAL, postgres pool failed
```

### Case B — Container running but /health not responding

```bash
# Enter the container
docker exec -it aegis-c2-1 bash

# Check if Flask is listening
ss -tlnp | grep 5000

# Check process
ps aux | grep python

# If process is dead but container is up:
pkill -f app.py   # let Docker restart it
```

### Case C — /health OK but /ready returns 503

```bash
curl -s http://localhost:5000/ready | jq .checks
```

- **postgres: error** → See RB-002 (Postgres Down)
- **redis: error**    → See RB-003 (Redis Down)
- Both fine but still 503 → Check migrations (new schema not applied?)

```bash
docker exec aegis-postgres psql -U aegis -d aegis -c '\dt'
# If missing v9 tables:
docker exec aegis-postgres psql -U aegis -d aegis \
  -f /docker-entrypoint-initdb.d/02_v9.sql
```

### Case D — OOM kill (container restarting in loop)

```bash
docker stats aegis-c2-1 --no-stream
# Check memory
docker inspect aegis-c2-1 | jq '.[].HostConfig.Memory'
# Increase limit in docker-compose or restart with more memory
```

---

## Escalation path

1. **< 5 min**: Try restart — `docker compose restart c2-1`
2. **5–10 min**: Check logs + dependency health → apply targeted fix
3. **> 10 min**: Page the team lead; consider activating c2-2 failover

## Failover to c2-2

```bash
# Start c2-2 if not already running
docker compose --profile ha up -d c2-2

# Update dashboard C2_URL to point to c2-2
docker compose exec dashboard env C2_URL=http://c2-2:5000 \
  supervisorctl restart dashboard
```

---

## Post-incident

1. Run `docker logs aegis-c2-1 > incident-$(date +%Y%m%d).log`
2. File an incident report in `docs/incidents/`
3. If crash was caused by a bug: open a ticket and add a regression test
4. Update this runbook if the resolution differed from documented steps
