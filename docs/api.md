# API Reference

`fortipot` exposes a small FastAPI service for health checks, event review, action review, approvals, releases, and redacted configuration inspection.

## Run the API

```powershell
fortipot api --config config.yaml --host 127.0.0.1 --port 8080
```

## Endpoints

## `GET /health`

Returns basic liveness status.

Example:

```bash
curl http://127.0.0.1:8080/health
```

Response:

```json
{
  "status": "ok"
}
```

## `GET /events`

Returns recent event records from SQLite.

Example:

```bash
curl http://127.0.0.1:8080/events
```

Each record includes:

- timestamp
- source IP
- source MAC when known
- classification
- score
- confidence
- matched behaviors
- recommended action
- reason

## `GET /actions`

Returns recent action records from SQLite.

Example:

```bash
curl http://127.0.0.1:8080/actions
```

Each record includes:

- timestamp
- source IP
- action
- enforcement mode
- status
- reason
- score
- confidence
- details

## `POST /actions/approve`

Approves a queued action in `approval_required` mode.

Example:

```bash
curl -X POST http://127.0.0.1:8080/actions/approve \
  -H "Content-Type: application/json" \
  -d '{"action_id": 1}'
```

Current MVP note:

- approval intent is recorded and acknowledged
- full replay/execution of the queued action is a documented next step

## `POST /actions/release`

Releases a quarantine or public-IP block by IP or MAC.

Example:

```bash
curl -X POST http://127.0.0.1:8080/actions/release \
  -H "Content-Type: application/json" \
  -d '{"ip":"10.0.0.25"}'
```

Or by MAC:

```bash
curl -X POST http://127.0.0.1:8080/actions/release \
  -H "Content-Type: application/json" \
  -d '{"mac":"aa:bb:cc:dd:ee:ff"}'
```

## `GET /config/redacted`

Returns a configuration view suitable for troubleshooting without exposing sensitive token naming details in raw form.

Example:

```bash
curl http://127.0.0.1:8080/config/redacted
```

## Operational Notes

- This API is intentionally small and local-first.
- Authentication and RBAC are not yet implemented in the MVP.
- If you expose the API outside localhost, place it behind appropriate access controls.
