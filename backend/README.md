# VoIP MikroTik Smart Diagnostic Tool - Backend (Phase 1)

Production-oriented Express backend exposing diagnostic APIs for:
- Ping test
- DNS resolution
- Port checks (80, 443, 5060 by default)

## Prerequisites
- Node.js 18.18+
- npm 9+
- `ping` utility available in runtime environment

## Setup
```bash
cd backend
cp .env.example .env
npm install
```

## Run
```bash
npm run dev
```
or
```bash
npm start
```

Server defaults:
- host: `0.0.0.0`
- port: `4000`

Health check:
```bash
curl http://localhost:4000/health
```

## API

### POST /api/v1/diagnostics
Start a diagnostic run.

Body:
```json
{
  "target": "example.com",
  "ports": [80, 443, 5060]
}
```

- `target` (required): valid IPv4, hostname, or `localhost`
- `ports` (optional): array of ports (1-65535). Defaults to `[80, 443, 5060]`

Example:
```bash
curl -X POST http://localhost:4000/api/v1/diagnostics \
  -H "Content-Type: application/json" \
  -d '{"target":"example.com"}'
```

Response:
```json
{
  "id": "uuid",
  "status": "healthy",
  "startedAt": "...",
  "finishedAt": "..."
}
```

### GET /api/v1/diagnostics/:id
Get full diagnostic result by ID.

Example:
```bash
curl http://localhost:4000/api/v1/diagnostics/<id>
```

## Architecture
- `src/routes`: route definitions
- `src/controllers`: request handlers
- `src/services/network`: ping, DNS, and port checks
- `src/services/diagnostics`: orchestration logic
- `src/repositories`: persistence (memory + JSON file)
- `src/middleware`: validation and centralized errors
- `src/config`: environment and logging

## Notes
- Storage is in-memory with file persistence to `backend/data/diagnostics.json`.
- API uses security middleware (`helmet`, rate limit, CORS).
- Request and error logs are emitted in structured JSON via `pino`.
