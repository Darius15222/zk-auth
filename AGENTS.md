# zk-auth

Minimal authentication service for the zk-secops lab: Schnorr zero-knowledge login next to a bcrypt password baseline. Its job in the lab is to emit authentication events for the SIEM. Workspace rules (`zk-secops-dev/CLAUDE.md`, `harness/`) apply here too.

## Stack

Node.js 26 running TypeScript directly (type stripping, no build step), `node:http`, `node:test`. Dependencies: `@noble/curves` (ristretto255), `bcryptjs`. Image: distroless, non-root.

## Commands

| Command | Does |
|---|---|
| `npm test` | Unit and HTTP tests |
| `npm start` | Server on `PORT` (default 8080) |
| `node src/client.ts keygen \| register \| login` | Demo client |
| `docker build -t zk-auth:dev .` | Image |

## Layout

- `src/schnorr.ts`: keygen, prove, verify. `src/server.ts`: HTTP routes and ECS audit log. `src/client.ts`: demo client.
- `test/`: `node:test` suites.

## Rules

- Every auth decision logs exactly one ECS line: `event.category: authentication`, `event.action`, `event.outcome`, `event.reason` on failure, `user.name`, `source.ip`. Detections in `zk-detections` depend on these field names; change them only together.
- Failure responses stay generic (`401 {ok:false}`); the reason goes to the log only.
- New crypto goes through `@noble/*`; never hand-roll group arithmetic.

## API

| Route | Body | Result |
|---|---|---|
| `POST /register/zk` | `username`, `publicKey` (hex) | 201 |
| `POST /register/password` | `username`, `password` (8-72 bytes) | 201 |
| `POST /challenge` | `username` | `nonce`, single use, 60 s |
| `POST /login/zk` | `username`, `nonce`, `R`, `s` | 200 or 401 |
| `POST /login/password` | `username`, `password` | 200 or 401 |
| `GET /healthz` | | 200 |
