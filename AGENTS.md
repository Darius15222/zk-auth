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
- Failure responses stay generic (`401 {ok:false}`); the reason goes to the log only. A malformed `/login/*` request answers 400 and logs `event.reason: bad_request`.
- One username namespace: a name registered for zk login cannot be registered for password login, and the reverse (409).
- Lockout (R-07): 10 login attempts for one (`source.ip`, `user.name`) pair within 5 minutes answer `429 {ok:false}` until the window ends, logged as a failure with `event.reason: rate_limited`. Attempts are counted before the check, so concurrent requests cannot exceed the limit; a success clears the count.
- `source.ip` is the last `X-Forwarded-For` hop when `TRUST_PROXY=1`. In k3d every client arrives through the svclb gateway (`10.42.0.1`), so in the lab the lockout is effectively per user and anyone can lock a user out for 5 minutes (accepted for the lab; behind a proxy that preserves client IPs it is per client).
- Used nonces are kept until the store fills (10 000 entries) so a late replay still logs `nonce_reuse`. A full store, or more than 16 concurrent bcrypt jobs, answers 503.
- New crypto goes through `@noble/*`; never hand-roll group arithmetic.

## API

| Route | Body | Result |
|---|---|---|
| `POST /register/zk` | `username`, `publicKey` (hex) | 201, 409 if the name is taken |
| `POST /register/password` | `username`, `password` (8-72 bytes) | 201, 409 or 503 |
| `POST /challenge` | `username` | `nonce`, single use, 60 s; 503 when the store is full |
| `POST /login/zk` | `username`, `nonce`, `R`, `s` | 200, 401 or 429 |
| `POST /login/password` | `username`, `password` | 200, 401, 429 or 503 |
| `GET /healthz` | | 200 |
