# zk-auth

A minimal authentication service with two logins side by side:

- **zero-knowledge login** (`/login/zk`): the client proves it knows a secret key with a Schnorr proof. The server never sees the secret, and each proof is bound to a single-use nonce.
- **password login** (`/login/password`): a classic bcrypt baseline, so both methods can be compared under the same attacks and detections.

In the [zk-secops lab](https://github.com/Darius15222/zk-secops-dev) it is the monitored application. Every authentication decision is written to stdout as one ECS JSON line, and the SIEM turns those lines into alerts (replayed proofs, forged proofs, brute force).

## How the zero-knowledge login works

1. **Register:** the client generates a key pair and sends only the public key (`POST /register/zk`).
2. **Challenge:** `POST /challenge` returns a random nonce, valid for 60 seconds and usable once.
3. **Prove:** the client signs `(username, nonce)` with a Schnorr proof (`R`, `s`) and sends it to `POST /login/zk`.
4. **Verify:** the server checks the proof against the stored public key and burns the nonce. A replayed proof fails and is logged as `nonce_reuse`.

## API

| Route | Body | Result |
|---|---|---|
| `POST /register/zk` | `username`, `publicKey` (hex) | 201, 409 if the name is taken |
| `POST /register/password` | `username`, `password` (8-72 bytes) | 201, 409 or 503 |
| `POST /challenge` | `username` | `nonce`; 503 when the store is full |
| `POST /login/zk` | `username`, `nonce`, `R`, `s` | 200, 400, 401 or 429 |
| `POST /login/password` | `username`, `password` | 200, 400, 401, 429 or 503 |
| `GET /healthz` | | 200 |

Failures are generic (`401 {ok:false}`); the reason goes only to the log (`event.reason`). After 10 attempts for one source and user within 5 minutes, further attempts answer 429 for 5 minutes (R-07).

## Layout

```
src/
├── schnorr.ts   keygen, prove, verify (Schnorr over ristretto255)
├── server.ts    HTTP routes, lockout, nonce store, ECS audit log
└── client.ts    demo client: keygen | register | login
test/
└── auth.test.ts crypto, HTTP flows, lockout, replay, logged reasons
Dockerfile       two stages, distroless runtime
.github/workflows/
├── ci.yml           test, Trivy + Semgrep + gitleaks, build, SBOM, cosign signature, PR to zk-platform
├── ai-review.yml    advisory AI security review of the diff
└── token-expiry.yml weekly check of the token that opens zk-platform PRs
```

## Technologies and why

| Technology | Used for | Why |
|---|---|---|
| Node.js 26 + TypeScript | The service | Node runs TypeScript directly (type stripping), so there is no build step; `node:http` and `node:test` keep dependencies near zero |
| `@noble/curves` (ristretto255) | Schnorr proofs | An audited, dependency-free library; ristretto255 gives a prime-order group without cofactor pitfalls. Group arithmetic is never written by hand |
| bcryptjs | Password baseline | The standard slow hash, pure JS (no native build) |
| ECS JSON logs | Audit trail | Elastic Common Schema field names, so the SIEM needs no parsing pipeline |
| Distroless image | Runtime | No shell or package manager, runs as non-root; base images pinned by digest |
| cosign, syft, Trivy | Supply chain (R-03) | CI signs the image keylessly and attaches an SBOM; zk-platform deploys only digests signed by this CI |

## Commands

| Command | Does |
|---|---|
| `npm ci && npm test` | Unit and HTTP tests |
| `npm start` | Server on `PORT` (default 8080) |
| `node src/client.ts keygen \| register \| login` | Demo client |
| `docker build -t zk-auth:dev .` | Image |

Rules for changes (log fields, lockout, crypto) are in [AGENTS.md](AGENTS.md).
