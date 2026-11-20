// Minimal auth service: Schnorr (zero-knowledge) login next to a bcrypt password baseline.
// Every auth attempt is logged to stdout as one ECS JSON line for the SIEM.
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { randomBytes } from 'node:crypto';
import bcrypt from 'bcryptjs';
import { verify, canonicalPublicKey } from './schnorr.ts';

// ponytail: in-memory stores, lost on restart; a database comes with the full dissertation prototype
// One username namespace: a name registered with either method cannot be claimed with the other.
const zkUsers = new Map<string, string>(); // user -> public key
const pwUsers = new Map<string, string>(); // user -> bcrypt hash
const taken = (user: string) => zkUsers.has(user) || pwUsers.has(user);
// used nonces stay until the store is swept, so a late replay still logs nonce_reuse (the replay detection's signal)
const nonces = new Map<string, { user: string; exp: number; used: boolean }>();

const NONCE_TTL_MS = 60_000;
const MAX_NONCES = 10_000; // unauthenticated /challenge must not grow memory without bound
const USER_RE = /^[a-z0-9_-]{1,32}$/;
const BCRYPT_COST = 12;
const DUMMY_HASH = bcrypt.hashSync('timing-equalizer', BCRYPT_COST); // unknown users cost the same as known ones
const MAX_BCRYPT = 16; // concurrent bcrypt jobs; past this, password routes answer 503 instead of starving the event loop
let bcryptBusy = 0;
// Behind Traefik: source.ip is the last X-Forwarded-For hop, the one Traefik appended (earlier hops are client-supplied).
// In k3d every client arrives through the svclb gateway (10.42.0.1), so the lab's source.ip is that gateway.
const TRUST_PROXY = process.env.TRUST_PROXY === '1';

// R-07 lockout: MAX_FAILURES failed logins for one (source IP, user) pair inside LOCK_MS block that pair until the window ends.
// Keyed on the pair so that, behind a proxy that preserves client IPs, an attacker cannot lock the real user out from another address.
// ponytail: in k3d all clients share the gateway IP, so the lab's key is effectively per user (accepted, see AGENTS.md);
// in-memory and per pair, so guessing one user from many addresses is not throttled; a per-user limit in a shared store is the upgrade path
const MAX_FAILURES = 10;
const LOCK_MS = 5 * 60_000;
const failures = new Map<string, { n: number; exp: number }>(); // "ip|user" -> failures in the current window

type Body = Record<string, unknown>;

function sourceIp(req: IncomingMessage): string {
  const xff = req.headers['x-forwarded-for'];
  if (TRUST_PROXY && typeof xff === 'string') return xff.split(',').at(-1)!.trim();
  return (req.socket.remoteAddress ?? '').replace(/^::ffff:/, ''); // IPv4-mapped IPv6 -> plain IPv4
}

function audit(req: IncomingMessage, action: string, outcome: 'success' | 'failure', user: string, reason?: string) {
  console.log(JSON.stringify({
    '@timestamp': new Date().toISOString(),
    'log.level': outcome === 'success' ? 'info' : 'warn',
    message: `${action} ${outcome} for ${user}${reason ? `: ${reason}` : ''}`,
    ecs: { version: '8.11.0' },
    service: { name: 'zk-auth' },
    event: { kind: 'event', category: ['authentication'], type: ['start'], action, outcome, ...(reason && { reason }) },
    user: { name: user },
    source: { ip: sourceIp(req) },
  }));
}

function send(res: ServerResponse, status: number, body: object) {
  res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify(body));
}

async function readJson(req: IncomingMessage): Promise<Body> {
  let raw = '';
  for await (const chunk of req) {
    raw += chunk;
    if (raw.length > 16_384) throw new Error('body too large');
  }
  const body = JSON.parse(raw);
  if (typeof body !== 'object' || body === null) throw new Error('body must be an object');
  return body;
}

const str = (b: Body, k: string): string => (typeof b[k] === 'string' ? (b[k] as string) : '');

// returns why a nonce cannot be used, or '' when it is valid; a valid nonce is burned
function consumeNonce(nonce: string, user: string): string {
  const entry = nonces.get(nonce);
  if (!entry || entry.user !== user) return 'unknown_nonce';
  if (entry.used) return 'nonce_reuse'; // replayed proof
  if (Date.now() > entry.exp) return 'nonce_expired';
  entry.used = true;
  return '';
}

async function withBcrypt<T>(job: () => Promise<T>): Promise<T> {
  bcryptBusy++;
  try {
    return await job();
  } finally {
    bcryptBusy--;
  }
}

function locked(key: string): boolean {
  const f = failures.get(key);
  if (f && Date.now() > f.exp) failures.delete(key);
  return (failures.get(key)?.n ?? 0) >= MAX_FAILURES;
}

// counted before the check runs: a check that awaits (bcrypt) would otherwise let concurrent attempts all pass locked()
function countAttempt(key: string) {
  const now = Date.now();
  // usernames are attacker-chosen: drop expired windows before the map can grow without bound
  if (failures.size > 10_000) for (const [k, v] of failures) if (now > v.exp) failures.delete(k);
  const f = failures.get(key) ?? { n: 0, exp: now + LOCK_MS };
  f.n++;
  failures.set(key, f);
}

// one login attempt behind the lockout: `check` returns why the login fails, or '' when it succeeds
async function login(req: IncomingMessage, res: ServerResponse, action: string, user: string, check: () => string | Promise<string>) {
  const key = `${sourceIp(req)}|${user}`;
  if (locked(key)) {
    audit(req, action, 'failure', user, 'rate_limited'); // still one failure line, so brute force detections keep counting
    return send(res, 429, { ok: false });
  }
  countAttempt(key);
  const reason = await check();
  if (!reason) failures.delete(key);
  audit(req, action, reason ? 'failure' : 'success', user, reason || undefined);
  send(res, reason ? 401 : 200, { ok: !reason });
}

const routes: Record<string, (req: IncomingMessage, res: ServerResponse, b: Body, user: string) => Promise<void> | void> = {
  '/register/zk'(req, res, b, user) {
    const pk = canonicalPublicKey(str(b, 'publicKey'));
    if (!pk) return send(res, 400, { error: 'invalid publicKey' });
    if (taken(user)) return send(res, 409, { error: 'user exists' }); // ponytail: open registration reveals taken names by design
    zkUsers.set(user, pk);
    audit(req, 'register-zk', 'success', user);
    send(res, 201, { ok: true });
  },

  async '/register/password'(req, res, b, user) {
    const pw = str(b, 'password');
    if (pw.length < 8 || Buffer.byteLength(pw) > 72) return send(res, 400, { error: 'password must be 8-72 bytes' });
    if (taken(user)) return send(res, 409, { error: 'user exists' });
    if (bcryptBusy >= MAX_BCRYPT) return send(res, 503, { error: 'busy' });
    const hash = await withBcrypt(() => bcrypt.hash(pw, BCRYPT_COST));
    if (taken(user)) return send(res, 409, { error: 'user exists' }); // claimed while hashing
    pwUsers.set(user, hash);
    audit(req, 'register-password', 'success', user);
    send(res, 201, { ok: true });
  },

  '/challenge'(_req, res, _b, user) {
    const now = Date.now();
    // sweep only when full: expired unused nonces go first, then used ones whose replay window (LOCK_MS) has passed
    if (nonces.size >= MAX_NONCES) for (const [k, v] of nonces) if (now > v.exp + (v.used ? LOCK_MS : 0)) nonces.delete(k);
    if (nonces.size >= MAX_NONCES) return send(res, 503, { error: 'busy' });
    const nonce = randomBytes(32).toString('hex');
    nonces.set(nonce, { user, exp: now + NONCE_TTL_MS, used: false }); // issued for unknown users too: no enumeration
    send(res, 200, { nonce });
  },

  '/login/zk'(req, res, b, user) {
    return login(req, res, 'login-zk', user, () => consumeNonce(str(b, 'nonce'), user)
      || (!zkUsers.has(user) ? 'unknown_user' : '')
      || (verify(zkUsers.get(user)!, user, str(b, 'nonce'), { R: str(b, 'R'), s: str(b, 's') }) ? '' : 'invalid_proof'));
  },

  '/login/password'(req, res, b, user) {
    if (bcryptBusy >= MAX_BCRYPT) {
      audit(req, 'login-password', 'failure', user, 'busy');
      return send(res, 503, { ok: false });
    }
    return login(req, res, 'login-password', user, async () => {
      const ok = await withBcrypt(() => bcrypt.compare(str(b, 'password'), pwUsers.get(user) ?? DUMMY_HASH)) && pwUsers.has(user);
      return ok ? '' : pwUsers.has(user) ? 'invalid_password' : 'unknown_user';
    });
  },
};

export const server = createServer(async (req, res) => {
  if (req.method === 'GET' && req.url === '/healthz') return send(res, 200, { ok: true });
  const route = req.method === 'POST' ? routes[req.url ?? ''] : undefined;
  if (!route) return send(res, 404, { error: 'not found' });
  // a malformed login is still an auth decision: one failure line (the username is logged only when it is safe to)
  const badLogin = (user: string) => {
    if (req.url!.startsWith('/login/')) audit(req, req.url!.slice(1).replace('/', '-'), 'failure', USER_RE.test(user) ? user : '-', 'bad_request');
  };
  let user = '';
  try {
    const body = await readJson(req);
    user = str(body, 'username');
    if (!USER_RE.test(user)) {
      badLogin(user);
      return send(res, 400, { error: 'username must match ' + USER_RE });
    }
    await route(req, res, body, user);
  } catch {
    if (!res.headersSent) {
      badLogin(user);
      send(res, 400, { error: 'bad request' });
    }
  }
});

if (import.meta.main) {
  const port = Number(process.env.PORT ?? 8080);
  server.listen(port, () => console.log(JSON.stringify({ message: `zk-auth listening on ${port}`, service: { name: 'zk-auth' } })));
}
