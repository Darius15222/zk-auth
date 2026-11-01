// Minimal auth service: Schnorr (zero-knowledge) login next to a bcrypt password baseline.
// Every auth attempt is logged to stdout as one ECS JSON line for the SIEM.
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { randomBytes } from 'node:crypto';
import bcrypt from 'bcryptjs';
import { verify, isPublicKey } from './schnorr.ts';

// ponytail: in-memory stores, lost on restart; a database comes with the full dissertation prototype
const zkUsers = new Map<string, string>(); // user -> public key
const pwUsers = new Map<string, string>(); // user -> bcrypt hash
const nonces = new Map<string, { user: string; exp: number; used: boolean }>();

const NONCE_TTL_MS = 60_000;
const USER_RE = /^[a-z0-9_-]{1,32}$/;
const BCRYPT_COST = 12;
const DUMMY_HASH = bcrypt.hashSync('timing-equalizer', BCRYPT_COST); // unknown users cost the same as known ones
const TRUST_PROXY = process.env.TRUST_PROXY === '1'; // set behind Traefik so source.ip is the real client

type Body = Record<string, unknown>;

function sourceIp(req: IncomingMessage): string {
  const xff = req.headers['x-forwarded-for'];
  if (TRUST_PROXY && typeof xff === 'string') return xff.split(',')[0].trim();
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

const routes: Record<string, (req: IncomingMessage, res: ServerResponse, b: Body, user: string) => Promise<void> | void> = {
  '/register/zk'(req, res, b, user) {
    const pk = str(b, 'publicKey');
    if (!isPublicKey(pk)) return send(res, 400, { error: 'invalid publicKey' });
    if (zkUsers.has(user)) return send(res, 409, { error: 'user exists' });
    zkUsers.set(user, pk);
    audit(req, 'register-zk', 'success', user);
    send(res, 201, { ok: true });
  },

  async '/register/password'(req, res, b, user) {
    const pw = str(b, 'password');
    if (pw.length < 8 || Buffer.byteLength(pw) > 72) return send(res, 400, { error: 'password must be 8-72 bytes' });
    if (pwUsers.has(user)) return send(res, 409, { error: 'user exists' });
    pwUsers.set(user, await bcrypt.hash(pw, BCRYPT_COST));
    audit(req, 'register-password', 'success', user);
    send(res, 201, { ok: true });
  },

  '/challenge'(_req, res, _b, user) {
    // ponytail: O(n) sweep per request; a TTL cache if challenge volume grows
    const now = Date.now();
    for (const [k, v] of nonces) if (now > v.exp + NONCE_TTL_MS) nonces.delete(k);
    const nonce = randomBytes(32).toString('hex');
    nonces.set(nonce, { user, exp: now + NONCE_TTL_MS, used: false }); // issued for unknown users too: no enumeration
    send(res, 200, { nonce });
  },

  '/login/zk'(req, res, b, user) {
    const reason = consumeNonce(str(b, 'nonce'), user)
      || (!zkUsers.has(user) ? 'unknown_user' : '')
      || (verify(zkUsers.get(user)!, user, str(b, 'nonce'), { R: str(b, 'R'), s: str(b, 's') }) ? '' : 'invalid_proof');
    audit(req, 'login-zk', reason ? 'failure' : 'success', user, reason || undefined);
    send(res, reason ? 401 : 200, { ok: !reason });
  },

  async '/login/password'(req, res, b, user) {
    const ok = await bcrypt.compare(str(b, 'password'), pwUsers.get(user) ?? DUMMY_HASH) && pwUsers.has(user);
    const reason = ok ? undefined : pwUsers.has(user) ? 'invalid_password' : 'unknown_user';
    audit(req, 'login-password', ok ? 'success' : 'failure', user, reason);
    send(res, ok ? 200 : 401, { ok });
  },
};

export const server = createServer(async (req, res) => {
  if (req.method === 'GET' && req.url === '/healthz') return send(res, 200, { ok: true });
  const route = req.method === 'POST' ? routes[req.url ?? ''] : undefined;
  if (!route) return send(res, 404, { error: 'not found' });
  try {
    const body = await readJson(req);
    const user = str(body, 'username');
    if (!USER_RE.test(user)) return send(res, 400, { error: 'username must match ' + USER_RE });
    await route(req, res, body, user);
  } catch {
    send(res, 400, { error: 'bad request' });
  }
});

if (import.meta.main) {
  const port = Number(process.env.PORT ?? 8080);
  server.listen(port, () => console.log(JSON.stringify({ message: `zk-auth listening on ${port}`, service: { name: 'zk-auth' } })));
}
