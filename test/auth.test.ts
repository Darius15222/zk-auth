import { test, before, after, mock } from 'node:test';
import assert from 'node:assert/strict';
import type { AddressInfo } from 'node:net';
import { server } from '../src/server.ts';
import { keygen, prove, verify } from '../src/schnorr.ts';

// the ECS lines the SIEM reads: detections in zk-detections match on event.action, event.outcome and event.reason
const logs: { event?: { action: string; outcome: string; reason?: string }; user?: { name: string } }[] = [];
const log = console.log;
console.log = (line: string) => { try { logs.push(JSON.parse(line)); } catch { log(line); } };
const lastEvent = () => logs.at(-1)?.event;

let base = '';
const post = async (path: string, body: object) => {
  const r = await fetch(base + path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  return { status: r.status, body: await r.json() };
};
const nonceFor = async (username: string) => (await post('/challenge', { username })).body.nonce as string;

before(() => new Promise<void>((ok) => server.listen(0, () => {
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  ok();
})));
after(() => server.close());

test('schnorr: honest proof verifies, tampered proof and wrong context do not', () => {
  const { secret, publicKey } = keygen();
  const p = prove(secret, 'alice', 'n1');
  assert.equal(verify(publicKey, 'alice', 'n1', p), true);
  assert.equal(verify(publicKey, 'alice', 'n2', p), false); // other nonce
  assert.equal(verify(publicKey, 'bob', 'n1', p), false); // other user
  assert.equal(verify(publicKey, 'alice', 'n1', { ...p, s: (BigInt('0x' + p.s) + 1n).toString(16) }), false);
  assert.equal(verify(publicKey, 'alice', 'n1', { R: 'zz', s: 'xyz' }), false); // malformed
});

test('zk login: success, wrong key fails, replayed proof fails', async () => {
  const { secret, publicKey } = keygen();
  assert.equal((await post('/register/zk', { username: 'alice', publicKey })).status, 201);

  const nonce = await nonceFor('alice');
  const proof = prove(secret, 'alice', nonce);
  assert.equal((await post('/login/zk', { username: 'alice', nonce, ...proof })).status, 200);
  assert.equal((await post('/login/zk', { username: 'alice', nonce, ...proof })).status, 401, 'replay must fail');

  const n2 = await nonceFor('alice');
  const forged = prove(keygen().secret, 'alice', n2);
  assert.equal((await post('/login/zk', { username: 'alice', nonce: n2, ...forged })).status, 401);
});

test('password login: success, wrong password and unknown user fail', async () => {
  assert.equal((await post('/register/password', { username: 'bob', password: 'correct horse' })).status, 201);
  assert.equal((await post('/login/password', { username: 'bob', password: 'correct horse' })).status, 200);
  assert.equal((await post('/login/password', { username: 'bob', password: 'wrong' })).status, 401);
  assert.equal((await post('/login/password', { username: 'nobody', password: 'whatever1' })).status, 401);
});

test('lockout: the 11th failure is 429, even with the right password; other users are not affected', async () => {
  assert.equal((await post('/register/password', { username: 'dave', password: 'correct horse' })).status, 201);
  assert.equal((await post('/register/password', { username: 'erin', password: 'correct horse' })).status, 201);
  for (let i = 0; i < 10; i++) assert.equal((await post('/login/password', { username: 'dave', password: 'wrong' })).status, 401);
  assert.equal((await post('/login/password', { username: 'dave', password: 'wrong' })).status, 429);
  assert.equal((await post('/login/password', { username: 'dave', password: 'correct horse' })).status, 429);
  assert.equal((await post('/login/password', { username: 'erin', password: 'correct horse' })).status, 200);
});

test('input validation', async () => {
  assert.equal((await post('/register/zk', { username: 'Bad Name!', publicKey: 'x' })).status, 400);
  assert.equal((await post('/register/zk', { username: 'carol', publicKey: 'not-a-point' })).status, 400);
  assert.equal((await fetch(base + '/nope')).status, 404);
});

test('one username namespace: a name taken by one method cannot be claimed with the other', async () => {
  assert.equal((await post('/register/zk', { username: 'frank', publicKey: keygen().publicKey })).status, 201);
  assert.equal((await post('/register/password', { username: 'frank', password: 'attacker-pw' })).status, 409);
  assert.equal((await post('/register/password', { username: 'gina', password: 'correct horse' })).status, 201);
  assert.equal((await post('/register/zk', { username: 'gina', publicKey: keygen().publicKey })).status, 409);
});

test('a public key sent in uppercase hex is stored canonically, so the honest proof verifies', async () => {
  const { secret, publicKey } = keygen();
  assert.equal((await post('/register/zk', { username: 'hank', publicKey: publicKey.toUpperCase() })).status, 201);
  const nonce = await nonceFor('hank');
  assert.equal((await post('/login/zk', { username: 'hank', nonce, ...prove(secret, 'hank', nonce) })).status, 200);
});

test('lockout holds under concurrency: 15 parallel wrong passwords give exactly 10 x 401', async () => {
  assert.equal((await post('/register/password', { username: 'ivan', password: 'correct horse' })).status, 201);
  // 15 < MAX_BCRYPT (16), so none answer 503
  const codes = await Promise.all(Array.from({ length: 15 }, () => post('/login/password', { username: 'ivan', password: 'wrong' })));
  assert.deepEqual(codes.map((c) => c.status).sort(), [...Array(10).fill(401), ...Array(5).fill(429)]);
});

test('every login decision logs the reason the detections match on', async () => {
  const { secret, publicKey } = keygen();
  await post('/register/zk', { username: 'judy', publicKey });
  const n1 = await nonceFor('judy');
  const proof = prove(secret, 'judy', n1);
  await post('/login/zk', { username: 'judy', nonce: n1, ...proof });
  assert.deepEqual(lastEvent(), { kind: 'event', category: ['authentication'], type: ['start'], action: 'login-zk', outcome: 'success' });
  await post('/login/zk', { username: 'judy', nonce: n1, ...proof });
  assert.equal(lastEvent()?.reason, 'nonce_reuse');
  const n2 = await nonceFor('judy');
  await post('/login/zk', { username: 'judy', nonce: n2, ...prove(keygen().secret, 'judy', n2) });
  assert.equal(lastEvent()?.reason, 'invalid_proof');
  await post('/login/zk', { username: 'judy', nonce: 'f'.repeat(64), ...proof });
  assert.equal(lastEvent()?.reason, 'unknown_nonce');
  await post('/login/password', { username: 'nobody', password: 'whatever1' });
  assert.equal(lastEvent()?.reason, 'unknown_user');
  await post('/register/password', { username: 'leo', password: 'correct horse' });
  for (let i = 0; i < 10; i++) await post('/login/password', { username: 'leo', password: 'wrong-one' });
  assert.equal(lastEvent()?.reason, 'invalid_password');
  await post('/login/password', { username: 'leo', password: 'wrong-one' });
  assert.equal(lastEvent()?.reason, 'rate_limited');
  assert.equal((await post('/login/zk', { username: 'Bad Name!' })).status, 400);
  assert.deepEqual([lastEvent()?.action, lastEvent()?.reason, logs.at(-1)?.user?.name], ['login-zk', 'bad_request', '-']);
});

test('a proof replayed minutes later is still logged as nonce_reuse', async () => {
  const { secret, publicKey } = keygen();
  await post('/register/zk', { username: 'kate', publicKey });
  const nonce = await nonceFor('kate');
  const proof = prove(secret, 'kate', nonce);
  assert.equal((await post('/login/zk', { username: 'kate', nonce, ...proof })).status, 200);
  mock.timers.enable({ apis: ['Date'], now: Date.now() + 10 * 60_000 });
  try {
    await nonceFor('kate'); // a challenge in between must not drop the burned nonce
    assert.equal((await post('/login/zk', { username: 'kate', nonce, ...proof })).status, 401);
    assert.equal(lastEvent()?.reason, 'nonce_reuse');
  } finally {
    mock.timers.reset();
  }
});

test('the lock lasts a full window from the 10th attempt, not from the first', async () => {
  assert.equal((await post('/register/password', { username: 'mia', password: 'correct horse' })).status, 201);
  mock.timers.enable({ apis: ['Date'], now: Date.now() });
  try {
    assert.equal((await post('/login/password', { username: 'mia', password: 'wrong' })).status, 401);
    mock.timers.tick(299_000);
    for (let i = 0; i < 9; i++) assert.equal((await post('/login/password', { username: 'mia', password: 'wrong' })).status, 401);
    mock.timers.tick(2_000); // past the first attempt's window
    assert.equal((await post('/login/password', { username: 'mia', password: 'wrong' })).status, 429);
  } finally {
    mock.timers.reset();
  }
});

// runs last: it fills the challenge store
test('a full challenge store answers 503 and logs it; a burned nonce survives the sweep for the replay window', async () => {
  const { secret, publicKey } = keygen();
  await post('/register/zk', { username: 'nina', publicKey });
  const nonce = await nonceFor('nina');
  const proof = prove(secret, 'nina', nonce);
  assert.equal((await post('/login/zk', { username: 'nina', nonce, ...proof })).status, 200);
  for (let i = 0; i < 20; i++) await Promise.all(Array.from({ length: 500 }, () => post('/challenge', { username: 'flood' })));
  assert.equal((await post('/challenge', { username: 'nina' })).status, 503);
  assert.deepEqual([lastEvent()?.action, lastEvent()?.outcome, lastEvent()?.reason], ['challenge', 'failure', 'busy']);
  mock.timers.enable({ apis: ['Date'], now: Date.now() + 2 * 60_000 }); // the flood has expired, nina's nonce is inside the window
  try {
    assert.equal((await post('/challenge', { username: 'nina' })).status, 200, 'the sweep frees expired nonces');
    assert.equal((await post('/login/zk', { username: 'nina', nonce, ...proof })).status, 401);
    assert.equal(lastEvent()?.reason, 'nonce_reuse');
  } finally {
    mock.timers.reset();
  }
});
