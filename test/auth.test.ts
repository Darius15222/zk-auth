import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import type { AddressInfo } from 'node:net';
import { server } from '../src/server.ts';
import { keygen, prove, verify } from '../src/schnorr.ts';

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

test('input validation', async () => {
  assert.equal((await post('/register/zk', { username: 'Bad Name!', publicKey: 'x' })).status, 400);
  assert.equal((await post('/register/zk', { username: 'carol', publicKey: 'not-a-point' })).status, 400);
  assert.equal((await fetch(base + '/nope')).status, 404);
});
