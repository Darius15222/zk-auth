// Schnorr identification over ristretto255 (prime-order group), made non-interactive with Fiat-Shamir.
// The prover shows knowledge of x for P = x*G without revealing x.
import { ristretto255 } from '@noble/curves/ed25519.js';
import { createHash, randomBytes } from 'node:crypto';

const { Point } = ristretto255;
const n = Point.Fn.ORDER;

export type Proof = { R: string; s: string };

const toScalar = (b: Uint8Array): bigint => BigInt('0x' + Buffer.from(b).toString('hex')) % n;

// 512 random bits reduced mod n: bias is negligible (n is ~2^252)
export const randomScalar = (): bigint => toScalar(randomBytes(64)) || 1n;

// c = H(R | P | user | nonce): binding the server nonce makes every proof single-use (no replay)
export const challenge = (R: string, P: string, user: string, nonce: string): bigint =>
  toScalar(createHash('sha512').update([R, P, user, nonce].join('|')).digest());

export function keygen(): { secret: bigint; publicKey: string } {
  const secret = randomScalar();
  return { secret, publicKey: Point.BASE.multiply(secret).toHex() };
}

export function prove(x: bigint, user: string, nonce: string): Proof {
  const r = randomScalar();
  const R = Point.BASE.multiply(r).toHex();
  const P = Point.BASE.multiply(x).toHex();
  const s = (r + challenge(R, P, user, nonce) * x) % n;
  return { R, s: s.toString(16) };
}

// accepts iff s*G == R + c*P
export function verify(P: string, user: string, nonce: string, proof: Proof): boolean {
  try {
    const s = BigInt('0x' + proof.s);
    if (s <= 0n || s >= n) return false;
    const c = challenge(proof.R, P, user, nonce);
    return Point.BASE.multiply(s).equals(Point.fromHex(proof.R).add(Point.fromHex(P).multiply(c)));
  } catch {
    return false; // malformed point or scalar
  }
}

export const isPublicKey = (hex: string): boolean => {
  try {
    return !Point.fromHex(hex).is0();
  } catch {
    return false;
  }
};
