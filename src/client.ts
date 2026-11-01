// Demo client. Usage:
//   node src/client.ts keygen
//   node src/client.ts register <url> <user> <publicKey>
//   node src/client.ts login <url> <user> <secretHex>
import { keygen, prove } from './schnorr.ts';

const post = async (url: string, body: object) => {
  const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  return { status: r.status, body: await r.json() };
};

const [cmd, url, user, arg] = process.argv.slice(2);

if (cmd === 'keygen') {
  const { secret, publicKey } = keygen();
  console.log(JSON.stringify({ secret: secret.toString(16), publicKey }));
} else if (cmd === 'register') {
  console.log(await post(`${url}/register/zk`, { username: user, publicKey: arg }));
} else if (cmd === 'login') {
  const { body } = await post(`${url}/challenge`, { username: user });
  const proof = prove(BigInt('0x' + arg), user, body.nonce);
  console.log(await post(`${url}/login/zk`, { username: user, nonce: body.nonce, ...proof }));
} else {
  console.error('usage: keygen | register <url> <user> <publicKey> | login <url> <user> <secretHex>');
  process.exit(1);
}
