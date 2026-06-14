// Protocol-correctness test for the Double Ratchet. Run:
//   node --experimental-strip-types test-ratchet.mts
import {
  deriveSK, initAlice, initBob, ratchetEncrypt, ratchetDecrypt, canSend,
  type RatchetSession, type RatchetMessage,
} from './src/ratchet.ts';

const subtle = globalThis.crypto.subtle;
const enc = (s: string) => new TextEncoder().encode(s);
const dec = (u: Uint8Array) => new TextDecoder().decode(u);

let failures = 0;
function check(cond: boolean, msg: string) {
  if (cond) { console.log('  ✓', msg); } else { console.error('  ✗ FAIL:', msg); failures++; }
}

async function genId() {
  return subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']) as Promise<CryptoKeyPair>;
}
async function rawPub(pair: CryptoKeyPair) {
  return new Uint8Array(await subtle.exportKey('raw', pair.publicKey));
}
async function idShared(myPriv: CryptoKey, theirPubRaw: Uint8Array) {
  const pub = await subtle.importKey('raw', theirPubRaw, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  return new Uint8Array(await subtle.deriveBits({ name: 'ECDH', public: pub }, myPriv, 256));
}

async function setup(): Promise<{ alice: RatchetSession; bob: RatchetSession }> {
  const aliceId = await genId();
  const bobId = await genId();
  const aliceIdPub = await rawPub(aliceId);
  const bobIdPub = await rawPub(bobId);

  // Bob's advertised prekey (Alice uses its public to seed the first chain).
  const bobPrekey = await genId();
  const bobPrekeyPub = await rawPub(bobPrekey);

  // Shared identity secret (same on both sides) -> SK.
  const sharedA = await idShared(aliceId.privateKey, bobIdPub);
  const sharedB = await idShared(bobId.privateKey, aliceIdPub);
  check(Buffer.from(sharedA).equals(Buffer.from(sharedB)), 'identity ECDH agrees on both sides');
  const SK = await deriveSK(sharedA);

  const alice = await initAlice(SK, bobPrekeyPub);
  const bob = await initBob(SK, bobPrekey, bobPrekeyPub);
  return { alice, bob };
}

async function main() {
  console.log('Double Ratchet protocol tests');

  // 1. Basic round-trip + reply (exercises the DH ratchet)
  {
    const { alice, bob } = await setup();
    check(canSend(alice) && !canSend(bob), 'initiator can send first, responder cannot yet');

    const m1 = await ratchetEncrypt(alice, enc('hello bob'));
    check(dec(await ratchetDecrypt(bob, m1)) === 'hello bob', 'bob decrypts alice msg #1');
    check(canSend(bob), 'bob can send after first receive');

    const m2 = await ratchetEncrypt(bob, enc('hi alice'));
    check(dec(await ratchetDecrypt(alice, m2)) === 'hi alice', 'alice decrypts bob reply (DH ratchet)');

    const m3 = await ratchetEncrypt(alice, enc('how are you'));
    check(dec(await ratchetDecrypt(bob, m3)) === 'how are you', 'bob decrypts alice msg after ratchet');
  }

  // 2. Many back-and-forth round-trips (healing / continuous ratcheting)
  {
    const { alice, bob } = await setup();
    let ok = true;
    for (let i = 0; i < 25; i++) {
      const a = await ratchetEncrypt(alice, enc('a' + i));
      if (dec(await ratchetDecrypt(bob, a)) !== 'a' + i) ok = false;
      const b = await ratchetEncrypt(bob, enc('b' + i));
      if (dec(await ratchetDecrypt(alice, b)) !== 'b' + i) ok = false;
    }
    check(ok, '25 ping-pong round-trips all decrypt correctly');
  }

  // 3. Out-of-order delivery within one chain (skipped message keys)
  {
    const { alice, bob } = await setup();
    const msgs: RatchetMessage[] = [];
    for (let i = 0; i < 5; i++) msgs.push(await ratchetEncrypt(alice, enc('seq' + i)));
    // Deliver 4, 0, 2, 1, 3 (out of order)
    const order = [4, 0, 2, 1, 3];
    let ok = true;
    for (const i of order) if (dec(await ratchetDecrypt(bob, msgs[i])) !== 'seq' + i) ok = false;
    check(ok, 'out-of-order delivery resolves via skipped keys');
  }

  // 4. Tamper detection (flipped ciphertext must not authenticate)
  {
    const { alice, bob } = await setup();
    const m = await ratchetEncrypt(alice, enc('secret'));
    const bad = unb64Mutate(m.ct);
    let threw = false;
    try { await ratchetDecrypt(bob, { ...m, ct: bad }); } catch { threw = true; }
    check(threw, 'tampered ciphertext is rejected');
    // ...and the session is untouched, so the real message still decrypts.
    check(dec(await ratchetDecrypt(bob, m)) === 'secret', 'session intact after a rejected message (transactional)');
  }

  // 5. Forward secrecy sanity: message keys differ per message.
  {
    const { alice, bob } = await setup();
    const a = await ratchetEncrypt(alice, enc('x'));
    const b = await ratchetEncrypt(alice, enc('x'));
    check(a.ct !== b.ct && a.iv !== b.iv, 'identical plaintexts produce different ciphertexts');
    await ratchetDecrypt(bob, a); await ratchetDecrypt(bob, b);
  }

  console.log(failures === 0 ? '\nALL PASS' : `\n${failures} FAILURE(S)`);
  process.exit(failures === 0 ? 0 : 1);
}

function unb64Mutate(s: string): string {
  const bin = atob(s); const a = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i);
  a[0] ^= 0xff; // flip a byte
  let out = ''; for (const b of a) out += String.fromCharCode(b);
  return btoa(out);
}

main();
