// Protocol-correctness test for the Sender Keys group scheme. Run:
//   node --experimental-strip-types test-senderkeys.mts
import {
  createSenderKey, distributionMessage, importDistribution,
  senderEncrypt, senderDecrypt,
  type SenderMessage,
} from './src/senderkeys.ts';

const enc = (s: string) => new TextEncoder().encode(s);
const dec = (u: Uint8Array) => new TextDecoder().decode(u);

let failures = 0;
function check(cond: boolean, msg: string) {
  if (cond) { console.log('  ✓', msg); } else { console.error('  ✗ FAIL:', msg); failures++; }
}

// A receiver who has imported the sender's distribution message.
async function receiverFor(sender: Awaited<ReturnType<typeof createSenderKey>>) {
  return importDistribution(distributionMessage(sender));
}

async function main() {
  console.log('Sender Keys protocol tests');

  // 1. One sender broadcasts to two receivers (the group case).
  {
    const alice = await createSenderKey();
    const bob   = await receiverFor(alice);
    const carol = await receiverFor(alice);
    const m = await senderEncrypt(alice, enc('hello group'));
    check(dec(await senderDecrypt(bob,   m)) === 'hello group', 'receiver B decrypts broadcast');
    check(dec(await senderDecrypt(carol, m)) === 'hello group', 'receiver C decrypts the same broadcast');
  }

  // 2. Many sequential messages all decrypt (chain ratchets in lock-step).
  {
    const alice = await createSenderKey();
    const bob   = await receiverFor(alice);
    let ok = true;
    for (let i = 0; i < 50; i++) {
      const m = await senderEncrypt(alice, enc('m' + i));
      if (dec(await senderDecrypt(bob, m)) !== 'm' + i) ok = false;
    }
    check(ok, '50 sequential broadcasts decrypt in order');
  }

  // 3. Forward secrecy: once a receiver advances past an iteration, that message
  //    key is gone — re-delivering an old message is unrecoverable.
  {
    const alice = await createSenderKey();
    const bob   = await receiverFor(alice);
    const m0 = await senderEncrypt(alice, enc('first'));
    const m1 = await senderEncrypt(alice, enc('second'));
    await senderDecrypt(bob, m0);
    await senderDecrypt(bob, m1);
    let threw = false;
    try { await senderDecrypt(bob, m0); } catch { threw = true; }
    check(threw, 'consumed (replayed) message key is rejected — forward secrecy');
  }

  // 4. Out-of-order delivery within the chain resolves via stashed keys.
  {
    const alice = await createSenderKey();
    const bob   = await receiverFor(alice);
    const msgs: SenderMessage[] = [];
    for (let i = 0; i < 6; i++) msgs.push(await senderEncrypt(alice, enc('seq' + i)));
    const order = [5, 1, 0, 4, 2, 3];
    let ok = true;
    for (const i of order) if (dec(await senderDecrypt(bob, msgs[i])) !== 'seq' + i) ok = false;
    check(ok, 'out-of-order delivery resolves via stashed keys');
  }

  // 5. Tamper detection: flipping the ciphertext breaks the signature.
  {
    const alice = await createSenderKey();
    const bob   = await receiverFor(alice);
    const m = await senderEncrypt(alice, enc('secret'));
    let threw = false;
    try { await senderDecrypt(bob, { ...m, ct: mutate(m.ct) }); } catch { threw = true; }
    check(threw, 'tampered ciphertext is rejected');
    check(dec(await senderDecrypt(bob, m)) === 'secret', 'inbound state intact after rejection (transactional)');
  }

  // 6. Forgery resistance: another member knows the chain key but cannot sign as
  //    the real sender. Mallory re-encrypts under Alice's chain yet signs with her
  //    own key; Bob (holding Alice's signPub) must reject it.
  {
    const alice = await createSenderKey();
    const dist  = distributionMessage(alice);
    const bob   = await importDistribution(dist);
    // Mallory bootstraps an outbound state from Alice's leaked chain key but her
    // own signing key — exactly what a malicious group member could attempt.
    const mallory = await createSenderKey();
    mallory.chainKey = (await importDistribution(dist)).chainKey;
    mallory.iteration = dist.iteration;
    const forged = await senderEncrypt(mallory, enc('I am alice'));
    let threw = false;
    try { await senderDecrypt(bob, forged); } catch { threw = true; }
    check(threw, 'message forged under a different signing key is rejected');
  }

  // 7. Membership rekey: after someone leaves, the sender mints a fresh chain.
  //    The departed member (old inbound state) can no longer read new messages;
  //    a re-bootstrapped member can.
  {
    const alice = await createSenderKey();
    const departed = await receiverFor(alice);          // had the old chain
    const m0 = await senderEncrypt(alice, enc('before leave'));
    check(dec(await senderDecrypt(departed, m0)) === 'before leave', 'old member reads pre-rotation message');

    const rekeyed = await createSenderKey();             // rotation on membership change
    const staying = await receiverFor(rekeyed);          // remaining member re-bootstraps
    const m1 = await senderEncrypt(rekeyed, enc('after leave'));
    check(dec(await senderDecrypt(staying, m1)) === 'after leave', 'remaining member reads post-rotation message');
    let threw = false;
    try { await senderDecrypt(departed, m1); } catch { threw = true; }
    check(threw, 'departed member cannot read post-rotation message');
  }

  console.log(failures === 0 ? '\nALL PASS' : `\n${failures} FAILURE(S)`);
  process.exit(failures === 0 ? 0 : 1);
}

function mutate(s: string): string {
  const bin = atob(s); const a = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i);
  a[0] ^= 0xff;
  let out = ''; for (const b of a) out += String.fromCharCode(b);
  return btoa(out);
}

main();
