// ─── Sender Keys (group forward secrecy) ───────────────────────────────────────
//
// The Double Ratchet (ratchet.ts) only secures 1:1 conversations. For group
// rooms (3+) we use Signal's "Sender Keys" scheme so a single broadcast
// ciphertext can be read by every member while still giving forward secrecy.
//
// Each member owns an outbound *sender key*:
//   chainKey:  32 random bytes that ratchet forward (HMAC) once per message.
//   signKey:   an ECDSA-P256 keypair used to sign every message.
//
// A member distributes (chainKey, iteration, signPub) — a SenderKeyDistribution —
// to every other member ONCE, over the existing pairwise secure channel
// (Double Ratchet / ECIES). Thereafter group messages are encrypted with a
// message key derived from the sender's current chainKey and broadcast to all;
// each receiver advances its own copy of that sender's chain to decrypt.
//
//   Forward secrecy: the chainKey is HMAC-ratcheted and the old value discarded
//   after every message, so a stolen chainKey cannot derive past message keys.
//   A member who joins late receives the *current* chainKey and so cannot read
//   anything sent before they joined.
//
//   Authenticity: every member legitimately knows the shared chainKey, so the
//   chainKey alone cannot prove who sent a message — any member could forge one.
//   The per-sender ECDSA signature closes that: only the real sender holds the
//   private signing key, so receivers reject messages whose signature doesn't
//   verify against the signPub they were given at distribution time.
//
// Membership changes are an integration concern, not handled here: when someone
// LEAVES, the remaining members must each call createSenderKey() to mint a fresh
// chain and redistribute it, so the departed member's copy goes stale. (Joins
// need no rotation — a new member simply can't read history.)
//
// IMPORTANT: like ratchet.ts this is hand-rolled, unit-tested (test-senderkeys.mts)
// cryptography that has NOT had a professional audit. Treat it as defence in depth.

const subtle = globalThis.crypto.subtle;
type Bytes = Uint8Array<ArrayBuffer>;
const INFO = new TextEncoder().encode('BunChat-SenderKey-v1') as Bytes;
const MAX_SKIP = 2000; // refuse to derive more than this many skipped keys at once
const SIG_ALGO = { name: 'ECDSA', namedCurve: 'P-256' } as const;

function b64(u: Bytes): string {
  let s = '';
  for (const b of u) s += String.fromCharCode(b);
  return btoa(s);
}
function unb64(s: string): Bytes {
  const bin = atob(s);
  const a = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i);
  return a;
}

// ── wire types ────────────────────────────────────────────────────────────────

// Sent over the pairwise secure channel to bootstrap a receiver's inbound state.
export interface SenderKeyDistribution { chainKey: string; iteration: number; signPub: string }

// Broadcast to the whole group for every chat message.
export interface SenderMessage { iteration: number; iv: string; ct: string; sig: string }

// ── state ───────────────────────────────────────────────────────────────────

export interface OutboundSenderState {
  chainKey:   Bytes;
  iteration:  number;
  signPriv:   CryptoKey;
  signPubRaw: Bytes;
}

export interface InboundSenderState {
  chainKey:  Bytes;
  iteration: number;
  signPub:   CryptoKey;
  skipped:   Map<number, Bytes>; // iteration -> message key, for out-of-order delivery
}

// ── primitives ──────────────────────────────────────────────────────────────

async function hmac(key: Bytes, data: Bytes): Promise<Bytes> {
  const k = await subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await subtle.sign('HMAC', k, data));
}

// Symmetric ratchet: split the chain key into a message key and the next chain
// key. Identical construction to the Double Ratchet's chain KDF.
async function kdfCK(ck: Bytes): Promise<[Bytes, Bytes]> {
  const mk  = await hmac(ck, new Uint8Array([0x01]));
  const nck = await hmac(ck, new Uint8Array([0x02]));
  return [nck, mk]; // [next chain key, message key]
}

async function hkdf(ikm: Bytes, len: number): Promise<Bytes> {
  const key = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: INFO }, key, len * 8,
  ));
}

async function mkAesKey(mk: Bytes): Promise<CryptoKey> {
  const raw = await hkdf(mk, 32);
  return subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

// 4-byte big-endian iteration counter, bound into both the AEAD additional data
// and the signed bytes so a message can't be silently replayed at a different
// position in the chain.
function iterBytes(i: number): Bytes {
  const b = new Uint8Array(4);
  b[0] = (i >>> 24) & 0xff; b[1] = (i >>> 16) & 0xff; b[2] = (i >>> 8) & 0xff; b[3] = i & 0xff;
  return b;
}

// Bytes the ECDSA signature covers: iteration ‖ iv ‖ ciphertext(+GCM tag).
function signedBytes(iteration: number, iv: Bytes, ct: Bytes): Bytes {
  const it = iterBytes(iteration);
  const out = new Uint8Array(it.length + iv.length + ct.length) as Bytes;
  out.set(it, 0); out.set(iv, it.length); out.set(ct, it.length + iv.length);
  return out;
}

// ── setup ───────────────────────────────────────────────────────────────────

// Mint a fresh outbound sender key. Call once on joining a group, and again
// (with redistribution) whenever a member leaves.
export async function createSenderKey(): Promise<OutboundSenderState> {
  const chainKey = crypto.getRandomValues(new Uint8Array(32)) as Bytes;
  const pair = await subtle.generateKey(SIG_ALGO, false, ['sign', 'verify']) as CryptoKeyPair;
  const signPubRaw = new Uint8Array(await subtle.exportKey('raw', pair.publicKey)) as Bytes;
  return { chainKey, iteration: 0, signPriv: pair.privateKey, signPubRaw };
}

// The message a sender hands each peer (over the pairwise channel) so they can
// build inbound state. Reflects the CURRENT chain position, so a peer who
// receives it late only gains the ability to read from here forward.
export function distributionMessage(s: OutboundSenderState): SenderKeyDistribution {
  return { chainKey: b64(s.chainKey), iteration: s.iteration, signPub: b64(s.signPubRaw) };
}

export async function importDistribution(d: SenderKeyDistribution): Promise<InboundSenderState> {
  const signPub = await subtle.importKey('raw', unb64(d.signPub), SIG_ALGO, false, ['verify']);
  return { chainKey: unb64(d.chainKey), iteration: d.iteration, signPub, skipped: new Map() };
}

// ── encrypt / decrypt ─────────────────────────────────────────────────────────

export async function senderEncrypt(s: OutboundSenderState, plaintext: BufferSource): Promise<SenderMessage> {
  const [nck, mk] = await kdfCK(s.chainKey);
  const iteration = s.iteration;
  const aesKey = await mkAesKey(mk);
  const iv = crypto.getRandomValues(new Uint8Array(12)) as Bytes;
  const ct = new Uint8Array(await subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: iterBytes(iteration) }, aesKey, plaintext,
  )) as Bytes;
  const sig = new Uint8Array(await subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' }, s.signPriv, signedBytes(iteration, iv, ct),
  )) as Bytes;
  // Ratchet forward and discard the spent chain key (forward secrecy).
  s.chainKey = nck;
  s.iteration += 1;
  return { iteration, iv: b64(iv), ct: b64(ct), sig: b64(sig) };
}

// Decrypt is transactional: chain state only advances if the message both
// authenticates (signature) and decrypts (GCM tag). A forged or corrupt message
// leaves the inbound state untouched.
export async function senderDecrypt(s: InboundSenderState, msg: SenderMessage): Promise<Bytes> {
  const iv = unb64(msg.iv), ct = unb64(msg.ct);

  // 1. Authenticity: reject anything not signed by this sender's key. Done first
  //    so a forgery never even touches the chain.
  const sigOk = await subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' }, s.signPub, unb64(msg.sig), signedBytes(msg.iteration, iv, ct),
  );
  if (!sigOk) throw new Error('senderkey: bad signature');

  const w = cloneInbound(s);

  // 2. Out-of-order message whose key we already derived and stashed?
  const stashed = w.skipped.get(msg.iteration);
  if (stashed) {
    const pt = await aeadDecrypt(stashed, msg.iteration, iv, ct);
    w.skipped.delete(msg.iteration);
    commit(s, w);
    return pt;
  }

  // 3. An iteration we've already advanced past — its key is gone (forward
  //    secrecy), so it's unrecoverable. Replays land here too.
  if (msg.iteration < w.iteration) throw new Error('senderkey: message key already consumed');

  // 4. Skip forward to the target iteration, stashing intervening keys so the
  //    skipped messages can still arrive out of order.
  if (msg.iteration - w.iteration > MAX_SKIP) throw new Error('senderkey: too many skipped messages');
  while (w.iteration < msg.iteration) {
    const [nck, mk] = await kdfCK(w.chainKey);
    w.skipped.set(w.iteration, mk);
    w.chainKey = nck;
    w.iteration += 1;
  }

  const [nck, mk] = await kdfCK(w.chainKey);
  const pt = await aeadDecrypt(mk, msg.iteration, iv, ct); // throws -> w discarded
  w.chainKey = nck;
  w.iteration += 1;
  commit(s, w);
  return pt;
}

async function aeadDecrypt(mk: Bytes, iteration: number, iv: Bytes, ct: Bytes): Promise<Bytes> {
  const aesKey = await mkAesKey(mk);
  const pt = await subtle.decrypt({ name: 'AES-GCM', iv, additionalData: iterBytes(iteration) }, aesKey, ct);
  return new Uint8Array(pt) as Bytes;
}

function cloneInbound(s: InboundSenderState): InboundSenderState {
  return { chainKey: s.chainKey, iteration: s.iteration, signPub: s.signPub, skipped: new Map(s.skipped) };
}

function commit(s: InboundSenderState, w: InboundSenderState): void {
  s.chainKey = w.chainKey; s.iteration = w.iteration; s.skipped = w.skipped;
}
