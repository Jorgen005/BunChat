// ─── Double Ratchet ────────────────────────────────────────────────────────────
//
// A pairwise Signal-style Double Ratchet built on WebCrypto:
//   DH:   ECDH P-256
//   KDFs: HKDF-SHA256 (root) + HMAC-SHA256 (chain)
//   AEAD: AES-256-GCM
//
// It gives a 1:1 conversation forward secrecy (a stolen key can't decrypt past
// messages, because each message key is derived from a chain that's immediately
// ratcheted forward and discarded) and post-compromise security / "healing" (a
// compromise stops being useful once both sides exchange again, because every
// round-trip mixes fresh DH entropy into the root key).
//
// Scope: used for single-peer conversations (DMs / 2-person rooms). Group rooms
// keep per-message ephemeral ECIES; full group ratcheting needs Sender Keys,
// which is a separate scheme.
//
// IMPORTANT: this is hand-rolled cryptography. It is unit-tested for protocol
// correctness (see test-ratchet.mts) but has NOT had a professional audit. Treat
// it as defence-in-depth on top of the transport, not as a life-safety guarantee.

const subtle = globalThis.crypto.subtle;
// WebCrypto wants byte buffers backed by a concrete ArrayBuffer; the project's TS
// lib distinguishes that from the default Uint8Array<ArrayBufferLike>.
type Bytes = Uint8Array<ArrayBuffer>;
const INFO = new TextEncoder().encode('BunChat-Ratchet-v1') as Bytes;
const MAX_SKIP = 1000; // refuse to derive more than this many skipped keys at once

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

export interface RatchetMessage { dh: string; pn: number; n: number; iv: string; ct: string }

export interface RatchetSession {
  DHs:    CryptoKeyPair;   // our current ratchet keypair
  DHsPub: Bytes;           // cached raw public of DHs
  DHrPub: Bytes | null;    // their current ratchet public
  RK:     Bytes;           // root key
  CKs:    Bytes | null;    // sending chain key
  CKr:    Bytes | null;    // receiving chain key
  Ns: number; Nr: number; PN: number;
  skipped: Map<string, Bytes>; // "<dhPubB64>:<n>" -> message key
}

// ── primitives ──────────────────────────────────────────────────────────────

async function genDH(): Promise<{ pair: CryptoKeyPair; pub: Bytes }> {
  const pair = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']) as CryptoKeyPair;
  const pub = new Uint8Array(await subtle.exportKey('raw', pair.publicKey));
  return { pair, pub };
}

async function dh(priv: CryptoKey, pubRaw: Bytes): Promise<Bytes> {
  const pub = await subtle.importKey('raw', pubRaw, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  return new Uint8Array(await subtle.deriveBits({ name: 'ECDH', public: pub }, priv, 256));
}

async function hkdf(ikm: Bytes, salt: Bytes, len: number): Promise<Bytes> {
  const key = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: INFO }, key, len * 8));
}

async function kdfRK(rk: Bytes, dhOut: Bytes): Promise<[Bytes, Bytes]> {
  const out = await hkdf(dhOut, rk, 64);
  return [out.slice(0, 32), out.slice(32, 64)];
}

async function hmac(key: Bytes, data: Bytes): Promise<Bytes> {
  const k = await subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await subtle.sign('HMAC', k, data));
}

async function kdfCK(ck: Bytes): Promise<[Bytes, Bytes]> {
  const mk  = await hmac(ck, new Uint8Array([0x01]));
  const nck = await hmac(ck, new Uint8Array([0x02]));
  return [nck, mk]; // [next chain key, message key]
}

async function mkAesKey(mk: Bytes): Promise<CryptoKey> {
  const raw = await hkdf(mk, new Uint8Array(32), 32);
  return subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

function adBytes(dh: string, pn: number, n: number): Bytes {
  return new TextEncoder().encode(JSON.stringify({ dh, pn, n })) as Bytes;
}

async function aeadDecrypt(mk: Bytes, msg: RatchetMessage): Promise<Bytes> {
  const aesKey = await mkAesKey(mk);
  const pt = await subtle.decrypt(
    { name: 'AES-GCM', iv: unb64(msg.iv), additionalData: adBytes(msg.dh, msg.pn, msg.n) },
    aesKey, unb64(msg.ct),
  );
  return new Uint8Array(pt);
}

// ── session setup ─────────────────────────────────────────────────────────────

// Initial shared secret from the two identities' ECDH output. Static-static, so
// the very first root key isn't forward-secret on its own; the first round-trip
// heals that. (A full X3DH with one-time prekeys would close this gap.)
export async function deriveSK(identityShared: Bytes): Promise<Bytes> {
  return hkdf(identityShared, new Uint8Array(32), 32);
}

// Initiator: the side with the lexicographically smaller identity key.
export async function initAlice(SK: Bytes, bobPrekeyPub: Bytes): Promise<RatchetSession> {
  const { pair, pub } = await genDH();
  const [rk, cks] = await kdfRK(SK, await dh(pair.privateKey, bobPrekeyPub));
  return { DHs: pair, DHsPub: pub, DHrPub: bobPrekeyPub, RK: rk, CKs: cks, CKr: null, Ns: 0, Nr: 0, PN: 0, skipped: new Map() };
}

// Responder: starts with the prekey it advertised; can't send until it receives
// the initiator's first message (which performs its first DH ratchet).
export async function initBob(SK: Bytes, myPrekey: CryptoKeyPair, myPrekeyPub: Bytes): Promise<RatchetSession> {
  return { DHs: myPrekey, DHsPub: myPrekeyPub, DHrPub: null, RK: SK, CKs: null, CKr: null, Ns: 0, Nr: 0, PN: 0, skipped: new Map() };
}

export function canSend(s: RatchetSession): boolean { return s.CKs !== null; }

// ── encrypt / decrypt ─────────────────────────────────────────────────────────

export async function ratchetEncrypt(s: RatchetSession, plaintext: BufferSource): Promise<RatchetMessage> {
  if (!s.CKs) throw new Error('ratchet: sending chain not ready');
  const [nck, mk] = await kdfCK(s.CKs);
  const dhPub = b64(s.DHsPub), pn = s.PN, n = s.Ns;
  s.CKs = nck;
  s.Ns += 1;
  const aesKey = await mkAesKey(mk);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: adBytes(dhPub, pn, n) }, aesKey, plaintext,
  ));
  return { dh: dhPub, pn, n, iv: b64(iv), ct: b64(ct) };
}

// Decrypt is transactional: all state changes happen on a working copy and are
// only committed if the message authenticates. So a message we can't decrypt
// (corruption, replay, or one not meant for this session) leaves state untouched.
export async function ratchetDecrypt(s: RatchetSession, msg: RatchetMessage): Promise<Bytes> {
  const w = cloneSession(s);

  // 1. Already-skipped (out-of-order) message key?
  const skKey = msg.dh + ':' + msg.n;
  const stored = w.skipped.get(skKey);
  if (stored) {
    const pt = await aeadDecrypt(stored, msg); // throws if it doesn't authenticate
    w.skipped.delete(skKey);
    commit(s, w);
    return pt;
  }

  // 2. New ratchet public key from the peer -> DH ratchet step.
  if (!w.DHrPub || b64(w.DHrPub) !== msg.dh) {
    await skipMessageKeys(w, msg.pn);
    await dhRatchet(w, unb64(msg.dh));
  }

  // 3. Skip forward within the current receiving chain to this message number.
  await skipMessageKeys(w, msg.n);

  if (!w.CKr) throw new Error('ratchet: no receiving chain');
  const [nck, mk] = await kdfCK(w.CKr);
  const pt = await aeadDecrypt(mk, msg); // throws -> w discarded, s untouched
  w.CKr = nck;
  w.Nr += 1;
  commit(s, w);
  return pt;
}

async function skipMessageKeys(w: RatchetSession, until: number): Promise<void> {
  if (w.CKr === null) return;
  if (until - w.Nr > MAX_SKIP) throw new Error('ratchet: too many skipped messages');
  while (w.Nr < until) {
    const [nck, mk] = await kdfCK(w.CKr);
    w.skipped.set(b64(w.DHrPub!) + ':' + w.Nr, mk);
    w.CKr = nck;
    w.Nr += 1;
  }
}

async function dhRatchet(w: RatchetSession, theirDh: Bytes): Promise<void> {
  w.PN = w.Ns; w.Ns = 0; w.Nr = 0;
  w.DHrPub = theirDh;
  const [rk, ckr] = await kdfRK(w.RK, await dh(w.DHs.privateKey, w.DHrPub));
  w.RK = rk; w.CKr = ckr;
  const { pair, pub } = await genDH();
  w.DHs = pair; w.DHsPub = pub;
  const [rk2, cks] = await kdfRK(w.RK, await dh(w.DHs.privateKey, w.DHrPub));
  w.RK = rk2; w.CKs = cks;
}

function cloneSession(s: RatchetSession): RatchetSession {
  return {
    DHs: s.DHs, DHsPub: s.DHsPub, DHrPub: s.DHrPub, RK: s.RK,
    CKs: s.CKs, CKr: s.CKr, Ns: s.Ns, Nr: s.Nr, PN: s.PN,
    skipped: new Map(s.skipped),
  };
}

function commit(s: RatchetSession, w: RatchetSession): void {
  s.DHs = w.DHs; s.DHsPub = w.DHsPub; s.DHrPub = w.DHrPub; s.RK = w.RK;
  s.CKs = w.CKs; s.CKr = w.CKr; s.Ns = w.Ns; s.Nr = w.Nr; s.PN = w.PN;
  s.skipped = w.skipped;
}
