// ─── At-rest secret storage ──────────────────────────────────────────────────
//
// Keeps the long-lived identity key and the chat-history encryption key as
// NON-EXTRACTABLE CryptoKey objects in IndexedDB. A non-extractable key can be
// *used* (sign/derive/decrypt) by app code but its raw bytes can never be read
// back out — not by our own JS, and not by anything scraping the WebView's
// storage. That's a strict upgrade over the previous plaintext JWK in
// localStorage, which any file/XSS read could lift verbatim.
//
// (A WebCrypto fact we rely on: for an ECDH keypair the PUBLIC key is always
// exportable even when the private key was generated non-extractable.)

const DB_NAME = 'bunchat-secure';
const STORE = 'kv';

function b64(u: Uint8Array<ArrayBuffer>): string {
  let s = '';
  for (const b of u) s += String.fromCharCode(b);
  return btoa(s);
}
function unb64(s: string): Uint8Array<ArrayBuffer> {
  const bin = atob(s);
  const a = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i);
  return a;
}

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function idbGet<T>(key: string): Promise<T | undefined> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const r = db.transaction(STORE, 'readonly').objectStore(STORE).get(key);
    r.onsuccess = () => resolve(r.result as T | undefined);
    r.onerror = () => reject(r.error);
  });
}

async function idbSet(key: string, val: unknown): Promise<void> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).put(val, key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

// Identity ECDH keypair: non-extractable private, persisted across launches so a
// peer's safety number stays stable. Migrates a previous plaintext JWK once, then
// deletes it from localStorage.
export async function loadOrCreateIdentity(): Promise<{ priv: CryptoKey; pubRaw: Uint8Array }> {
  let pair = await idbGet<CryptoKeyPair>('identity');

  if (!pair) {
    const oldJwk = localStorage.getItem('p2p-identity-key');
    if (oldJwk) {
      try {
        const jwk = JSON.parse(oldJwk);
        const privateKey = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
        const publicKey = await crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, ext: true }, { name: 'ECDH', namedCurve: 'P-256' }, true, []);
        pair = { privateKey, publicKey };
        await idbSet('identity', pair);
        localStorage.removeItem('p2p-identity-key'); // drop the plaintext copy
      } catch { /* corrupt — fall through to a fresh key */ }
    }
  }

  if (!pair) {
    pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']) as CryptoKeyPair;
    await idbSet('identity', pair);
  }

  const pubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  return { priv: pair.privateKey, pubRaw };
}

// Non-extractable AES-GCM key used to encrypt chat history before it touches
// localStorage.
export async function loadOrCreateHistoryKey(): Promise<CryptoKey> {
  let key = await idbGet<CryptoKey>('historyKey');
  if (!key) {
    key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    await idbSet('historyKey', key);
  }
  return key;
}

export async function encryptHistory(key: CryptoKey, json: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(json)));
  return JSON.stringify({ iv: b64(iv), ct: b64(ct) });
}

export async function decryptHistory(key: CryptoKey, blob: string): Promise<string> {
  const { iv, ct } = JSON.parse(blob) as { iv: string; ct: string };
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(iv) }, key, unb64(ct));
  return new TextDecoder().decode(pt);
}
