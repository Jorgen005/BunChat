import React, { useState, useEffect, useRef, useCallback, type CSSProperties, type SVGProps } from 'react';
import { joinRoom } from 'trystero';
import { invoke } from '@tauri-apps/api/core';
import { isPermissionGranted, requestPermission, sendNotification } from '@tauri-apps/plugin-notification';
import { getCurrentWindow } from '@tauri-apps/api/window';
import {
  initAlice, initBob, deriveSK, ratchetEncrypt, ratchetDecrypt, canSend,
  type RatchetSession, type RatchetMessage,
} from './ratchet';
import {
  createSenderKey, distributionMessage, importDistribution, senderEncrypt, senderDecrypt,
  type SenderMessage, type SenderKeyDistribution, type OutboundSenderState, type InboundSenderState,
} from './senderkeys';
import {
  loadOrCreateIdentity, loadOrCreateHistoryKey, encryptHistory, decryptHistory,
} from './secureStore';

const APP_ID             = 'norway-friends-p2p-v1';
const DEFAULT_ROOM_ID    = 'southern-norway-20';
const DEFAULT_ROOM_LABEL = 'Global-1';
const MSG_PAD_TARGET     = 1024; // all encrypted payloads are padded to this many chars
const MAX_HISTORY        = 200;  // messages kept per room when saving chat

const RTC_CONFIG = {
  iceServers: [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun1.l.google.com:19302' },
    { urls: 'stun:stun.cloudflare.com:3478' },
  ],
};

// ─── Interfaces ───────────────────────────────────────────────────────────────

interface PeerKeyMessage     { publicKeyBase64: string; ratchetPrekeyBase64?: string }

interface EncryptedLayer {
  ephemeralPub: string;
  iv:           string;
  ciphertext:   string;
}

interface PlainInstruction {
  nextHop: string;
  payload: string;
}

interface OnionForwardPacket  { circuitId: string; layer: EncryptedLayer }
interface OnionResponsePacket { circuitId: string; data: string; isError: boolean }

interface SearchResult  { title: string; url: string; snippet: string; href: string }
// `synced` marks a message imported from a peer's history rather than received
// live. Such messages are author-spoofable (old messages aren't signed), so they
// are rendered as unverified instead of being trusted like live traffic.
interface Message       { id: string; from: string; text: string; ts: number; synced?: boolean }
interface RelayPeerInfo { pubKey: string; rooms: Array<{ roomId: string; peerId: string; rt: RoomRuntime }> }

interface RoomDef { id: string; label: string; isDM?: boolean; dmFriend?: string }

// Envelope sent over the wire for all non-relay, non-key messages. One of:
//   rk  — a Double Ratchet message (1:1 conversations)
//   sk  — a Sender Keys message (group chat: one ciphertext for the whole room)
//   enc — an ECIES layer (presence, mixer batches, and the warm-up window before
//         a ratchet/sender-key session is ready)
type EncMsgPacket = { enc: EncryptedLayer } | { rk: RatchetMessage } | { sk: SenderMessage }

type EncMsgPayload =
  | { type: 'chat';        id: string; username: string; text: string }
  | { type: 'username';    username: string }
  | { type: 'voiceStatus'; username: string; inVoice: boolean }
  | { type: 'relayAvail';  isRelay: boolean; isExit: boolean }
  | { type: 'dmInvite';    fromUsername: string; roomId: string }
  | { type: 'relayBatch';  blobs: EncryptedLayer[] }
  | { type: 'senderKey';   dist: SenderKeyDistribution }
  | { type: 'chatHistory'; messages: Array<{ id: string; from: string; text: string; ts: number }> };

interface RoomReactState {
  peers:           string[];
  displayNames:    Record<string, string>;
  messages:        Message[];
  inVoiceUsers:    string[];
  availableRelays: string[];
  availableExits:  string[];
  fingerprints:    Record<string, string>; // peerId -> safety-number fingerprint of their key
  isInVoice:       boolean;
}

interface RoomRuntime {
  trysteroRoom:    any;
  sendEncMsg:      ((d: EncMsgPacket,        t?: string | string[]) => void) | null;
  sendPeerKey:     ((d: PeerKeyMessage,      t?: string | string[]) => void) | null;
  sendRelayFwd:    ((d: OnionForwardPacket,  t?: string | string[]) => void) | null;
  sendRelayResp:   ((d: OnionResponsePacket, t?: string | string[]) => void) | null;
  peerPublicKeys:  Record<string, string>;
  ratchetSessions: Record<string, RatchetSession>; // peerId -> 1:1 Double Ratchet session
  outboundSenderKey: OutboundSenderState | null;     // our group sender key for this room
  inboundSenderKeys: Record<string, InboundSenderState>; // sender pubKeyB64 -> their group chain
  peerUsername:    Record<string, string>;
  usernamePeer:    Record<string, string>;
  remoteAudios:    Record<string, HTMLAudioElement>;
  remoteAnalysers: Record<string, AnalyserNode>;
  selfStream:       MediaStream | null;
  selfAnalyser:     AnalyserNode | null;
  isInVoice:        boolean;
  announceInterval: ReturnType<typeof setInterval> | null;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function formatTime(ts: number): string {
  const d = new Date(ts);
  return d.getHours().toString().padStart(2, '0') + ':' + d.getMinutes().toString().padStart(2, '0');
}

// Cryptographically-secure integer in [0, max) — unbiased via rejection sampling.
// Used everywhere a random choice has security/anonymity weight (relay/circuit
// selection, room codes) so the result can't be predicted from a weak PRNG.
function secureRandInt(max: number): number {
  if (max <= 0) return 0;
  const limit = Math.floor(0x100000000 / max) * max;
  const buf = new Uint32Array(1);
  let x = 0;
  do { crypto.getRandomValues(buf); x = buf[0]; } while (x >= limit);
  return x % max;
}

// Fisher–Yates shuffle using the CSPRNG. Math.random()-based `sort` shuffles are
// both predictable and statistically biased, which weakens circuit diversity.
function secureShuffle<T>(arr: T[]): T[] {
  const a = arr.slice();
  for (let i = a.length - 1; i > 0; i--) {
    const j = secureRandInt(i + 1);
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

function uint8ToBase64(arr: Uint8Array): string {
  let s = '';
  for (const b of arr) s += String.fromCharCode(b);
  return btoa(s);
}

function base64ToUint8(b64: string): Uint8Array<ArrayBuffer> {
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}

// Renders 12 bytes of a hash as a Signal-style grouped numeric "safety number"
// that two people can read aloud to confirm they hold each other's real key
// (i.e. that no one is sitting in the middle relaying a swapped key).
function formatDigits(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < 6; i++) {
    const n = ((bytes[i * 2] << 8) | bytes[i * 2 + 1]) % 100000;
    s += n.toString().padStart(5, '0') + (i < 5 ? ' ' : '');
  }
  return s;
}

// Fingerprint of a single public key — shown next to a peer so that two peers
// claiming the same username are still distinguishable by their key.
async function keyFingerprint(pubKeyBase64: string): Promise<string> {
  const d = await crypto.subtle.digest('SHA-256', base64ToUint8(pubKeyBase64));
  return formatDigits(new Uint8Array(d));
}

// Combined safety number for a pair — deterministic no matter which side computes
// it, so both people see the identical number when verifying a DM.
async function safetyNumber(keyA: string, keyB: string): Promise<string> {
  const [x, y] = [keyA, keyB].sort();
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(x + y));
  return formatDigits(new Uint8Array(d));
}

async function encryptForPeer(plaintext: string, peerPublicKeyBase64: string): Promise<EncryptedLayer> {
  const peerPubKey = await crypto.subtle.importKey(
    'raw', base64ToUint8(peerPublicKeyBase64),
    { name: 'ECDH', namedCurve: 'P-256' }, false, []
  );
  const ephemeral = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']
  );
  const sharedBits = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: peerPubKey }, ephemeral.privateKey, 256
  );
  const aesKey = await crypto.subtle.importKey('raw', sharedBits, { name: 'AES-GCM' }, false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv }, aesKey, new TextEncoder().encode(plaintext)
  );
  const ephPubRaw = await crypto.subtle.exportKey('raw', ephemeral.publicKey);
  return {
    ephemeralPub: uint8ToBase64(new Uint8Array(ephPubRaw)),
    iv:           uint8ToBase64(iv),
    ciphertext:   uint8ToBase64(new Uint8Array(ciphertext)),
  };
}

async function decryptLayer(layer: EncryptedLayer, privateKey: CryptoKey): Promise<string> {
  const ephPubKey = await crypto.subtle.importKey(
    'raw', base64ToUint8(layer.ephemeralPub),
    { name: 'ECDH', namedCurve: 'P-256' }, false, []
  );
  const sharedBits = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: ephPubKey }, privateKey, 256
  );
  const aesKey = await crypto.subtle.importKey('raw', sharedBits, { name: 'AES-GCM' }, false, ['decrypt']);
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: base64ToUint8(layer.iv) },
    aesKey,
    base64ToUint8(layer.ciphertext)
  );
  return new TextDecoder().decode(plaintext);
}

async function buildOnionPacket(
  url: string,
  circuit: [string, string, string],
  peerKeys: Record<string, string>
): Promise<{ circuitId: string; layer: EncryptedLayer }> {
  const circuitId = crypto.randomUUID();
  const l3: PlainInstruction = { nextHop: 'exit', payload: url };
  const enc3 = await encryptForPeer(JSON.stringify(l3), peerKeys[circuit[2]]);
  const l2: PlainInstruction = { nextHop: circuit[2], payload: btoa(JSON.stringify(enc3)) };
  const enc2 = await encryptForPeer(JSON.stringify(l2), peerKeys[circuit[1]]);
  const l1: PlainInstruction = { nextHop: circuit[1], payload: btoa(JSON.stringify(enc2)) };
  const enc1 = await encryptForPeer(JSON.stringify(l1), peerKeys[circuit[0]]);
  return { circuitId, layer: enc1 };
}

// Pads a JSON string to MSG_PAD_TARGET chars by injecting a random `_p` field.
// The receiver ignores `_p`; all messages on the wire become the same size.
function addPadding(json: string): string {
  // Overhead of appending `,"_p":"<pad>"}` while replacing the closing `}`:
  // we remove 1 char (`}`) and add (8 + padLen) chars (`,"_p":"` + pad + `"}`).
  const padLen = MSG_PAD_TARGET - json.length - 8;
  if (padLen <= 0) return json;
  const randBytes = crypto.getRandomValues(new Uint8Array(Math.ceil(padLen * 0.75) + 1));
  const pad = uint8ToBase64(randBytes).slice(0, padLen);
  return json.slice(0, -1) + `,"_p":"${pad}"}`;
}

async function encryptMsg(payload: EncMsgPayload, pubKey: string): Promise<EncMsgPacket> {
  const enc = await encryptForPeer(addPadding(JSON.stringify(payload)), pubKey);
  return { enc };
}

// Packs a payload for one peer: a Double Ratchet message if a session exists and
// is ready to send (1:1 conversation), otherwise an ECIES layer. Returns null if
// we don't even have the peer's key yet.
async function packForPeer(rt: RoomRuntime, peerId: string, payload: EncMsgPayload): Promise<EncMsgPacket | null> {
  const padded = addPadding(JSON.stringify(payload));
  const session = rt.ratchetSessions[peerId];
  if (session && canSend(session)) {
    return { rk: await ratchetEncrypt(session, new TextEncoder().encode(padded)) };
  }
  const pubKey = rt.peerPublicKeys[peerId];
  if (!pubKey) return null;
  return { enc: await encryptForPeer(padded, pubKey) };
}

async function sendToPeer(rt: RoomRuntime, peerId: string, payload: EncMsgPayload): Promise<void> {
  const pkt = await packForPeer(rt, peerId, payload);
  if (pkt) rt.sendEncMsg?.(pkt, peerId);
}

// Sends `payload` to every peer in `rt`, routing through a random mixer when
// there are 2+ peers so that a network observer only sees traffic from us to
// one peer, not to all of them directly.
async function sendEncryptedToAll(rt: RoomRuntime, payload: EncMsgPayload): Promise<void> {
  const entries = Object.entries(rt.peerPublicKeys);
  if (entries.length === 0) return;

  if (entries.length === 1) {
    // Single peer (DM / 2-person room) — ratchet if the session is ready.
    await sendToPeer(rt, entries[0][0], payload);
    return;
  }

  // Group (2+ peers): chat is encrypted ONCE under our Sender Key and broadcast —
  // every member decrypts the same ciphertext with their own copy of our chain,
  // and each message key is ratcheted away for forward secrecy. (Other payload
  // types fall through to the per-recipient ECIES mixer path below. NOTE: unlike
  // that path, this broadcasts directly rather than via the one-hop mixer —
  // routing the single sender-key ciphertext through a mixer is a follow-up.)
  if (payload.type === 'chat' && rt.outboundSenderKey) {
    const sm = await senderEncrypt(rt.outboundSenderKey, new TextEncoder().encode(addPadding(JSON.stringify(payload))));
    for (const peerId of Object.keys(rt.peerPublicKeys)) rt.sendEncMsg?.({ sk: sm }, peerId);
    return;
  }

  // Pick a random peer as the one-hop mixer.
  const mixerIdx                   = secureRandInt(entries.length);
  const [mixerPeerId, mixerPubKey] = entries[mixerIdx];
  const others                     = entries.filter((_, i) => i !== mixerIdx);

  // Encrypt the payload individually for every non-mixer peer — no peerId labels
  // so the mixer cannot learn who each blob is intended for.
  const blobs = await Promise.all(
    others.map(([, pubKey]) => encryptForPeer(addPadding(JSON.stringify(payload)), pubKey))
  );

  // Also include the mixer's own copy in the blob list so the mixer decrypts it
  // like any other recipient rather than getting a separately-labelled packet.
  blobs.push(await encryptForPeer(addPadding(JSON.stringify(payload)), mixerPubKey));

  const batchEnc = await encryptForPeer(
    addPadding(JSON.stringify({ type: 'relayBatch' as const, blobs })),
    mixerPubKey
  );
  rt.sendEncMsg?.({ enc: batchEnc }, mixerPeerId);
}

// Sends `payload` directly to every peer without mixing — used for presence
// messages where peerId attribution must be the true sender, not a forwarder.
// Ratchets per peer where a session is ready; ECIES otherwise.
async function sendDirectToAll(rt: RoomRuntime, payload: EncMsgPayload): Promise<void> {
  await Promise.all(
    Object.keys(rt.peerPublicKeys).map(peerId => sendToPeer(rt, peerId, payload))
  );
}

function parseSearchResults(html: string): SearchResult[] {
  const doc = new DOMParser().parseFromString(html, 'text/html');
  const out: SearchResult[] = [];

  console.log('[search] HTML length:', html.length, '| first 500:', html.slice(0, 500));

  doc.querySelectorAll('a.result-link').forEach(a => {
    const title = a.textContent?.trim() ?? '';
    if (!title) return;
    const href       = a.getAttribute('href') ?? '';
    const row        = a.closest('tr');
    const snippetRow = row?.nextElementSibling;
    const urlRow     = snippetRow?.nextElementSibling;
    const snippet    = snippetRow?.querySelector('.result-snippet')?.textContent?.trim()
                    ?? snippetRow?.textContent?.trim() ?? '';
    const url        = urlRow?.querySelector('.result-url')?.textContent?.trim()
                    ?? urlRow?.textContent?.trim() ?? '';
    out.push({ title, url: url || href, snippet, href });
  });

  if (out.length > 0) { console.log('[search] result-link found:', out.length); return out.slice(0, 10); }

  doc.querySelectorAll('.result-title a').forEach(a => {
    const title = a.textContent?.trim() ?? '';
    if (!title) return;
    const href       = a.getAttribute('href') ?? '';
    const titleRow   = a.closest('tr');
    const snippetRow = titleRow?.nextElementSibling;
    const urlRow     = snippetRow?.nextElementSibling;
    const snippet    = snippetRow?.textContent?.trim() ?? '';
    const url        = urlRow?.querySelector('a')?.textContent?.trim()
                    ?? urlRow?.textContent?.trim() ?? '';
    out.push({ title, url: url || href, snippet, href });
  });

  if (out.length > 0) { console.log('[search] result-title found:', out.length); return out.slice(0, 10); }

  doc.querySelectorAll('.result').forEach(el => {
    const title   = el.querySelector('.result__title')?.textContent?.trim()   ?? '';
    const url     = el.querySelector('.result__url')?.textContent?.trim()     ?? '';
    const snippet = el.querySelector('.result__snippet')?.textContent?.trim() ?? '';
    const href    = el.querySelector('a.result__a')?.getAttribute('href')     ?? url;
    if (title) out.push({ title, url, snippet, href });
  });

  console.log('[search] .result fallback found:', out.length);
  return out.slice(0, 10);
}

// Chat history is encrypted at rest with a non-extractable AES-GCM key kept in
// IndexedDB (see secureStore). Without the key we simply don't persist — we never
// write plaintext history to disk.
async function persistHistory(roomId: string, messages: Message[], myUsername: string, key: CryptoKey | null): Promise<void> {
  if (messages.length === 0 || !key) return;
  try {
    const savable = messages.slice(-MAX_HISTORY).map(m => ({
      ...m,
      from: m.from === 'You' ? myUsername : m.from,
    }));
    const blob = await encryptHistory(key, JSON.stringify(savable));
    localStorage.setItem(`p2p-history-${roomId}`, blob);
  } catch { /* storage quota or crypto failure — skip */ }
}

function generateRoomCode(): string {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const pick = (n: number) =>
    Array.from({ length: n }, () => chars[secureRandInt(chars.length)]).join('');
  return `${pick(4)}-${pick(4)}`;
}

function emptyRoomState(): RoomReactState {
  return { peers: [], displayNames: {}, messages: [], inVoiceUsers: [], availableRelays: [], availableExits: [], fingerprints: {}, isInVoice: false };
}

// Exponential backoff: 2 s, 3 s, 6 s, 12 s, 24 s … capped at 5 min
function reconnectDelay(attempt: number): number {
  if (attempt === 0) return 2_000;
  return Math.min(3_000 * Math.pow(2, attempt - 1), 300_000);
}

interface CircuitResult {
  sendRt:          RoomRuntime;
  circuit:         [string, string, string];
  circuitPeerKeys: Record<string, string>;
}

// Builds all valid 3-hop circuits from the global relay pool across all joined rooms.
// Consecutive hops must share a room the initiator is also in, so each intermediate
// relay can look up and forward to the next hop via its own room connections.
// The same physical peer (identified by public key) appearing in multiple rooms counts
// once; their room entries are used to bridge cross-room chains.
function findAllCrossRoomCircuits(
  roomRuntimes:  Record<string, RoomRuntime>,
  roomStatesSnap: Record<string, RoomReactState>,
): CircuitResult[] {
  const byPubKey = new Map<string, RelayPeerInfo>();
  // Peers that opted in to the exit role — only these may be the final hop.
  const exitPubKeys = new Set<string>();
  for (const [roomId, rt] of Object.entries(roomRuntimes)) {
    const state = roomStatesSnap[roomId];
    for (const peerId of (state?.availableRelays ?? [])) {
      const pubKey = rt.peerPublicKeys[peerId];
      if (!pubKey) continue;
      if (!byPubKey.has(pubKey)) byPubKey.set(pubKey, { pubKey, rooms: [] });
      byPubKey.get(pubKey)!.rooms.push({ roomId, peerId, rt });
    }
    for (const peerId of (state?.availableExits ?? [])) {
      const pubKey = rt.peerPublicKeys[peerId];
      if (pubKey) exitPubKeys.add(pubKey);
    }
  }
  const relays = [...byPubKey.values()];
  const results: CircuitResult[] = [];
  for (let i = 0; i < relays.length; i++) {
    const A = relays[i];
    for (let j = 0; j < relays.length; j++) {
      if (j === i) continue;
      const B = relays[j];
      const rAB_A = A.rooms.find(ra => B.rooms.some(rb => rb.roomId === ra.roomId));
      if (!rAB_A) continue;
      const rAB_B = B.rooms.find(rb => rb.roomId === rAB_A.roomId)!;
      for (let k = 0; k < relays.length; k++) {
        if (k === i || k === j) continue;
        const C = relays[k];
        if (!exitPubKeys.has(C.pubKey)) continue; // final hop must be an opted-in exit
        const rBC_B = B.rooms.find(rb => C.rooms.some(rc => rc.roomId === rb.roomId));
        if (!rBC_B) continue;
        const rBC_C = C.rooms.find(rc => rc.roomId === rBC_B.roomId)!;
        results.push({
          sendRt:  rAB_A.rt,
          circuit: [rAB_A.peerId, rAB_B.peerId, rBC_C.peerId],
          circuitPeerKeys: {
            [rAB_A.peerId]: A.pubKey,
            [rAB_B.peerId]: B.pubKey,
            [rBC_C.peerId]: C.pubKey,
          },
        });
      }
    }
  }
  return secureShuffle(results);
}

// ─── Design tokens ────────────────────────────────────────────────────────────

const T = {
  bg:          '#1a1410',
  railBg:      '#13100c',
  panel:       '#221b15',
  panelAlt:    '#2a2218',
  border:      'rgba(244,234,216,0.07)',
  borderStrong:'rgba(244,234,216,0.12)',
  text:        '#f4ead8',
  textMuted:   'rgba(244,234,216,0.62)',
  textFaint:   'rgba(244,234,216,0.38)',
  accent:      '#e9a857',
  accentDeep:  '#c98839',
  accentText:  '#1a1410',
  accentSoft:  'rgba(233,168,87,0.14)',
  online:      '#84d49b',
  offline:     'rgba(244,234,216,0.22)',
  danger:      '#e07a6a',
  speak:       '#84d49b',
  font:        '"Geist Variable","Geist","Inter",-apple-system,sans-serif',
  fontMono:    '"Geist Mono Variable","Geist Mono","JetBrains Mono",ui-monospace,monospace',
  radius:      12,
  radiusS:     8,
  radiusL:     18,
} as const;

// ─── Icons ────────────────────────────────────────────────────────────────────

type SP = SVGProps<SVGSVGElement>;
const IHash   = (p:SP) => <svg {...p} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round"><path d="M6 2L4 14M12 2l-2 12M2.5 6h11M2 10h11"/></svg>;
const IGlobe  = (p:SP) => <svg {...p} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4"><circle cx="8" cy="8" r="6.2"/><path d="M1.8 8h12.4M8 1.8c2 2.3 2 10.1 0 12.4M8 1.8c-2 2.3-2 10.1 0 12.4"/></svg>;
const ILock   = (p:SP) => <svg {...p} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="7.5" width="10" height="6.5" rx="1.5"/><path d="M5 7.5V5a3 3 0 116 0v2.5"/></svg>;
const IShield = (p:SP) => <svg {...p} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round"><path d="M8 1.5l5.5 2v5c0 3-2.5 5.4-5.5 6.5-3-1.1-5.5-3.5-5.5-6.5v-5l5.5-2z"/></svg>;
const ISearch = (p:SP) => <svg {...p} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round"><circle cx="7" cy="7" r="4.5"/><path d="M10.5 10.5L14 14"/></svg>;
const IPlus   = (p:SP) => <svg {...p} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round"><path d="M8 3v10M3 8h10"/></svg>;
const ISend   = (p:SP) => <svg {...p} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2L2 7l5 2 2 5 5-12z"/></svg>;
const IMic    = (p:SP) => <svg {...p} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><rect x="6" y="2" width="4" height="8" rx="2"/><path d="M3.5 7.5a4.5 4.5 0 009 0M8 12v2"/></svg>;
const IMicOff = (p:SP) => <svg {...p} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><rect x="6" y="2" width="4" height="8" rx="2"/><path d="M3.5 7.5a4.5 4.5 0 009 0M8 12v2M2 2l12 12"/></svg>;
const IPhone  = (p:SP) => <svg {...p} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round"><path d="M3.5 2.5h2l1.2 3-1.5 1c.8 1.7 2 2.9 3.8 3.7l1-1.5 3 1.2v2c0 .8-.7 1.4-1.5 1.3C6.2 13 3 9.8 2.2 4c-.1-.8.5-1.5 1.3-1.5z"/></svg>;
const IHangup = (p:SP) => <svg {...p} viewBox="0 0 16 16" fill="currentColor"><path d="M8 4.5c-2.5 0-4.8.7-6.4 1.9-.5.4-.7 1.1-.5 1.7l.5 1.4c.2.7.9 1 1.6.8L5 9.6c.5-.2.9-.7.9-1.2v-.6c1.4-.5 2.8-.5 4.2 0v.6c0 .5.4 1 .9 1.2l1.8.7c.7.2 1.4-.1 1.6-.8l.5-1.4c.2-.6 0-1.3-.5-1.7C12.8 5.2 10.5 4.5 8 4.5z"/></svg>;
const ICog    = (p:SP) => <svg {...p} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4"><circle cx="8" cy="8" r="2.2"/><path d="M8 1.5v1.8M8 12.7v1.8M14.5 8h-1.8M3.3 8H1.5M12.6 3.4l-1.3 1.3M4.7 11.3l-1.3 1.3M12.6 12.6l-1.3-1.3M4.7 4.7L3.4 3.4"/></svg>;
const ICopy   = (p:SP) => <svg {...p} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round"><rect x="5" y="5" width="8" height="9" rx="1.5"/><path d="M3 11V3a1 1 0 011-1h7"/></svg>;
const IBack   = (p:SP) => <svg {...p} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round"><path d="M10 3L5 8l5 5"/></svg>;
const IFwd    = (p:SP) => <svg {...p} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round"><path d="M6 3l5 5-5 5"/></svg>;
const IReload = (p:SP) => <svg {...p} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M13.5 8a5.5 5.5 0 11-1.6-3.9M13.8 2.5v2.8H11"/></svg>;

// ─── UI primitives ─────────────────────────────────────────────────────────────

function hueForName(s: string): number {
  let h = 0; for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) & 0xffff; return h % 360;
}

function Av({ name, size = 32, status, speaking }: { name: string; size?: number; status?: 'online'|'voice'|'off'; speaking?: boolean }) {
  const hue = hueForName(name);
  return (
    <div style={{ position: 'relative', width: size, height: size, flexShrink: 0 }}>
      <div style={{ width: size, height: size, borderRadius: T.radiusL, background: `oklch(0.62 0.13 ${hue})`, color: `oklch(0.18 0.04 ${hue})`, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: size * 0.42, fontWeight: 600, letterSpacing: -0.5, boxShadow: speaking ? `0 0 0 2.5px ${T.speak}` : 'none', transition: 'box-shadow .15s', userSelect: 'none' }}>
        {name.slice(0,1).toLowerCase()}
      </div>
      {status && <div style={{ position: 'absolute', right: -1, bottom: -1, width: Math.max(8, size*.28), height: Math.max(8, size*.28), borderRadius: '50%', background: status === 'online' ? T.online : status === 'voice' ? T.accent : T.offline, boxShadow: `0 0 0 2px ${T.panel}` }} />}
    </div>
  );
}

function Tog({ on, onClick }: { on: boolean; onClick?: () => void }) {
  return (
    <div onClick={onClick} style={{ width: 30, height: 18, borderRadius: 9, background: on ? T.accent : T.panelAlt, border: `1px solid ${on ? T.accent : T.borderStrong}`, position: 'relative', cursor: 'pointer', flexShrink: 0, transition: 'background .15s' }}>
      <div style={{ position: 'absolute', top: 1, left: on ? 13 : 1, width: 14, height: 14, borderRadius: 7, background: on ? T.accentText : T.text, transition: 'left .15s', boxShadow: '0 1px 2px rgba(0,0,0,.25)' }} />
    </div>
  );
}

function BunLogo({ size = 28 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" style={{ flexShrink: 0 }}>
      <rect x="2" y="7" width="28" height="18" rx="9" fill={T.accent} />
      <path d="M7 16h18" stroke={T.accentText} strokeWidth="1.6" strokeLinecap="round" opacity="0.4" />
      <circle cx="11" cy="13" r="0.9" fill={T.accentText} opacity="0.5" />
      <circle cx="16" cy="12.4" r="0.9" fill={T.accentText} opacity="0.5" />
      <circle cx="21" cy="13" r="0.9" fill={T.accentText} opacity="0.5" />
    </svg>
  );
}

function IBtn({ active, onClick, title, children }: { active?: boolean; onClick?: () => void; title?: string; children: React.ReactNode }) {
  return (
    <button title={title} onClick={onClick} style={{ width: 28, height: 28, borderRadius: T.radiusS, background: active ? T.accentSoft : 'transparent', color: active ? T.accent : T.textMuted, border: 'none', cursor: 'pointer', padding: 0, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      {children}
    </button>
  );
}

function VoiceTile({ name, isSelf, speaking, muted, volume, tileH, onVol }: { name: string; isSelf: boolean; speaking: boolean; muted: boolean; volume: number; tileH: number; onVol: (v: number) => void }) {
  const [hov, setHov] = useState(false);
  return (
    <div onMouseEnter={() => !isSelf && setHov(true)} onMouseLeave={() => setHov(false)}
      style={{ height: tileH, background: T.panel, borderRadius: T.radius, border: `1.5px solid ${speaking ? T.speak : T.border}`, boxShadow: speaking ? `0 0 10px ${T.speak}44` : 'none', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 12, position: 'relative', overflow: 'hidden', transition: 'border-color .15s, box-shadow .15s' }}>
      {muted && <div style={{ position: 'absolute', top: 10, right: 10, background: T.danger, color: '#fff', borderRadius: 12, padding: '2px 8px', fontSize: 11, fontFamily: T.fontMono, display: 'flex', alignItems: 'center', gap: 4 }}><IMicOff width="9" height="9" /> muted</div>}
      <Av name={name} size={86} speaking={speaking} />
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <span style={{ fontSize: 15, fontWeight: 600, color: T.text }}>{name}</span>
        {isSelf && <span style={{ fontFamily: T.fontMono, fontSize: 11, color: T.accent }}>· you</span>}
      </div>
      {hov && !isSelf && (
        <div style={{ position: 'absolute', bottom: 0, left: 0, right: 0, background: 'rgba(0,0,0,.55)', backdropFilter: 'blur(8px)', padding: '10px 12px', borderRadius: `0 0 ${T.radius}px ${T.radius}px` }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6, fontSize: 10, fontFamily: T.fontMono, color: T.textFaint }}>
            <span>VOLUME</span><span style={{ color: T.text, fontWeight: 600 }}>{Math.round(volume)}%</span>
          </div>
          <input type="range" min="0" max="200" value={volume} onChange={e => onVol(Number(e.target.value))} style={{ width: '100%', accentColor: volume > 100 ? T.danger : T.accent } as CSSProperties} />
          <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 4, fontSize: 10, fontFamily: T.fontMono, color: T.textFaint }}>
            <span>0%</span><span>100%</span><span>200%</span>
          </div>
        </div>
      )}
    </div>
  );
}


// ─── Component ────────────────────────────────────────────────────────────────

function App() {
  // ── Global state ─────────────────────────────────────────────────────────────
  const [username, setUsername]             = useState('');
  const [isMuted, setIsMuted]               = useState(false);
  const [isInVoice, setIsInVoice]           = useState(false);
  const [newMessage, setNewMessage]         = useState('');
  const [showSetup, setShowSetup]           = useState(false);
  const [isRelayEnabled, setIsRelayEnabled] = useState(true);  // middle hop — low risk
  const [isExitEnabled, setIsExitEnabled]   = useState(false); // exit hop — opt-in, see warning
  const [showExitWarning, setShowExitWarning] = useState(false);
  const [acceptHistory, setAcceptHistory]   = useState(false); // history from peers is spoofable; opt-in only
  const [myFingerprint, setMyFingerprint]   = useState('');
  const [searchQuery, setSearchQuery]       = useState('');
  const [activeView, setActiveView]         = useState<'chat' | 'search' | 'browse' | 'voice'>('chat');
  const [callDuration, setCallDuration]     = useState('');
  const [voiceRoomId, setVoiceRoomId]       = useState<string | null>(null);
  const [isSearching, setIsSearching]       = useState(false);
  const [searchResults, setSearchResults]   = useState<SearchResult[]>([]);
  const [searchError, setSearchError]       = useState<string | null>(null);
  const [, setActiveCircuit]                = useState<string[]>([]); // tracked for future circuit-path UI
  const [isAtBottom, setIsAtBottom]         = useState(true);
  const [isSpeaking, setIsSpeaking]         = useState(false);
  const [speakingPeers, setSpeakingPeers]   = useState<Record<string, boolean>>({});
  const [browseUrl, setBrowseUrl]           = useState('');
  const [browseHtml, setBrowseHtml]         = useState('');
  const [isBrowsing, setIsBrowsing]         = useState(false);
  const [, setBrowseCircuit]                = useState<string[]>([]); // tracked for future circuit-path UI

  // ── Room state ────────────────────────────────────────────────────────────────
  const [roomDefs, setRoomDefs]             = useState<RoomDef[]>([]);
  const [activeRoomId, setActiveRoomId]     = useState(DEFAULT_ROOM_ID);
  const [roomStates, setRoomStates]         = useState<Record<string, RoomReactState>>({});
  const [showRoomModal, setShowRoomModal]   = useState<'create' | 'join' | null>(null);
  const [roomModalLabel, setRoomModalLabel] = useState('');
  const [roomModalCode, setRoomModalCode]   = useState('');
  const [createdRoomCode, setCreatedRoomCode] = useState('');
  const [pendingDmInvite, setPendingDmInvite] = useState<{ fromUsername: string; roomId: string; peerId: string } | null>(null);
  const [userContextMenu, setUserContextMenu] = useState<{ username: string; peerId: string; x: number; y: number } | null>(null);
  const [menuSafety, setMenuSafety]           = useState(''); // combined safety number for the selected peer

  // ── Refs ─────────────────────────────────────────────────────────────────────
  const usernameInputRef  = useRef<HTMLInputElement>(null);
  const messageListRef    = useRef<HTMLDivElement>(null);
  const audioCtxRef       = useRef<AudioContext | null>(null);
  const speakingTimerRef  = useRef<ReturnType<typeof setInterval> | null>(null);
  const volumesRef        = useRef<Record<string, number>>({});
  const myPublicKeyRef    = useRef('');
  const myPrivateKeyRef   = useRef<CryptoKey | null>(null);
  const myRatchetPrekeyRef = useRef<{ pair: CryptoKeyPair; pub: Uint8Array<ArrayBuffer> } | null>(null);
  const historyKeyRef     = useRef<CryptoKey | null>(null);
  const isRelayEnabledRef  = useRef(true);
  const isExitEnabledRef   = useRef(false);
  const acceptHistoryRef   = useRef(false);
  const usernameRef       = useRef('');
  const activeRoomIdRef   = useRef(DEFAULT_ROOM_ID);
  const browsePageRef     = useRef<((href: string) => void) | null>(null);
  const roomRuntimesRef    = useRef<Record<string, RoomRuntime>>({});
  const windowFocusedRef   = useRef(true);
  const roomPeerCountRef      = useRef<Record<string, number>>({});
  const roomHadPeersRef       = useRef<Record<string, boolean>>({});
  const roomReconnectAttempts = useRef<Record<string, number>>({});
  const circuitTableRef   = useRef<Record<string, { returnRuntime: RoomRuntime; returnPeer: string; expiresAt: number }>>({});
  const pendingCircuitsRef = useRef<Record<string, { resolve: (d: string) => void; reject: (e: string) => void }>>({});
  const callStartRef       = useRef<number | null>(null);
  const callTimerRef       = useRef<ReturnType<typeof setInterval> | null>(null);

  // ── Room connection helper ────────────────────────────────────────────────────

  const setupRoom = (roomId: string) => {
    if (roomRuntimesRef.current[roomId]) return;

    const runtime: RoomRuntime = {
      trysteroRoom:    null,
      sendEncMsg:      null,
      sendPeerKey:     null,
      sendRelayFwd:    null,
      sendRelayResp:   null,
      peerPublicKeys:  {},
      ratchetSessions: {},
      outboundSenderKey: null,
      inboundSenderKeys: {},
      peerUsername:    {},
      usernamePeer:    {},
      remoteAudios:    {},
      remoteAnalysers: {},
      selfStream:       null,
      selfAnalyser:     null,
      isInVoice:        false,
      announceInterval: null,
    };
    roomRuntimesRef.current[roomId] = runtime;

    // Mint this room's group Sender Key, then hand its distribution to anyone
    // already connected. Peers who connect later get it during key exchange (see
    // getPeerKey). Until it's ready, group chat degrades gracefully to ECIES.
    void createSenderKey().then(async sk => {
      runtime.outboundSenderKey = sk;
      const dist = distributionMessage(sk);
      for (const pid of Object.keys(runtime.peerPublicKeys)) {
        await sendToPeer(runtime, pid, { type: 'senderKey', dist });
      }
    });

    // Our public key + ratchet prekey, sent so peers can key-exchange and start a
    // Double Ratchet session with us.
    const myKeyMsg = (): PeerKeyMessage => ({
      publicKeyBase64: myPublicKeyRef.current,
      ratchetPrekeyBase64: myRatchetPrekeyRef.current ? uint8ToBase64(myRatchetPrekeyRef.current.pub) : undefined,
    });

    const trysteroRoom = joinRoom({ appId: APP_ID, rtcConfig: RTC_CONFIG }, roomId);
    runtime.trysteroRoom = trysteroRoom;

    const upd = (fn: (s: RoomReactState) => RoomReactState) =>
      setRoomStates(prev => ({ ...prev, [roomId]: fn(prev[roomId] ?? emptyRoomState()) }));

    // All non-key messages travel as AES-256-GCM ciphertext encrypted for the recipient.
    const [sendEncMsg, getEncMsg] = trysteroRoom.makeAction('encMsg');
    runtime.sendEncMsg = sendEncMsg;
    getEncMsg(async (data: EncMsgPacket, peerId: string) => {
      if (!myPrivateKeyRef.current) return;
      try {
        let plaintext: string;
        if ('rk' in data) {
          // Double Ratchet message — needs the session with this exact sender.
          const session = runtime.ratchetSessions[peerId];
          if (!session) return;
          plaintext = new TextDecoder().decode(await ratchetDecrypt(session, data.rk));
        } else if ('sk' in data) {
          // Group Sender Key message — decrypt with the inbound chain we hold for
          // this sender's identity key. Keying on the transport sender's pubkey
          // means a peer can't pass off another member's chain as its own: the
          // ECDSA signature would verify against the wrong signing key and fail.
          const senderPub = runtime.peerPublicKeys[peerId];
          const inbound   = senderPub ? runtime.inboundSenderKeys[senderPub] : undefined;
          if (!inbound) return; // no distribution from this sender yet — drop
          plaintext = new TextDecoder().decode(await senderDecrypt(inbound, data.sk));
        } else {
          plaintext = await decryptLayer(data.enc, myPrivateKeyRef.current);
        }
        const payload = JSON.parse(plaintext) as EncMsgPayload;
        switch (payload.type) {
          case 'username':
            runtime.peerUsername[peerId]           = payload.username;
            runtime.usernamePeer[payload.username] = peerId;
            upd(s => ({ ...s, displayNames: { ...s.displayNames, [peerId]: payload.username } }));
            break;
          case 'chat':
            runtime.peerUsername[peerId]           = payload.username;
            runtime.usernamePeer[payload.username] = peerId;
            upd(s => {
              const messages = [...s.messages, { id: payload.id, from: payload.username, text: payload.text, ts: Date.now() }];
              void persistHistory(roomId, messages, usernameRef.current, historyKeyRef.current);
              return {
                ...s,
                displayNames: s.displayNames[peerId] ? s.displayNames : { ...s.displayNames, [peerId]: payload.username },
                messages,
              };
            });
            if (!windowFocusedRef.current) {
              isPermissionGranted().then(granted => {
                if (!granted) return;
                const roomLabel = roomDefs.find(d => d.id === roomId)?.label ?? roomId;
                sendNotification({ title: `${payload.username} — ${roomLabel}`, body: payload.text });
              });
            }
            break;
          case 'voiceStatus':
            runtime.peerUsername[peerId]           = payload.username;
            runtime.usernamePeer[payload.username] = peerId;
            upd(s => ({
              ...s,
              displayNames: s.displayNames[peerId] ? s.displayNames : { ...s.displayNames, [peerId]: payload.username },
              inVoiceUsers: payload.inVoice
                ? s.inVoiceUsers.includes(payload.username) ? s.inVoiceUsers : [...s.inVoiceUsers, payload.username]
                : s.inVoiceUsers.filter(u => u !== payload.username),
            }));
            break;
          case 'relayAvail':
            upd(s => ({
              ...s,
              availableRelays: payload.isRelay
                ? s.availableRelays.includes(peerId) ? s.availableRelays : [...s.availableRelays, peerId]
                : s.availableRelays.filter(id => id !== peerId),
              availableExits: payload.isExit
                ? s.availableExits.includes(peerId) ? s.availableExits : [...s.availableExits, peerId]
                : s.availableExits.filter(id => id !== peerId),
            }));
            break;
          case 'dmInvite':
            setPendingDmInvite({ fromUsername: payload.fromUsername, roomId: payload.roomId, peerId });
            break;
          case 'relayBatch':
            // Broadcast every blob to every peer — we don't know which blob is
            // for which peer, so recipients discard what they cannot decrypt.
            for (const enc of payload.blobs) {
              for (const targetPeerId of Object.keys(runtime.peerPublicKeys)) {
                runtime.sendEncMsg?.({ enc }, targetPeerId);
              }
            }
            break;
          case 'senderKey': {
            // The sender handed us their group chain (over this secure channel).
            // Store it under their identity key so we can decrypt their broadcasts.
            const senderPub = runtime.peerPublicKeys[peerId];
            if (senderPub) runtime.inboundSenderKeys[senderPub] = await importDistribution(payload.dist);
            break;
          }
          case 'chatHistory':
            if (!acceptHistoryRef.current) break;
            upd(s => {
              const existingIds = new Set(s.messages.map(m => m.id));
              const myUsername  = usernameRef.current;
              const incoming    = payload.messages
                .filter(m => !existingIds.has(m.id))
                .map(m => ({ ...m, synced: true, from: m.from === myUsername ? 'You' : m.from }));
              if (incoming.length === 0) return s;
              const merged = [...incoming, ...s.messages].sort((a, b) => a.ts - b.ts);
              return { ...s, messages: merged };
            });
            break;
        }
      } catch { /* malformed packet or decryption failure — discard */ }
    });

    // peerKey is the only plaintext action: public keys are not secret.
    // Once we receive a peer's key we immediately send them our encrypted introduction.
    const [sendPeerKey, getPeerKey] = trysteroRoom.makeAction('peerKey');
    runtime.sendPeerKey = sendPeerKey;
    getPeerKey(async (data: PeerKeyMessage, peerId: string) => {
      // peerKey is re-announced every few seconds; only the first sighting of a
      // peer is treated as new (drives one-time setup like sender-key handoff).
      const isNewPeer = !runtime.peerPublicKeys[peerId];
      runtime.peerPublicKeys[peerId] = data.publicKeyBase64;
      const pubKey = data.publicKeyBase64;
      // Derive and surface this peer's safety-number fingerprint.
      keyFingerprint(pubKey).then(fp =>
        upd(s => ({ ...s, fingerprints: { ...s.fingerprints, [peerId]: fp } }))
      );

      // Establish a Double Ratchet session for 1:1 conversations. Symmetry is
      // broken by comparing identity keys so both sides agree on who is the
      // initiator. (Group rooms still use ECIES; the ratchet just rides alongside.)
      if (
        data.ratchetPrekeyBase64 && myPrivateKeyRef.current && myRatchetPrekeyRef.current &&
        !runtime.ratchetSessions[peerId]
      ) {
        try {
          const theirIdPub = await crypto.subtle.importKey(
            'raw', base64ToUint8(pubKey), { name: 'ECDH', namedCurve: 'P-256' }, false, []
          );
          const shared = new Uint8Array(await crypto.subtle.deriveBits(
            { name: 'ECDH', public: theirIdPub }, myPrivateKeyRef.current, 256
          ));
          const SK = await deriveSK(shared);
          const iAmInitiator = myPublicKeyRef.current < pubKey;
          runtime.ratchetSessions[peerId] = iAmInitiator
            ? await initAlice(SK, base64ToUint8(data.ratchetPrekeyBase64))
            : await initBob(SK, myRatchetPrekeyRef.current.pair, myRatchetPrekeyRef.current.pub);
        } catch { /* couldn't establish — messages fall back to ECIES */ }
      }

      // Encrypted introduction (ratcheted when the session can already send).
      await sendToPeer(runtime, peerId, { type: 'username',    username: usernameRef.current });
      await sendToPeer(runtime, peerId, { type: 'relayAvail',  isRelay: isRelayEnabledRef.current, isExit: isExitEnabledRef.current });
      await sendToPeer(runtime, peerId, { type: 'voiceStatus', username: usernameRef.current, inVoice: runtime.isInVoice });

      // Hand a newly-seen peer our group sender key once (over this secure
      // channel) so they can decrypt our group broadcasts. Re-sending on every
      // announcement would reset their chain past messages they hadn't read yet.
      if (isNewPeer && runtime.outboundSenderKey) {
        await sendToPeer(runtime, peerId, { type: 'senderKey', dist: distributionMessage(runtime.outboundSenderKey) });
      }

      const savedRaw = localStorage.getItem(`p2p-history-${roomId}`);
      if (savedRaw && historyKeyRef.current) {
        try {
          const messages = JSON.parse(await decryptHistory(historyKeyRef.current, savedRaw));
          await sendToPeer(runtime, peerId, { type: 'chatHistory', messages });
        } catch { /* corrupt or undecryptable save — ignore */ }
      }
    });

    const [sendRelayFwd, getRelayFwd] = trysteroRoom.makeAction('relayFwd');
    runtime.sendRelayFwd = sendRelayFwd;
    getRelayFwd(async (data: OnionForwardPacket, senderPeerId: string) => {
      if (!myPrivateKeyRef.current) return;
      // Act only in a role we've actually enabled: middle hop (relay) and/or exit.
      if (!isRelayEnabledRef.current && !isExitEnabledRef.current) return;
      circuitTableRef.current[data.circuitId] = { returnRuntime: runtime, returnPeer: senderPeerId, expiresAt: Date.now() + 60_000 };
      try {
        const plaintext    = await decryptLayer(data.layer, myPrivateKeyRef.current);
        const instruction: PlainInstruction = JSON.parse(plaintext);
        if (instruction.nextHop === 'exit') {
          // Being the exit means OUR IP makes the request. Only do it if the user
          // explicitly opted in to the exit role (see the warning dialog).
          if (!isExitEnabledRef.current) {
            runtime.sendRelayResp?.({ circuitId: data.circuitId, data: 'Exit relay unavailable', isError: true }, senderPeerId);
            return;
          }
          try {
            const html = await invoke<string>('relay_fetch', { url: instruction.payload });
            runtime.sendRelayResp?.({ circuitId: data.circuitId, data: html, isError: false }, senderPeerId);
          } catch (e) {
            runtime.sendRelayResp?.({ circuitId: data.circuitId, data: String(e), isError: true }, senderPeerId);
          }
        } else {
          if (!isRelayEnabledRef.current) {
            runtime.sendRelayResp?.({ circuitId: data.circuitId, data: 'Relay unavailable', isError: true }, senderPeerId);
            return;
          }
          const nextLayer: EncryptedLayer = JSON.parse(atob(instruction.payload));
          // Search all joined rooms for the next hop — enables cross-room relay chains
          let nextRt: RoomRuntime | null = null;
          for (const rt of Object.values(roomRuntimesRef.current)) {
            if (rt.peerPublicKeys[instruction.nextHop]) { nextRt = rt; break; }
          }
          if (!nextRt) {
            runtime.sendRelayResp?.({ circuitId: data.circuitId, data: 'Relay hop unreachable', isError: true }, senderPeerId);
            return;
          }
          nextRt.sendRelayFwd?.({ circuitId: data.circuitId, layer: nextLayer }, instruction.nextHop);
        }
      } catch { /* malformed packet — discard */ }
    });

    const [sendRelayResp, getRelayResp] = trysteroRoom.makeAction('relayResp');
    runtime.sendRelayResp = sendRelayResp;
    getRelayResp((data: OnionResponsePacket) => {
      const pending = pendingCircuitsRef.current[data.circuitId];
      if (pending) {
        delete pendingCircuitsRef.current[data.circuitId];
        if (data.isError) pending.reject(data.data);
        else              pending.resolve(data.data);
        return;
      }
      const entry = circuitTableRef.current[data.circuitId];
      if (entry) {
        entry.returnRuntime.sendRelayResp?.(data, entry.returnPeer);
        delete circuitTableRef.current[data.circuitId];
      }
    });

    trysteroRoom.onPeerJoin((peerId: string) => {
      roomPeerCountRef.current[roomId]      = (roomPeerCountRef.current[roomId] ?? 0) + 1;
      roomHadPeersRef.current[roomId]       = true;
      roomReconnectAttempts.current[roomId] = 0;
      upd(s => ({ ...s, peers: s.peers.includes(peerId) ? s.peers : [...s.peers, peerId] }));
      // Send our public key; the getPeerKey handler on the other side will send back
      // an encrypted introduction once it receives this.
      if (myPublicKeyRef.current) runtime.sendPeerKey?.(myKeyMsg(), peerId);
    });

    trysteroRoom.onPeerLeave((peerId: string) => {
      const leavingUsername = runtime.peerUsername[peerId];
      const leavingPubKey   = runtime.peerPublicKeys[peerId];
      upd(s => ({
        ...s,
        peers:           s.peers.filter(id => id !== peerId),
        displayNames:    Object.fromEntries(Object.entries(s.displayNames).filter(([k]) => k !== peerId)),
        inVoiceUsers:    leavingUsername ? s.inVoiceUsers.filter(u => u !== leavingUsername) : s.inVoiceUsers,
        availableRelays: s.availableRelays.filter(id => id !== peerId),
        availableExits:  s.availableExits.filter(id => id !== peerId),
        fingerprints:    Object.fromEntries(Object.entries(s.fingerprints).filter(([k]) => k !== peerId)),
      }));
      const audio = runtime.remoteAudios[peerId];
      if (audio) {
        audio.pause();
        (audio.srcObject as MediaStream | null)?.getTracks().forEach(t => t.stop());
        audio.srcObject = null;
        delete runtime.remoteAudios[peerId];
      }
      delete runtime.remoteAnalysers[peerId];
      if (leavingUsername) {
        delete runtime.usernamePeer[leavingUsername];
        delete runtime.peerUsername[peerId];
      }
      delete runtime.peerPublicKeys[peerId];
      delete runtime.ratchetSessions[peerId]; // ratchet sessions are per-connection; re-handshake on rejoin
      if (leavingPubKey) delete runtime.inboundSenderKeys[leavingPubKey];

      // Membership rekey: a departed member still holds a copy of our sender chain
      // and could ratchet it forward, so mint a fresh chain and redistribute it to
      // the remaining members. Anything we send next is unreadable to the leaver.
      if (runtime.outboundSenderKey && Object.keys(runtime.peerPublicKeys).length > 0) {
        void createSenderKey().then(async sk => {
          runtime.outboundSenderKey = sk;
          const dist = distributionMessage(sk);
          for (const pid of Object.keys(runtime.peerPublicKeys)) {
            await sendToPeer(runtime, pid, { type: 'senderKey', dist });
          }
        });
      }
      Object.keys(circuitTableRef.current).forEach(cid => {
        const e = circuitTableRef.current[cid];
        if (e.returnRuntime === runtime && e.returnPeer === peerId) delete circuitTableRef.current[cid];
      });

      const remaining = Math.max(0, (roomPeerCountRef.current[roomId] ?? 1) - 1);
      roomPeerCountRef.current[roomId] = remaining;
      if (remaining === 0 && roomHadPeersRef.current[roomId]) {
        const attempt = roomReconnectAttempts.current[roomId] ?? 0;
        roomReconnectAttempts.current[roomId] = attempt + 1;
        setTimeout(() => {
          if (roomRuntimesRef.current[roomId] !== runtime) return;
          if ((roomPeerCountRef.current[roomId] ?? 0) > 0) return;
          if (runtime.announceInterval) clearInterval(runtime.announceInterval);
          runtime.trysteroRoom?.leave();
          delete roomRuntimesRef.current[roomId];
          delete roomPeerCountRef.current[roomId];
          setupRoom(roomId);
        }, reconnectDelay(attempt));
      }
    });

    trysteroRoom.onPeerStream((stream: MediaStream, peerId: string) => {
      const audio = new Audio();
      audio.srcObject = stream;
      const peerName = runtime.peerUsername[peerId];
      const saved    = peerName ? volumesRef.current[peerName] : undefined;
      if (saved !== undefined) audio.volume = saved;
      runtime.remoteAudios[peerId] = audio;
      if (runtime.isInVoice) audio.play().catch(() => {});
      try {
        const ctx = audioCtxRef.current ?? new AudioContext();
        audioCtxRef.current = ctx;
        const analyser = ctx.createAnalyser();
        analyser.fftSize = 256;
        ctx.createMediaStreamSource(stream).connect(analyser);
        runtime.remoteAnalysers[peerId] = analyser;
      } catch { /* AudioContext unavailable */ }
    });

    // Announce our public key on room join so any already-connected peers
    // can initiate the encrypted key exchange with us.
    if (myPublicKeyRef.current) runtime.sendPeerKey?.(myKeyMsg());

    // Re-announce periodically so late joiners who missed the initial broadcast
    // pick up our key and then receive encrypted status via the getPeerKey handler.
    runtime.announceInterval = setInterval(async () => {
      if (myPublicKeyRef.current) runtime.sendPeerKey?.(myKeyMsg());
      if (usernameRef.current) {
        await sendDirectToAll(runtime, { type: 'username',   username: usernameRef.current });
        await sendDirectToAll(runtime, { type: 'relayAvail', isRelay: isRelayEnabledRef.current, isExit: isExitEnabledRef.current });
      }
    }, 5_000);
  };

  // ── Effects ───────────────────────────────────────────────────────────────────

  useEffect(() => {
    (async () => {
      const granted = await isPermissionGranted();
      if (!granted) await requestPermission();
    })();
    const win = getCurrentWindow();
    let unlisten: (() => void) | undefined;
    win.onFocusChanged(({ payload: focused }) => {
      windowFocusedRef.current = focused;
    }).then(fn => { unlisten = fn; });
    return () => unlisten?.();
  }, []);

  useEffect(() => {
    (async () => {
      // Identity key is a non-extractable CryptoKey in IndexedDB (no plaintext on
      // disk); persisted so a peer's safety number is stable across sessions.
      const { priv, pubRaw } = await loadOrCreateIdentity();
      myPrivateKeyRef.current = priv;
      const pubB64 = uint8ToBase64(pubRaw);
      myPublicKeyRef.current = pubB64;
      setMyFingerprint(await keyFingerprint(pubB64));

      // A ratchet prekey advertised to peers; used as our initial ratchet key when
      // we're the responder in a Double Ratchet session.
      const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']) as CryptoKeyPair;
      const pub = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
      myRatchetPrekeyRef.current = { pair, pub };

      // Key for encrypting chat history at rest.
      historyKeyRef.current = await loadOrCreateHistoryKey();
    })();
  }, []);

  useEffect(() => {
    const savedUsername = localStorage.getItem('p2p-username');
    if (savedUsername) setUsername(savedUsername);
    else setShowSetup(true);

    const savedVols = localStorage.getItem('p2p-volumes');
    if (savedVols) volumesRef.current = JSON.parse(savedVols);

    // History import is OFF by default (it's the message-forgery vector); only
    // re-enable if the user previously opted in.
    if (localStorage.getItem('p2p-accept-history') === 'true') {
      setAcceptHistory(true);
      acceptHistoryRef.current = true;
    }

    // Exit relaying is OFF by default and only restored if the user previously
    // acknowledged the warning and enabled it.
    if (localStorage.getItem('p2p-exit-enabled') === 'true') {
      setIsExitEnabled(true);
      isExitEnabledRef.current = true;
    }

    const savedRooms = localStorage.getItem('p2p-rooms');
    let defs: RoomDef[] = savedRooms
      ? JSON.parse(savedRooms)
      : [{ id: DEFAULT_ROOM_ID, label: DEFAULT_ROOM_LABEL }];
    if (!defs.find(d => d.id === DEFAULT_ROOM_ID)) {
      defs = [{ id: DEFAULT_ROOM_ID, label: DEFAULT_ROOM_LABEL }, ...defs];
    }
    const savedDms = localStorage.getItem('p2p-dm-rooms');
    if (savedDms) {
      const dmDefs: RoomDef[] = JSON.parse(savedDms);
      defs = [...defs, ...dmDefs];
    }
    setRoomDefs(defs);
  }, []);

  // Connect to rooms whenever username or room list changes
  useEffect(() => {
    if (!username || roomDefs.length === 0) return;
    usernameRef.current = username;
    roomDefs.forEach(def => setupRoom(def.id));
  }, [username, roomDefs]); // eslint-disable-line react-hooks/exhaustive-deps

  // Cleanup all rooms on unmount
  useEffect(() => {
    return () => {
      if (callTimerRef.current) clearInterval(callTimerRef.current);
      Object.values(roomRuntimesRef.current).forEach(rt => {
        if (rt.announceInterval) clearInterval(rt.announceInterval);
        rt.trysteroRoom?.leave();
        Object.values(rt.remoteAudios).forEach(a => {
          a.pause();
          (a.srcObject as MediaStream | null)?.getTracks().forEach(t => t.stop());
          a.srcObject = null;
        });
        rt.selfStream?.getTracks().forEach(t => t.stop());
      });
    };
  }, []);

  useEffect(() => {
    const msgs = roomStates[activeRoomId]?.messages ?? [];
    if (isAtBottom && messageListRef.current && msgs.length > 0) {
      messageListRef.current.scrollTop = messageListRef.current.scrollHeight;
    }
  }, [roomStates, activeRoomId, isAtBottom]);

  useEffect(() => {
    const handler = (e: MessageEvent) => {
      if (e.data?.type === 'nav' && typeof e.data.href === 'string') {
        browsePageRef.current?.(e.data.href);
      }
    };
    window.addEventListener('message', handler);
    return () => window.removeEventListener('message', handler);
  }, []);

  // Compute the combined safety number when a peer's menu opens, so two people
  // can compare the same number out-of-band and confirm there's no key swap.
  useEffect(() => {
    if (!userContextMenu) { setMenuSafety(''); return; }
    const rt = roomRuntimesRef.current[activeRoomId];
    const theirKey = rt?.peerPublicKeys[userContextMenu.peerId];
    const myKey = myPublicKeyRef.current;
    if (theirKey && myKey) safetyNumber(myKey, theirKey).then(setMenuSafety);
  }, [userContextMenu, activeRoomId]);

  useEffect(() => {
    const pruner = setInterval(() => {
      const now = Date.now();
      for (const cid of Object.keys(circuitTableRef.current)) {
        if (circuitTableRef.current[cid].expiresAt < now)
          delete circuitTableRef.current[cid];
      }
    }, 60_000);
    return () => clearInterval(pruner);
  }, []);

  // Speaking detection — re-runs when voice or active room changes
  useEffect(() => {
    if (!isInVoice) {
      if (speakingTimerRef.current) clearInterval(speakingTimerRef.current);
      speakingTimerRef.current = null;
      setIsSpeaking(false);
      setSpeakingPeers({});
      return;
    }
    speakingTimerRef.current = setInterval(() => {
      const rt = roomRuntimesRef.current[voiceRoomId ?? activeRoomId];
      if (!rt) return;
      if (rt.selfAnalyser) {
        const data = new Uint8Array(rt.selfAnalyser.frequencyBinCount);
        rt.selfAnalyser.getByteFrequencyData(data);
        setIsSpeaking(data.reduce((s, v) => s + v, 0) / data.length > 8);
      }
      const updates: Record<string, boolean> = {};
      Object.entries(rt.remoteAnalysers).forEach(([pid, analyser]) => {
        const d = new Uint8Array(analyser.frequencyBinCount);
        analyser.getByteFrequencyData(d);
        updates[pid] = d.reduce((s, v) => s + v, 0) / d.length > 8;
      });
      setSpeakingPeers(updates);
    }, 100);
    return () => { if (speakingTimerRef.current) clearInterval(speakingTimerRef.current); };
  }, [isInVoice, activeRoomId, voiceRoomId]);

  // ── Handlers ──────────────────────────────────────────────────────────────────

  const saveUsername = (name: string) => {
    if (!name.trim()) return;
    if (name.length > 18) return;
    localStorage.setItem('p2p-username', name);
    setUsername(name);
    setShowSetup(false);
  };

  const sendMessage = async () => {
    const rt = roomRuntimesRef.current[activeRoomId];
    if (!newMessage.trim() || !rt?.sendEncMsg) return;
    if (newMessage.length > 800) return;
    const msgId = crypto.randomUUID();
    await sendEncryptedToAll(rt, { type: 'chat', id: msgId, username, text: newMessage });
    const newMsg: Message = { id: msgId, from: 'You', text: newMessage, ts: Date.now() };
    setRoomStates(prev => {
      const s = prev[activeRoomId] ?? emptyRoomState();
      const messages = [...s.messages, newMsg];
      void persistHistory(activeRoomId, messages, username, historyKeyRef.current);
      return { ...prev, [activeRoomId]: { ...s, messages } };
    });
    setNewMessage('');
    setTimeout(() => {
      if (messageListRef.current) {
        messageListRef.current.scrollTop = messageListRef.current.scrollHeight;
        setIsAtBottom(true);
      }
    }, 0);
  };

  const handleScroll = useCallback(() => {
    if (!messageListRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = messageListRef.current;
    setIsAtBottom(scrollHeight - scrollTop - clientHeight < 50);
  }, []);

  const scrollToBottom = () => {
    if (messageListRef.current) {
      messageListRef.current.scrollTop = messageListRef.current.scrollHeight;
      setIsAtBottom(true);
    }
  };

  const leaveVoiceInRoom = async (roomId: string) => {
    const rt = roomRuntimesRef.current[roomId];
    if (!rt?.isInVoice) return;
    const myUsername = usernameRef.current;
    rt.selfStream?.getTracks().forEach(t => t.stop());
    rt.selfStream   = null;
    rt.selfAnalyser = null;
    rt.isInVoice    = false;
    Object.values(rt.remoteAudios).forEach(a => { a.pause(); });
    await sendDirectToAll(rt, { type: 'voiceStatus', username: myUsername, inVoice: false });
    setRoomStates(prev => {
      const s = prev[roomId];
      if (!s) return prev;
      return { ...prev, [roomId]: { ...s, inVoiceUsers: s.inVoiceUsers.filter(u => u !== myUsername), isInVoice: false } };
    });
  };

  const toggleVoice = async () => {
    const leaveRoomId = voiceRoomId ?? activeRoomId;
    const leaveRt = roomRuntimesRef.current[leaveRoomId];
    if (isInVoice && leaveRt?.isInVoice) {
      if (callTimerRef.current) { clearInterval(callTimerRef.current); callTimerRef.current = null; }
      callStartRef.current = null;
      setCallDuration('');
      leaveVoiceInRoom(leaveRoomId);
      setIsInVoice(false);
      setIsMuted(false);
      setVoiceRoomId(null);
      if (activeView === 'voice') setActiveView('chat');
    } else if (!isInVoice) {
      const rt = roomRuntimesRef.current[activeRoomId];
      if (!rt) return;
      try {
        const stream = await navigator.mediaDevices.getUserMedia({
          audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true }
        });
        rt.selfStream = stream;
        try {
          const ctx = audioCtxRef.current ?? new AudioContext();
          audioCtxRef.current = ctx;
          const analyser = ctx.createAnalyser();
          analyser.fftSize = 256;
          ctx.createMediaStreamSource(stream).connect(analyser);
          rt.selfAnalyser = analyser;
        } catch { /* AudioContext unavailable */ }
        rt.isInVoice = true;
        rt.trysteroRoom.addStream(stream);
        Object.values(rt.remoteAudios).forEach(a => {
          if (a.srcObject && a.paused) a.play().catch(() => {});
        });
        await sendDirectToAll(rt, { type: 'voiceStatus', username, inVoice: true });
        setRoomStates(prev => {
          const s = prev[activeRoomId] ?? emptyRoomState();
          return { ...prev, [activeRoomId]: { ...s, inVoiceUsers: s.inVoiceUsers.includes(username) ? s.inVoiceUsers : [...s.inVoiceUsers, username], isInVoice: true } };
        });
        setIsInVoice(true);
        setVoiceRoomId(activeRoomId);
        callStartRef.current = Date.now();
        callTimerRef.current = setInterval(() => {
          if (!callStartRef.current) return;
          const e = Math.floor((Date.now() - callStartRef.current) / 1000);
          setCallDuration(`${String(Math.floor(e/3600)).padStart(2,'0')}:${String(Math.floor((e%3600)/60)).padStart(2,'0')}:${String(e%60).padStart(2,'0')}`);
        }, 1000);
      } catch {
        alert('Could not access microphone');
      }
    }
  };

  const toggleMute = () => {
    const rt = roomRuntimesRef.current[voiceRoomId ?? activeRoomId];
    if (!rt?.selfStream) return;
    const track = rt.selfStream.getAudioTracks()[0];
    if (track) track.enabled = !track.enabled;
    setIsMuted(!track?.enabled);
  };

  const changeVolume = (targetUsername: string, value: number) => {
    const volume = value / 100;
    volumesRef.current[targetUsername] = volume;
    localStorage.setItem('p2p-volumes', JSON.stringify(volumesRef.current));
    const rt = roomRuntimesRef.current[voiceRoomId ?? activeRoomId];
    if (!rt) return;
    const peerId = rt.usernamePeer[targetUsername];
    const audio  = peerId ? rt.remoteAudios[peerId] : undefined;
    if (audio) audio.volume = volume;
  };

  const saveChat = () => {
    const msgs = roomStates[activeRoomId]?.messages ?? [];
    if (msgs.length === 0) return;
    const lines = msgs.map(m => `[${new Date(m.ts).toLocaleString()}] ${m.from === 'You' ? username : m.from}: ${m.text}`);
    const blob  = new Blob([lines.join('\n')], { type: 'text/plain' });
    const url   = URL.createObjectURL(blob);
    const a     = document.createElement('a');
    a.href      = url;
    a.download  = `bunchat-${activeRoomLabel}-${new Date().toISOString().slice(0,10)}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const toggleAcceptHistory = () => {
    const next = !acceptHistory;
    setAcceptHistory(next);
    acceptHistoryRef.current = next;
    localStorage.setItem('p2p-accept-history', String(next));
  };

  const deleteLog = () => {
    localStorage.removeItem(`p2p-history-${activeRoomId}`);
    setRoomStates(prev => {
      const s = prev[activeRoomId];
      if (!s) return prev;
      return { ...prev, [activeRoomId]: { ...s, messages: [] } };
    });
  };

  const announceRelayStatus = async () => {
    await Promise.all(
      Object.values(roomRuntimesRef.current).map(rt =>
        sendDirectToAll(rt, { type: 'relayAvail', isRelay: isRelayEnabledRef.current, isExit: isExitEnabledRef.current })
      )
    );
  };

  const toggleRelay = async () => {
    const next = !isRelayEnabled;
    setIsRelayEnabled(next);
    isRelayEnabledRef.current = next;
    // Turning off middle-relay also disables exit (exit can't work without it).
    if (!next && isExitEnabled) {
      setIsExitEnabled(false);
      isExitEnabledRef.current = false;
      localStorage.setItem('p2p-exit-enabled', 'false');
    }
    await announceRelayStatus();
  };

  // Exit = our IP makes the actual web request for someone else. First enable
  // goes through a one-time legal warning; see showExitWarning modal.
  const setExitEnabled = async (next: boolean) => {
    setIsExitEnabled(next);
    isExitEnabledRef.current = next;
    localStorage.setItem('p2p-exit-enabled', String(next));
    // Exit requires middle-relay to be on (the exit hop receives via relayFwd).
    if (next && !isRelayEnabled) {
      setIsRelayEnabled(true);
      isRelayEnabledRef.current = true;
    }
    await announceRelayStatus();
  };

  const toggleExit = () => {
    if (!isExitEnabled) setShowExitWarning(true); // confirm before taking on exit risk
    else setExitEnabled(false);
  };

  const switchRoom = (roomId: string) => {
    if (roomId === activeRoomId) return;
    setActiveRoomId(roomId);
    activeRoomIdRef.current = roomId;
    setActiveView(prev => prev === 'voice' ? 'chat' : prev);
    setIsAtBottom(true);
  };

  const addRoom = (def: RoomDef) => {
    setRoomDefs(prev => {
      if (prev.find(d => d.id === def.id)) return prev;
      const next = [...prev, def];
      if (def.isDM) {
        const dmOnly = next.filter(d => d.isDM);
        localStorage.setItem('p2p-dm-rooms', JSON.stringify(dmOnly));
      } else {
        localStorage.setItem('p2p-rooms', JSON.stringify(next.filter(d => !d.isDM)));
      }
      return next;
    });
    if (usernameRef.current) setupRoom(def.id);
  };

  const removeRoom = (roomId: string) => {
    setRoomDefs(prev => {
      const next = prev.filter(d => d.id !== roomId);
      const removedIsDM = prev.find(d => d.id === roomId)?.isDM;
      if (removedIsDM) {
        localStorage.setItem('p2p-dm-rooms', JSON.stringify(next.filter(d => d.isDM)));
      } else {
        localStorage.setItem('p2p-rooms', JSON.stringify(next.filter(d => !d.isDM)));
      }
      return next;
    });
    if (activeRoomId === roomId) switchRoom(DEFAULT_ROOM_ID);
  };

  const openDm = async (targetPeerId: string, targetUsername: string) => {
    setUserContextMenu(null);
    const myKey    = myPublicKeyRef.current;
    const rt       = roomRuntimesRef.current[activeRoomId];
    const theirKey = rt?.peerPublicKeys[targetPeerId];
    if (!myKey || !theirKey) return;
    const keys  = [myKey.slice(0, 24), theirKey.slice(0, 24)].sort();
    const roomId = 'dm-' + keys.join('');
    if (roomRuntimesRef.current[roomId]) { switchRoom(roomId); return; }
    const packet = await encryptMsg({ type: 'dmInvite', fromUsername: username, roomId }, theirKey);
    rt.sendEncMsg?.(packet, targetPeerId);
    addRoom({ id: roomId, label: targetUsername, isDM: true, dmFriend: targetUsername });
    switchRoom(roomId);
  };

  const acceptDmInvite = () => {
    if (!pendingDmInvite) return;
    const { fromUsername, roomId } = pendingDmInvite;
    setPendingDmInvite(null);
    addRoom({ id: roomId, label: fromUsername, isDM: true, dmFriend: fromUsername });
    switchRoom(roomId);
  };

  const handleCreateRoom = () => {
    if (!roomModalLabel.trim()) return;
    const code = generateRoomCode();
    addRoom({ id: code, label: roomModalLabel.trim() });
    setCreatedRoomCode(code);
  };

  const handleJoinRoom = () => {
    const code  = roomModalCode.trim().toUpperCase();
    const label = roomModalLabel.trim() || code;
    if (!code) return;
    addRoom({ id: code, label });
    setShowRoomModal(null);
    setRoomModalLabel('');
    setRoomModalCode('');
  };

  const closeRoomModal = () => {
    setShowRoomModal(null);
    setRoomModalLabel('');
    setRoomModalCode('');
    setCreatedRoomCode('');
  };

  const handleSearch = async (queryOverride?: string) => {
    const q = (queryOverride ?? searchQuery).trim();
    if (!q) return;

    const circuits = findAllCrossRoomCircuits(roomRuntimesRef.current, roomStates);
    const MAX_ATTEMPTS = Math.min(3, circuits.length);
    if (MAX_ATTEMPTS === 0) return;

    const url = `https://lite.duckduckgo.com/lite/?q=${encodeURIComponent(q)}`;
    setActiveView('search');
    setIsSearching(true);
    setSearchError(null);
    setSearchResults([]);
    if (queryOverride !== undefined) setSearchQuery(queryOverride);

    let lastError = '';
    for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
      const { sendRt, circuit, circuitPeerKeys } = circuits[attempt];
      setActiveCircuit(circuit);
      try {
        const packet = await buildOnionPacket(url, circuit, circuitPeerKeys);
        const html = await new Promise<string>((resolve, reject) => {
          const timer = setTimeout(() => {
            if (pendingCircuitsRef.current[packet.circuitId]) {
              delete pendingCircuitsRef.current[packet.circuitId];
              reject('Search timed out — a relay may have gone offline.');
            }
          }, 30_000);
          pendingCircuitsRef.current[packet.circuitId] = {
            resolve: (d: string) => { clearTimeout(timer); resolve(d); },
            reject:  (e: string) => { clearTimeout(timer); reject(e); },
          };
          sendRt.sendRelayFwd?.({ circuitId: packet.circuitId, layer: packet.layer }, circuit[0]);
        });
        setSearchResults(parseSearchResults(html));
        setIsSearching(false);
        return;
      } catch (err) {
        lastError = String(err);
      }
    }

    setSearchError(lastError + (MAX_ATTEMPTS > 1 ? ' (tried multiple circuits)' : ' Try again.'));
    setIsSearching(false);
  };

  const browsePage = async (href: string) => {
    let url = href;
    if (url.startsWith('//')) url = 'https:' + url;
    try {
      const parsed = new URL(url);
      const uddg   = parsed.searchParams.get('uddg');
      if (uddg) {
        const unwrapped = new URL(uddg);
        if (unwrapped.protocol !== 'http:' && unwrapped.protocol !== 'https:') return;
        url = uddg;
      } else {
        if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return;
      }
    } catch { return; }

    const circuits = findAllCrossRoomCircuits(roomRuntimesRef.current, roomStates);
    if (circuits.length === 0) return;

    setIsBrowsing(true);
    setBrowseUrl(url);
    setActiveView('browse');

    const MAX_ATTEMPTS = Math.min(3, circuits.length);
    let lastError = '';
    let html = '';

    for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
      const { sendRt, circuit, circuitPeerKeys } = circuits[attempt];
      setBrowseCircuit(circuit);
      try {
        const packet = await buildOnionPacket(url, circuit, circuitPeerKeys);
        html = await new Promise<string>((resolve, reject) => {
          const timer = setTimeout(() => {
            if (pendingCircuitsRef.current[packet.circuitId]) {
              delete pendingCircuitsRef.current[packet.circuitId];
              reject('Page load timed out.');
            }
          }, 30_000);
          pendingCircuitsRef.current[packet.circuitId] = {
            resolve: (d: string) => { clearTimeout(timer); resolve(d); },
            reject:  (e: string) => { clearTimeout(timer); reject(e); },
          };
          sendRt.sendRelayFwd?.({ circuitId: packet.circuitId, layer: packet.layer }, circuit[0]);
        });
        break; // success
      } catch (err) {
        lastError = String(err);
        html = '';
      }
    }

    try {
      if (!html) throw new Error(lastError);
      const doc = new DOMParser().parseFromString(html, 'text/html');
      const csp = doc.createElement('meta');
      csp.setAttribute('http-equiv', 'Content-Security-Policy');
      // Only the top-level HTML is fetched through the relay circuit. Anything the
      // page itself loads (images, fonts, CSS @import, media, fetch/XHR, frames)
      // would otherwise be requested by THIS WebView directly — from the user's
      // real IP — silently deanonymising them and defeating the whole circuit.
      // So we forbid every remote subresource: nothing but inline styles and
      // data: images may load. Remote images won't render; that's the price of
      // not leaking the user's address.
      csp.setAttribute('content', [
        "default-src 'none'",
        "style-src 'unsafe-inline'",
        "script-src 'unsafe-inline'", // only our injected nav handler; page scripts are stripped below
        "img-src data:",
        "font-src data:",
        "media-src 'none'",
        "connect-src 'none'",
        "form-action 'none'",
        "frame-src 'none'",
        "base-uri 'none'",
      ].join('; '));
      doc.head.prepend(csp);
      // Strip page-controlled scripts and inline event handlers / javascript: URLs
      // so nothing from the fetched page executes except our own click handler.
      doc.querySelectorAll('script').forEach(s => s.remove());
      doc.querySelectorAll('*').forEach(el => {
        for (const attr of [...el.attributes]) {
          const name = attr.name.toLowerCase();
          if (name.startsWith('on')) el.removeAttribute(attr.name);
          else if ((name === 'href' || name === 'src' || name === 'xlink:href')
                   && attr.value.trim().toLowerCase().startsWith('javascript:')) {
            el.removeAttribute(attr.name);
          }
        }
      });
      // Resolve link targets to absolute URLs against the page address so that
      // clicking a relative link still routes the next fetch through a circuit.
      // (We dropped the <base> tag because base-uri 'none' would ignore it.)
      doc.querySelectorAll('a[href]').forEach(a => {
        try { a.setAttribute('href', new URL(a.getAttribute('href')!, url).href); }
        catch { a.removeAttribute('href'); }
      });
      const intercept = doc.createElement('script');
      intercept.textContent = `document.addEventListener('click',function(e){var a=e.target&&e.target.closest&&e.target.closest('a');if(a&&a.href){e.preventDefault();window.parent.postMessage({type:'nav',href:a.href},'*');}});`;
      doc.body?.appendChild(intercept);
      setBrowseHtml(doc.documentElement.outerHTML);
    } catch (err) {
      setBrowseHtml(`<html><body style="background:#36393f;color:#b9bbbe;font-family:sans-serif;padding:40px"><h2>Failed to load</h2><p>${String(err).replace(/</g, '&lt;')}</p></body></html>`);
    } finally {
      setIsBrowsing(false);
    }
  };
  browsePageRef.current = browsePage;

  // ── Computed ──────────────────────────────────────────────────────────────────

  const activeState     = roomStates[activeRoomId] ?? emptyRoomState();
  const activeRuntime   = roomRuntimesRef.current[activeRoomId];
  const onlineList      = [username, ...activeState.peers.map(id => activeState.displayNames[id] ?? `User-${id.slice(0, 6)}`)];
  const isConnected     = activeState.peers.length > 0;
  const activeRoomLabel = roomDefs.find(d => d.id === activeRoomId)?.label ?? activeRoomId;
  const voiceRoomLabel  = voiceRoomId ? (roomDefs.find(d => d.id === voiceRoomId)?.label ?? voiceRoomId) : activeRoomLabel;

  // Count unique relay/exit peers (by public key) across all joined rooms
  const _seenRelayKeys = new Set<string>();
  const _seenExitKeys  = new Set<string>();
  for (const [roomId, rt] of Object.entries(roomRuntimesRef.current)) {
    const state = roomStates[roomId];
    for (const peerId of (state?.availableRelays ?? [])) {
      const k = rt.peerPublicKeys[peerId];
      if (k) _seenRelayKeys.add(k);
    }
    for (const peerId of (state?.availableExits ?? [])) {
      const k = rt.peerPublicKeys[peerId];
      if (k) _seenExitKeys.add(k);
    }
  }
  const globalRelayCount = _seenRelayKeys.size;
  const globalExitCount  = _seenExitKeys.size;
  // A 3-hop circuit needs 3 relays total and at least one opted-in exit as the last hop.
  const canSearch        = globalRelayCount >= 3 && globalExitCount >= 1;

  // Flag username impersonation: a display name claimed by more than one key.
  const _nameKeys: Record<string, Set<string>> = {};
  for (const pid of activeState.peers) {
    const nm = activeState.displayNames[pid];
    const fp = activeState.fingerprints[pid];
    if (nm && fp) (_nameKeys[nm] ??= new Set()).add(fp);
  }
  const dupNames = new Set(Object.entries(_nameKeys).filter(([, s]) => s.size > 1).map(([n]) => n));

  const activeRoomDef = roomDefs.find(d => d.id === activeRoomId);

  // Group consecutive messages by the same author for Discord-style dense layout
  type MsgGroup = { author: string; msgs: Message[] };
  const msgGroups: MsgGroup[] = [];
  for (const m of activeState.messages) {
    const last = msgGroups[msgGroups.length - 1];
    if (last && last.author === m.from) last.msgs.push(m);
    else msgGroups.push({ author: m.from, msgs: [m] });
  }

  // Voice grid participants — always read from the room we're actually in voice in
  const voiceState      = roomStates[voiceRoomId ?? activeRoomId] ?? emptyRoomState();
  const voiceRuntime    = roomRuntimesRef.current[voiceRoomId ?? activeRoomId];
  const voiceParticipants = voiceState.inVoiceUsers.map(name => {
    const displayName = (name === 'You') ? username : name;
    const peerId      = voiceRuntime?.usernamePeer[displayName];
    const speaking    = displayName === username ? isSpeaking : (peerId ? speakingPeers[peerId] ?? false : false);
    const vol         = Math.round((volumesRef.current[displayName] ?? 1) * 100);
    return { name: displayName, isSelf: displayName === username, speaking, muted: displayName === username ? isMuted : false, vol };
  });
  const tileCols = voiceParticipants.length <= 1 ? 1 : 2;
  const tileH    = voiceParticipants.length <= 2 ? 300 : voiceParticipants.length <= 4 ? 210 : 170;

  // ── Render ────────────────────────────────────────────────────────────────────

  if (showSetup) {
    return (
      <div style={{ display:'flex', height:'100vh', background:T.bg, color:T.text, fontFamily:T.font, alignItems:'center', justifyContent:'center' }}>
        <div style={{ background:T.panel, padding:40, borderRadius:T.radius, width:380, textAlign:'center', border:`1px solid ${T.border}` }}>
          <BunLogo size={40} />
          <h2 style={{ margin:'16px 0 8px', fontSize:22, fontWeight:700, color:T.text }}>Welcome to BunChat</h2>
          <p style={{ margin:'0 0 20px', color:T.textMuted, fontSize:13, lineHeight:1.6 }}>
            Choose a username. Relay starts automatically, helping your friends stay connected.
          </p>
          <input ref={usernameInputRef} type="text" placeholder="Enter username" maxLength={18}
            onKeyDown={e => e.key === 'Enter' && saveUsername(usernameInputRef.current?.value ?? '')}
            style={{ width:'100%', padding:'11px 14px', fontSize:14, background:T.panelAlt, border:`1px solid ${T.border}`, borderRadius:T.radiusS, color:T.text, marginBottom:14, boxSizing:'border-box', outline:'none', fontFamily:T.font }}
          />
          <button onClick={() => saveUsername(usernameInputRef.current?.value ?? '')}
            style={{ padding:'11px 32px', background:T.accent, color:T.accentText, border:'none', borderRadius:T.radiusS, fontSize:14, fontWeight:600, cursor:'pointer', fontFamily:T.font }}>
            Join
          </button>
        </div>
      </div>
    );
  }

  // Shared style helpers
  const secHead = { padding:'14px 18px 6px', fontSize:11, fontWeight:600, letterSpacing:1.2, textTransform:'uppercase' as const, color:T.textFaint };
  const modalInput = { width:'100%', padding:'10px', background:T.panelAlt, border:`1px solid ${T.border}`, borderRadius:T.radiusS, color:T.text, fontSize:14, marginBottom:10, boxSizing:'border-box' as const, outline:'none', fontFamily:T.font } as const;
  const modalPrimaryBtn = { width:'100%', padding:'10px', background:T.accent, color:T.accentText, border:'none', borderRadius:T.radiusS, fontSize:14, cursor:'pointer', marginBottom:8, fontWeight:600, fontFamily:T.font } as const;
  const modalCancelBtn  = { width:'100%', padding:'9px', background:'transparent', color:T.textMuted, border:`1px solid ${T.border}`, borderRadius:T.radiusS, fontSize:13, cursor:'pointer', fontFamily:T.font } as const;

  return (
    <div style={{ display:'flex', flexDirection:'column', height:'100vh', background:T.bg, color:T.text, fontFamily:T.font, fontSize:14, letterSpacing:-0.1, overflow:'hidden' }}>

      {/* ── Title bar ── */}
      <div data-tauri-drag-region style={{ height:32, background:T.railBg, borderBottom:`1px solid ${T.border}`, display:'flex', alignItems:'center', padding:'0 12px', flexShrink:0, fontSize:12, color:T.textFaint, fontFamily:T.fontMono, userSelect:'none' }}>
        <BunLogo size={14} />
        <span style={{ marginLeft:8 }}>bunchat</span>
      </div>

      {/* ── 3-column body ── */}
      <div style={{ flex:1, display:'flex', minHeight:0 }}>

        {/* ── Channels column ── */}
        <div style={{ width:248, background:T.panel, borderRight:`1px solid ${T.border}`, display:'flex', flexDirection:'column', flexShrink:0 }}>

          {/* Brand header */}
          <div style={{ padding:'12px 14px', borderBottom:`1px solid ${T.border}`, display:'flex', alignItems:'center', gap:10 }}>
            <BunLogo size={30} />
            <div style={{ flex:1, minWidth:0 }}>
              <div style={{ display:'inline-flex', alignItems:'center', gap:6, background: isConnected ? `${T.online}18` : `${T.danger}18`, border:`1px solid ${isConnected ? T.online+'44' : T.danger+'44'}`, borderRadius:99, padding:'3px 10px 3px 6px' }}>
                <span style={{ width:7, height:7, borderRadius:'50%', background: isConnected ? T.online : T.danger, boxShadow: isConnected ? `0 0 6px ${T.online}` : 'none', flexShrink:0 }} />
                <span style={{ fontSize:12, fontWeight:600, color: isConnected ? T.online : T.danger }}>{isConnected ? 'connected' : 'searching'}</span>
              </div>
              <div style={{ display:'flex', alignItems:'center', gap:5, marginTop:4, paddingLeft:2 }}>
                <IShield width="10" height="10" style={{ color:T.online }} />
                <span style={{ fontSize:11, color:T.textFaint, fontFamily:T.fontMono }}>{activeState.peers.length} peers · encrypted mesh</span>
              </div>
            </div>
          </div>

          {/* Browser entry card */}
          <div onClick={() => setActiveView('search')} style={{ margin:'8px 10px 4px', padding:'10px 12px 12px', borderRadius:T.radius, cursor:'pointer', background: (activeView==='search'||activeView==='browse') ? T.accentSoft : T.bg, border:`1px solid ${(activeView==='search'||activeView==='browse') ? T.accent+'55' : T.border}`, display:'flex', flexDirection:'column', gap:10, transition:'background .12s' }}>
            <div style={{ display:'flex', alignItems:'center', gap:10 }}>
              <div style={{ width:32, height:32, borderRadius:T.radiusS, background: canSearch ? T.accent : T.panelAlt, color: canSearch ? T.accentText : T.textMuted, display:'flex', alignItems:'center', justifyContent:'center', position:'relative', flexShrink:0 }}>
                <IGlobe width="16" height="16" />
                {!canSearch && <div style={{ position:'absolute', right:-3, bottom:-3, width:14, height:14, borderRadius:7, background:T.bg, color:T.danger, display:'flex', alignItems:'center', justifyContent:'center', boxShadow:`0 0 0 2px ${T.bg}` }}><ILock width="8" height="8" /></div>}
              </div>
              <div style={{ flex:1, minWidth:0 }}>
                <div style={{ fontSize:13.5, fontWeight:600, color:T.text, letterSpacing:-0.1 }}>Private browser</div>
                <div style={{ fontSize:11, color:T.textFaint, fontFamily:T.fontMono, marginTop:1 }}>{canSearch ? `${globalRelayCount} peers relaying` : `${globalRelayCount}/3 peers · waiting`}</div>
              </div>
              <span style={{ fontSize:10, fontFamily:T.fontMono, letterSpacing:1, fontWeight:600, padding:'2px 6px', borderRadius:4, color: canSearch ? T.online : T.danger, background: canSearch ? `${T.online}1a` : `${T.danger}1a` }}>{canSearch ? 'READY' : 'LOCKED'}</span>
            </div>
            {!canSearch && <div style={{ display:'flex', gap:4 }}>{[0,1,2].map(i => <div key={i} style={{ flex:1, height:4, borderRadius:2, background: i < globalRelayCount ? T.accent : T.border }} />)}</div>}
            <div style={{ display:'flex', alignItems:'center', gap:8, background: canSearch ? T.panel : T.panelAlt, border:`1px solid ${canSearch ? T.border : 'transparent'}`, borderRadius:T.radiusS, padding:'7px 10px', opacity: canSearch ? 1 : 0.45 }}>
              <ISearch width="12" height="12" style={{ color:T.textFaint, flexShrink:0 }} />
              <input value={searchQuery} onChange={e => setSearchQuery(e.target.value)} onKeyDown={e => e.key==='Enter' && handleSearch()} placeholder={canSearch ? 'Search securely…' : 'Unavailable'} disabled={!canSearch}
                style={{ flex:1, background:'transparent', border:'none', outline:'none', color:T.textFaint, fontSize:13, fontFamily:T.font, padding:0 }} />
              {canSearch && <span style={{ fontFamily:T.fontMono, fontSize:10.5, color:T.textFaint }}>⌘K</span>}
            </div>
          </div>

          {/* Relay card (middle hop — low risk) */}
          <div style={{ margin:'0 10px 4px', padding:'10px 12px', background:T.bg, border:`1px solid ${T.border}`, borderRadius:T.radius, display:'flex', alignItems:'center', gap:10 }}>
            <div style={{ width:28, height:28, borderRadius:T.radiusS, background: isRelayEnabled ? `${T.online}22` : T.panelAlt, color: isRelayEnabled ? T.online : T.textFaint, display:'flex', alignItems:'center', justifyContent:'center', flexShrink:0 }}>
              <IShield width="14" height="14" />
            </div>
            <div style={{ flex:1, minWidth:0 }}>
              <div style={{ fontSize:13, fontWeight:600, color:T.text, letterSpacing:-0.1 }}>Relay (forward only)</div>
              <div style={{ fontSize:11, color:T.textFaint, fontFamily:T.fontMono, marginTop:1 }}>{isRelayEnabled ? 'passes encrypted data · never visits sites' : 'not helping others'}</div>
            </div>
            <Tog on={isRelayEnabled} onClick={toggleRelay} />
          </div>

          {/* Exit card (fetches sites from YOUR IP — opt-in) */}
          <div style={{ margin:'0 10px 4px', padding:'10px 12px', background:T.bg, border:`1px solid ${isExitEnabled ? T.danger+'55' : T.border}`, borderRadius:T.radius, display:'flex', alignItems:'center', gap:10 }}>
            <div style={{ width:28, height:28, borderRadius:T.radiusS, background: isExitEnabled ? `${T.danger}22` : T.panelAlt, color: isExitEnabled ? T.danger : T.textFaint, display:'flex', alignItems:'center', justifyContent:'center', flexShrink:0 }}>
              <IGlobe width="14" height="14" />
            </div>
            <div style={{ flex:1, minWidth:0 }}>
              <div style={{ fontSize:13, fontWeight:600, color:T.text, letterSpacing:-0.1 }}>Exit node</div>
              <div style={{ fontSize:11, color: isExitEnabled ? T.danger : T.textFaint, fontFamily:T.fontMono, marginTop:1 }}>{isExitEnabled ? 'your IP fetches sites for others' : 'off · safest'}</div>
            </div>
            <Tog on={isExitEnabled} onClick={toggleExit} />
          </div>

          {/* Room list */}
          <div style={{ flex:1, overflowY:'auto', paddingBottom:8 }}>
            <div style={secHead}>Rooms</div>
            {roomDefs.filter(d => !d.isDM).map(def => {
              const isAct = activeRoomId === def.id;
              return (
                <div key={def.id} onClick={() => switchRoom(def.id)} style={{ display:'flex', alignItems:'center', gap:10, padding:'7px 10px', margin:'1px 8px', borderRadius:T.radiusS, background: isAct ? T.accentSoft : 'transparent', color: isAct ? T.text : T.textMuted, fontWeight: isAct ? 500 : 400, cursor:'pointer', fontSize:14.5, transition:'background .12s' }}>
                  {def.id === DEFAULT_ROOM_ID ? <IGlobe width="15" height="15" /> : <IHash width="15" height="15" />}
                  <span style={{ flex:1, minWidth:0, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{def.label}</span>
                  {def.id === DEFAULT_ROOM_ID && !isAct && <span style={{ fontSize:12, color:T.textFaint, fontFamily:T.fontMono }}>public</span>}
                  {def.id !== DEFAULT_ROOM_ID && (
                    <button onClick={e => { e.stopPropagation(); removeRoom(def.id); }} style={{ width:20, height:20, borderRadius:10, background:`${T.danger}22`, color:T.danger, border:'none', cursor:'pointer', display:'flex', alignItems:'center', justifyContent:'center', fontSize:14 }}>×</button>
                  )}
                </div>
              );
            })}
            <div style={{ padding:'6px 10px 12px', display:'flex', gap:6 }}>
              <button onClick={() => { setShowRoomModal('create'); setCreatedRoomCode(''); }} style={{ flex:1, padding:'7px 10px', background:T.accent, color:T.accentText, border:'none', borderRadius:T.radiusS, cursor:'pointer', fontSize:12.5, fontWeight:600, fontFamily:T.font, display:'flex', alignItems:'center', justifyContent:'center', gap:5 }}>
                <IPlus width="11" height="11" /> Create
              </button>
              <button onClick={() => setShowRoomModal('join')} style={{ flex:1, padding:'7px 10px', background:T.bg, color:T.text, border:`1px solid ${T.border}`, borderRadius:T.radiusS, cursor:'pointer', fontSize:12.5, fontWeight:600, fontFamily:T.font, display:'flex', alignItems:'center', justifyContent:'center' }}>
                Join with code
              </button>
            </div>

            {/* DMs */}
            {roomDefs.some(d => d.isDM) && (
              <>
                <div style={secHead}>Direct Messages</div>
                {roomDefs.filter(d => d.isDM).map(def => {
                  const isAct = activeRoomId === def.id;
                  const friend = def.dmFriend ?? def.label;
                  return (
                    <div key={def.id} onClick={() => switchRoom(def.id)} style={{ display:'flex', alignItems:'center', gap:10, padding:'7px 10px', margin:'1px 8px', borderRadius:T.radiusS, background: isAct ? T.accentSoft : 'transparent', color: isAct ? T.text : T.textMuted, fontWeight: isAct ? 500 : 400, cursor:'pointer', fontSize:14.5, transition:'background .12s' }}>
                      <Av name={friend} size={20} status="online" />
                      <span style={{ flex:1, minWidth:0, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{friend}</span>
                      <button onClick={e => { e.stopPropagation(); removeRoom(def.id); }} style={{ width:18, height:18, borderRadius:9, background:`${T.danger}22`, color:T.danger, border:'none', cursor:'pointer', display:'flex', alignItems:'center', justifyContent:'center', fontSize:13 }}>×</button>
                    </div>
                  );
                })}
              </>
            )}
          </div>

          {/* User footer */}
          <div style={{ padding:'10px 12px', borderTop:`1px solid ${T.border}`, background:T.railBg, display:'flex', alignItems:'center', gap:10 }}>
            <Av name={username} size={32} status="online" />
            <div style={{ flex:1, minWidth:0 }}>
              <div style={{ fontSize:13.5, fontWeight:600, color:T.text }}>{username}</div>
              <div title="Your safety number — share/compare to verify it's really you" style={{ fontSize:11, color:T.textFaint, fontFamily:T.fontMono, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{myFingerprint ? myFingerprint.slice(0, 11) + '…' : 'online'}</div>
            </div>
            <IBtn title="Mute mic" active={isMuted} onClick={isInVoice ? toggleMute : undefined}>
              {isMuted ? <IMicOff width="14" height="14" /> : <IMic width="14" height="14" />}
            </IBtn>
            <IBtn title="Settings"><ICog width="14" height="14" /></IBtn>
          </div>
        </div>{/* end channels column */}

        {/* ── Main area ── */}
        <div style={{ flex:1, display:'flex', flexDirection:'column', minWidth:0, background:T.bg, position:'relative' }}>

          {/* In-call banner — shown when mic is live but user is browsing chat/search */}
          {isInVoice && activeView !== 'voice' && (
            <div style={{ padding:'6px 20px', background:`${T.speak}18`, borderBottom:`1px solid ${T.speak}28`, display:'flex', alignItems:'center', gap:10, flexShrink:0, fontSize:12, fontFamily:T.fontMono }}>
              <span style={{ width:7, height:7, borderRadius:'50%', background:T.speak, flexShrink:0 }} className="pulse" />
              <span style={{ color:T.speak }}>in call · {callDuration || '00:00:00'}</span>
              {voiceRoomId && voiceRoomId !== activeRoomId && <span style={{ color:T.textFaint }}>— {voiceRoomLabel}</span>}
              <button onClick={() => { if (voiceRoomId && voiceRoomId !== activeRoomId) { setActiveRoomId(voiceRoomId); activeRoomIdRef.current = voiceRoomId; } setActiveView('voice'); }}
                style={{ marginLeft:'auto', padding:'3px 10px', background:T.speak, color:'#000', border:'none', borderRadius:99, fontSize:11, fontWeight:600, cursor:'pointer' }}>
                View call
              </button>
            </div>
          )}

          {activeView === 'voice' ? (<>
            {/* Voice header */}
            <div style={{ height:54, padding:'0 14px 0 20px', borderBottom:`1px solid ${T.border}`, display:'flex', alignItems:'center', gap:12, background:T.bg, flexShrink:0 }}>
              <div style={{ width:26, height:26, borderRadius:T.radiusS, background:T.accentSoft, display:'flex', alignItems:'center', justifyContent:'center' }}><IPhone width="14" height="14" style={{ color:T.accent }} /></div>
              <span style={{ fontSize:17, fontWeight:600, letterSpacing:-0.3, color:T.text }}>Voice · {voiceRoomLabel}</span>
              {callDuration && <span style={{ fontFamily:T.fontMono, fontSize:12, color:T.online }}>● {callDuration} · {voiceParticipants.length} in call</span>}
              <button onClick={() => setActiveView('chat')} title="Back to chat" style={{ marginLeft:'auto', width:32, height:32, borderRadius:T.radiusS, background:T.accentSoft, color:T.accent, border:'none', cursor:'pointer', display:'flex', alignItems:'center', justifyContent:'center' }}>
                <IBack width="14" height="14" />
              </button>
            </div>
            {/* Voice grid */}
            <div style={{ flex:1, padding:16, display:'grid', gridTemplateColumns:`repeat(${tileCols}, 1fr)`, gap:12, overflowY:'auto' }}>
              {voiceParticipants.map(p => (
                <VoiceTile key={p.name} name={p.name} isSelf={p.isSelf} speaking={p.speaking} muted={p.muted} volume={p.vol} tileH={tileH} onVol={v => changeVolume(p.name, v)} />
              ))}
            </div>
            {/* Call dock */}
            <div style={{ padding:'14px 20px 18px', borderTop:`1px solid ${T.border}`, background:T.panel, display:'flex', alignItems:'center', justifyContent:'center', gap:12, flexShrink:0 }}>
              <button onClick={toggleMute} style={{ width:46, height:46, borderRadius:23, background: isMuted ? T.danger : T.panelAlt, color: isMuted ? '#fff' : T.textMuted, border:'none', cursor:'pointer', display:'flex', alignItems:'center', justifyContent:'center' }}>
                {isMuted ? <IMicOff width="18" height="18" /> : <IMic width="18" height="18" />}
              </button>
              <div style={{ width:12 }} />
              <button onClick={toggleVoice} style={{ width:46, height:46, borderRadius:23, background:T.danger, color:'#fff', border:'none', cursor:'pointer', display:'flex', alignItems:'center', justifyContent:'center' }}>
                <IHangup width="20" height="20" />
              </button>
            </div>
          </>) : activeView === 'browse' ? (<>
            {/* Browser chrome */}
            <div style={{ padding:'10px 14px', background:T.panel, borderBottom:`1px solid ${T.border}`, display:'flex', alignItems:'center', gap:8, flexShrink:0 }}>
              <IBtn onClick={() => setActiveView('search')}><IBack width="14" height="14" /></IBtn>
              <IBtn><IFwd width="14" height="14" /></IBtn>
              <IBtn><IReload width="14" height="14" /></IBtn>
              <div style={{ flex:1, display:'flex', alignItems:'center', gap:8, background:T.bg, border:`1px solid ${T.border}`, borderRadius:99, padding:'7px 14px', minWidth:0 }}>
                <ILock width="11" height="11" style={{ color:T.online, flexShrink:0 }} />
                <span style={{ fontFamily:T.fontMono, fontSize:10.5, letterSpacing:1, color:T.online, fontWeight:600, flexShrink:0 }}>SECURE</span>
                <span style={{ width:1, height:12, background:T.border, flexShrink:0 }} />
                <span style={{ color:T.text, fontSize:13, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{browseUrl}</span>
              </div>
            </div>
            <div style={{ flex:1, position:'relative', overflow:'hidden' }}>
              {isBrowsing && <div style={{ position:'absolute', inset:0, background:T.bg, display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center', gap:14, color:T.textFaint, fontSize:13, zIndex:1 }}><div className="spinner" />Loading through relays…</div>}
              <iframe srcDoc={browseHtml} sandbox="allow-scripts" style={{ width:'100%', height:'100%', border:'none', background:'white' }} title="Browse" />
            </div>
          </>) : activeView === 'search' && !canSearch ? (
            /* Browser locked */
            <div style={{ flex:1, display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center', padding:'40px 60px', gap:24, background:T.bg }}>
              <div style={{ width:84, height:84, borderRadius:42, background:T.accentSoft, display:'flex', alignItems:'center', justifyContent:'center', boxShadow:`0 0 0 16px ${T.accentSoft}55` }}>
                <IShield width="40" height="40" style={{ color:T.accent }} />
              </div>
              <div style={{ textAlign:'center' }}>
                <h2 style={{ margin:'0 0 10px', fontSize:26, fontWeight:700, letterSpacing:-0.5, color:T.text }}>The browser needs friends.</h2>
                <p style={{ margin:0, fontSize:15, color:T.textMuted, lineHeight:1.6, maxWidth:420 }}>BunChat routes traffic through other peers. We need <strong style={{ color:T.text }}>3 peers online</strong> and <strong style={{ color:T.text }}>at least one willing to be an exit node</strong> before the browser can open.{globalExitCount === 0 && globalRelayCount >= 3 ? ' (Enough peers — but none are exit nodes yet.)' : ''}</p>
              </div>
              <div style={{ width:'100%', maxWidth:360, background:T.panel, border:`1px solid ${T.border}`, borderRadius:T.radius, padding:'20px 24px', display:'flex', flexDirection:'column', gap:12 }}>
                <div style={{ display:'flex', alignItems:'baseline', gap:6 }}>
                  <span style={{ fontFamily:T.fontMono, fontWeight:700, color:T.accent, fontSize:32 }}>{globalRelayCount}</span>
                  <span style={{ fontFamily:T.fontMono, color:T.textFaint }}>/3 peers online</span>
                </div>
                <div style={{ display:'flex', gap:6 }}>{[0,1,2].map(i => <div key={i} style={{ flex:1, height:6, borderRadius:3, background: i < globalRelayCount ? T.accent : T.border }} />)}</div>
                <div style={{ display:'flex', alignItems:'center', gap:8, color:T.textFaint, fontSize:13, fontFamily:T.fontMono }}>
                  <span className="pulse" style={{ width:8, height:8, borderRadius:4, background:T.accent, flexShrink:0 }} />
                  searching for peers…
                </div>
              </div>
              <button onClick={() => setActiveView('chat')} style={{ padding:'10px 24px', background:T.accent, color:T.accentText, border:'none', borderRadius:T.radiusS, fontSize:14, fontWeight:600, cursor:'pointer', fontFamily:T.font }}>Back to chat</button>
            </div>
          ) : activeView === 'search' ? (<>
            {/* Search header */}
            <div style={{ height:54, padding:'0 14px', borderBottom:`1px solid ${T.border}`, display:'flex', alignItems:'center', gap:8, background:T.bg, flexShrink:0 }}>
              <IBtn onClick={() => setActiveView('chat')}><IBack width="14" height="14" /></IBtn>
              <input value={searchQuery} onChange={e => setSearchQuery(e.target.value)} onKeyDown={e => e.key==='Enter' && handleSearch()} placeholder="Refine search…"
                style={{ flex:1, background:T.panelAlt, border:`1px solid ${T.border}`, borderRadius:T.radiusS, padding:'6px 12px', color:T.text, fontSize:13, fontFamily:T.font, outline:'none' }} />
              <button onClick={() => handleSearch()} disabled={isSearching} style={{ padding:'7px 14px', background:T.accent, color:T.accentText, border:'none', borderRadius:T.radiusS, fontSize:13, fontWeight:600, cursor:'pointer', fontFamily:T.font, opacity: isSearching ? 0.6 : 1 }}>{isSearching ? '…' : 'Go'}</button>
            </div>
            {/* Search results */}
            <div style={{ flex:1, padding:'16px 20px', overflowY:'auto' }}>
              {isSearching && <div style={{ display:'flex', flexDirection:'column', alignItems:'center', gap:14, padding:'48px 0', color:T.textFaint, fontSize:13 }}><div className="spinner" />Routing through relays…</div>}
              {searchError && <div style={{ color:T.danger, padding:14, background:T.panelAlt, borderRadius:T.radiusS, fontSize:13 }}>{searchError}</div>}
              {!isSearching && !searchError && searchResults.length === 0 && <div style={{ color:T.textFaint, padding:'40px 0', textAlign:'center', fontSize:13 }}>No results found</div>}
              {searchResults.map((r, i) => (
                <div key={i} style={{ marginBottom:20, paddingBottom:20, borderBottom:`1px solid ${T.border}` }}>
                  <div style={{ color:T.accent, fontWeight:600, fontSize:14, marginBottom:3, cursor:'pointer' }} onClick={() => browsePage(r.href)}>{r.title}</div>
                  <div style={{ color:T.online, fontSize:12, marginBottom:5, cursor:'pointer', fontFamily:T.fontMono }} onClick={() => browsePage(r.href)}>{r.url}</div>
                  <div style={{ color:T.textMuted, fontSize:13, lineHeight:1.5 }}>{r.snippet}</div>
                </div>
              ))}
            </div>
          </>) : (<>
            {/* Channel header */}
            <div style={{ height:54, padding:'0 20px', borderBottom:`1px solid ${T.border}`, display:'flex', alignItems:'center', gap:12, background:T.bg, flexShrink:0 }}>
              {activeRoomDef?.isDM ? <Av name={activeRoomDef.dmFriend ?? activeRoomLabel} size={26} /> : <IGlobe width="17" height="17" style={{ color:T.textMuted }} />}
              <span style={{ fontSize:17, fontWeight:600, letterSpacing:-0.3, color:T.text }}>{activeRoomLabel}</span>
              <span style={{ display:'inline-flex', alignItems:'center', gap:4, color:T.textFaint, fontSize:12 }}><ILock width="11" height="11" /><span style={{ fontFamily:T.fontMono }}>e2e</span></span>
              {activeRoomDef?.isDM && <span style={{ fontSize:13, color:T.textFaint }}>{isConnected ? 'online · direct peer' : 'waiting…'}</span>}
            </div>
            {/* Message list */}
            <div ref={messageListRef} style={{ flex:1, overflowY:'auto', padding:'8px 0' }} onScroll={handleScroll}>
              {msgGroups.map(g =>
                g.msgs.map((m, mi) => {
                  const isMe = m.from === 'You';
                  const dispName = isMe ? username : m.from;
                  const hue = hueForName(dispName);
                  return mi === 0 ? (
                    <div key={m.id} style={{ display:'flex', gap:14, padding:'8px 20px 4px', alignItems:'flex-start' }}>
                      <Av name={dispName} size={36} />
                      <div style={{ flex:1, minWidth:0 }}>
                        <div style={{ display:'flex', alignItems:'baseline', gap:8, marginBottom:2 }}>
                          <span style={{ fontSize:14.5, fontWeight:600, color:`oklch(0.78 0.10 ${hue})` }}>{dispName}</span>
                          <span style={{ fontSize:11, color:T.textFaint, fontFamily:T.fontMono }}>{formatTime(m.ts)}</span>
                          {isMe && <span style={{ fontSize:10, fontFamily:T.fontMono, color:T.accent, background:T.accentSoft, padding:'1px 5px', borderRadius:4 }}>you</span>}
                          {m.synced && <span title="Imported from a peer's history — authorship is not verified" style={{ fontSize:10, fontFamily:T.fontMono, color:T.textFaint, background:T.panelAlt, padding:'1px 5px', borderRadius:4 }}>synced · unverified</span>}
                        </div>
                        <div style={{ color:T.text, fontSize:14.5, lineHeight:1.55 }}>{m.text}</div>
                      </div>
                    </div>
                  ) : (
                    <div key={m.id} style={{ padding:'2px 20px 2px 70px' }}>
                      <span style={{ color:T.text, fontSize:14.5, lineHeight:1.5 }}>{m.text}</span>
                    </div>
                  );
                })
              )}
            </div>
            {!isAtBottom && <button style={{ position:'absolute', bottom:80, right:16, background:T.accent, color:T.accentText, border:'none', borderRadius:'50%', width:32, height:32, cursor:'pointer', display:'flex', alignItems:'center', justifyContent:'center', boxShadow:'0 2px 8px rgba(0,0,0,.4)', zIndex:10, fontSize:14 }} onClick={scrollToBottom}>↓</button>}
            {/* Composer */}
            <div style={{ padding:'0 20px 16px', flexShrink:0 }}>
              <div style={{ background:`color-mix(in srgb, ${T.panelAlt} 85%, ${T.accent} 15%)`, border:`1px solid ${T.accent}2e`, borderRadius:T.radius, padding:'4px 6px 4px 10px', display:'flex', alignItems:'center', gap:6 }}>
                <input value={newMessage} onChange={e => setNewMessage(e.target.value.slice(0,800))} onKeyDown={e => e.key==='Enter' && sendMessage()} placeholder={`Message ${activeRoomDef?.isDM ? activeRoomLabel : '#'+activeRoomLabel}`} maxLength={800}
                  style={{ flex:1, background:'transparent', border:'none', outline:'none', color:T.text, fontSize:14.5, padding:'10px 4px', fontFamily:T.font }} />
                <button onClick={sendMessage} style={{ width:32, height:32, borderRadius:T.radiusS, background:T.accent, color:T.accentText, border:'none', cursor:'pointer', display:'flex', alignItems:'center', justifyContent:'center' }}><ISend width="14" height="14" /></button>
              </div>
              <div style={{ display:'flex', alignItems:'center', gap:6, padding:'6px 4px 0', color:T.textFaint, fontSize:11, fontFamily:T.fontMono }}>
                <ILock width="10" height="10" /><span>end-to-end · routed via {globalRelayCount} peers</span>
              </div>
            </div>
          </>)}

        </div>{/* end main area */}

        {/* ── Right rail ── */}
        <aside style={{ width:280, background:T.panel, borderLeft:`1px solid ${T.border}`, display:'flex', flexDirection:'column', flexShrink:0, overflow:'hidden' }}>
          {activeView === 'voice' ? (<>
            <div style={{ padding:'14px 16px', borderBottom:`1px solid ${T.border}` }}>
              <div style={{ fontSize:13.5, fontWeight:600, color:T.text }}>In call</div>
              <div style={{ fontSize:11, color:T.textFaint, fontFamily:T.fontMono, marginTop:2 }}>{voiceParticipants.length} participants</div>
            </div>
            <div style={{ flex:1, overflowY:'auto', padding:'8px 0' }}>
              {voiceParticipants.map(p => (
                <div key={p.name} style={{ padding:'6px 18px', display:'flex', alignItems:'center', gap:10 }}>
                  <Av name={p.name} size={28} speaking={p.speaking} />
                  <span style={{ flex:1, fontSize:13.5, color:T.text }}>{p.name}</span>
                  {p.muted && <IMicOff width="13" height="13" style={{ color:T.danger }} />}
                </div>
              ))}
            </div>
            <div style={{ padding:'8px 12px 12px', borderTop:`1px solid ${T.border}`, fontSize:11, color:T.textFaint, fontFamily:T.fontMono }}>hover any tile to set volume (0–200%)</div>
          </>) : (activeView === 'search' || activeView === 'browse') ? (<>
            <div style={{ padding:'14px 16px', borderBottom:`1px solid ${T.border}` }}>
              <div style={{ fontSize:11, fontWeight:600, letterSpacing:1.2, textTransform:'uppercase', color:T.textFaint, marginBottom:10 }}>Browser status</div>
              <div style={{ textAlign:'center', marginBottom:14 }}>
                <div style={{ fontSize:48, fontWeight:700, color:T.accent, fontFamily:T.fontMono }}>{globalRelayCount}</div>
                <div style={{ fontSize:12, color:T.textFaint, marginTop:4 }}>relaying your traffic right now</div>
              </div>
              {[['Identity','hidden'],['Path','randomised'],['Encryption','layered (onion)']].map(([k,v]) => (
                <div key={k} style={{ display:'flex', justifyContent:'space-between', fontSize:12, marginBottom:6 }}>
                  <span style={{ color:T.textFaint }}>{k}</span><span style={{ color:T.text, fontFamily:T.fontMono }}>{v}</span>
                </div>
              ))}
            </div>
            <div style={{ flex:1, padding:'12px 14px', fontSize:11, color:T.textFaint, fontFamily:T.fontMono, lineHeight:1.6, background:T.bg, margin:'10px 14px', borderRadius:T.radiusS, border:`1px solid ${T.border}` }}>
              for safety, the specific peers relaying for you are never shown — even to you.
            </div>
          </>) : (<>
            {/* Join/leave voice */}
            <div style={{ padding:'14px 16px', borderBottom:`1px solid ${T.border}`, display:'flex', flexDirection:'column', gap:8 }}>
              {isInVoice && (
                <button onClick={() => { if (voiceRoomId && voiceRoomId !== activeRoomId) { setActiveRoomId(voiceRoomId); activeRoomIdRef.current = voiceRoomId; } setActiveView('voice'); }}
                  style={{ width:'100%', padding:'8px 14px', background:T.accentSoft, color:T.text, border:`1px solid ${T.accent}44`, borderRadius:T.radius, cursor:'pointer', fontSize:13, fontWeight:600, fontFamily:T.font, display:'flex', alignItems:'center', justifyContent:'center', gap:8 }}>
                  <IPhone width="13" height="13" style={{ color:T.accent }} /> View call
                </button>
              )}
              <button onClick={toggleVoice} style={{ width:'100%', padding:'11px 14px', background: isInVoice ? T.danger : T.accent, color: isInVoice ? '#fff' : T.accentText, border:'none', borderRadius:T.radius, cursor:'pointer', fontSize:14, fontWeight:600, fontFamily:T.font, display:'flex', alignItems:'center', justifyContent:'center', gap:8 }}>
                {isInVoice ? <IHangup width="14" height="14" /> : <IPhone width="14" height="14" />}
                {isInVoice ? 'Leave voice' : 'Join voice'}
                {!isInVoice && activeState.inVoiceUsers.length > 0 && <span style={{ fontFamily:T.fontMono, fontSize:11.5, background:'rgba(0,0,0,.18)', padding:'1px 6px', borderRadius:99 }}>{activeState.inVoiceUsers.length} in call</span>}
              </button>
            </div>
            {/* Members */}
            <div style={{ flex:1, overflowY:'auto' }}>
              <div style={{ ...secHead, display:'flex', alignItems:'center', gap:6 }}>
                <span style={{ width:6, height:6, borderRadius:'50%', background:T.online }} />
                Online — {onlineList.length}
              </div>
              {onlineList.map(name => {
                const dispN = name === username ? username : name;
                const inVoice = activeState.inVoiceUsers.includes(name) || (name === username && isInVoice);
                const pid = name === username ? null : activeRuntime?.usernamePeer[name];
                const fp = name === username ? myFingerprint : (pid ? activeState.fingerprints[pid] : undefined);
                const shortFp = fp ? fp.slice(0, 11) : '';
                const impersonated = dupNames.has(name);
                return (
                  <button key={name} style={{ width:'100%', padding:'6px 18px', display:'flex', alignItems:'center', gap:10, background:'none', border:'none', cursor: name !== username ? 'pointer' : 'default', textAlign:'left', color:T.text }}
                    onClick={e => { if (name === username) return; const p = activeRuntime?.usernamePeer[name]; if (!p) return; setUserContextMenu({ username: name, peerId: p, x: e.clientX, y: e.clientY }); }}>
                    <Av name={dispN} size={28} status={inVoice ? 'voice' : 'online'} />
                    <div style={{ flex:1, minWidth:0 }}>
                      <span style={{ fontSize:13.5, color:T.text }}>{dispN}{name === username && <span style={{ color:T.textFaint }}> · you</span>}
                        {impersonated && <span title="This name is used by more than one key — verify the safety number" style={{ marginLeft:6, color:T.danger, fontSize:11 }}>⚠ name reused</span>}
                      </span>
                      {shortFp && <div style={{ fontSize:10, fontFamily:T.fontMono, color:T.textFaint, marginTop:1 }}>{shortFp}…</div>}
                    </div>
                  </button>
                );
              })}
            </div>
            {/* Room actions */}
            <div style={{ padding:'10px 16px 14px', borderTop:`1px solid ${T.border}` }}>
              <div style={{ fontSize:11, letterSpacing:1.2, textTransform:'uppercase', fontWeight:600, color:T.textFaint, marginBottom:8 }}>Room</div>
              <button onClick={saveChat} style={{ width:'100%', padding:'9px 12px', background:T.bg, border:`1px solid ${T.border}`, borderRadius:T.radiusS, color:T.text, cursor:'pointer', fontSize:12.5, fontWeight:600, fontFamily:T.font, display:'flex', alignItems:'center', gap:8, marginBottom:6 }}>
                <ICopy width="13" height="13" style={{ color:T.textMuted }} /> Save chat to file
              </button>
              <div style={{ display:'flex', alignItems:'center', gap:8, padding:'8px 12px', marginBottom:6, background:T.bg, border:`1px solid ${T.border}`, borderRadius:T.radiusS }}>
                <IShield width="13" height="13" style={{ color: acceptHistory ? T.online : T.textFaint }} />
                <div style={{ flex:1, minWidth:0 }}>
                  <div style={{ fontSize:12.5, fontWeight:600, color:T.text }}>History</div>
                  <div style={{ fontSize:10.5, color:T.textFaint, fontFamily:T.fontMono, marginTop:1 }}>{acceptHistory ? 'saved locally' : 'not saved'}</div>
                </div>
                <Tog on={acceptHistory} onClick={toggleAcceptHistory} />
              </div>
              <button onClick={deleteLog} style={{ width:'100%', padding:'8px 12px', background:'transparent', color:T.danger, border:`1px solid ${T.danger}33`, borderRadius:T.radiusS, cursor:'pointer', fontSize:12.5, fontWeight:600, fontFamily:T.font, display:'flex', alignItems:'center', justifyContent:'center' }}>Delete log</button>
            </div>
          </>)}
        </aside>

      </div>{/* end 3-column body */}

      {/* ── Room modal ── */}
      {showRoomModal && (
        <div style={{ position:'fixed', inset:0, background:'rgba(0,0,0,.75)', display:'flex', alignItems:'center', justifyContent:'center', zIndex:200 }} onClick={closeRoomModal}>
          <div style={{ background:T.panel, padding:28, borderRadius:T.radius, width:340, boxShadow:'0 8px 32px rgba(0,0,0,.5)', border:`1px solid ${T.border}` }} onClick={e => e.stopPropagation()}>
            {showRoomModal === 'create' && !createdRoomCode && (<>
              <p style={{ margin:'0 0 18px', fontSize:16, fontWeight:700, color:T.text }}>Create a Room</p>
              <input autoFocus placeholder="Room name (e.g. Gaming Squad)" value={roomModalLabel} onChange={e => setRoomModalLabel(e.target.value)} onKeyDown={e => e.key==='Enter' && handleCreateRoom()} style={modalInput} />
              <button onClick={handleCreateRoom} style={modalPrimaryBtn}>Create</button>
              <button onClick={closeRoomModal} style={modalCancelBtn}>Cancel</button>
            </>)}
            {showRoomModal === 'create' && createdRoomCode && (<>
              <p style={{ margin:'0 0 8px', fontSize:16, fontWeight:700, color:T.text }}>Room Created!</p>
              <p style={{ margin:'0 0 16px', fontSize:12, color:T.textMuted, lineHeight:1.5 }}>Share this code with anyone you want to invite.</p>
              <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', background:T.panelAlt, padding:'12px 14px', borderRadius:T.radiusS, marginBottom:16 }}>
                <span style={{ fontFamily:T.fontMono, fontSize:18, letterSpacing:3, color:T.text, fontWeight:700 }}>{createdRoomCode}</span>
                <button onClick={() => navigator.clipboard.writeText(createdRoomCode)} style={{ padding:'4px 10px', background:T.accent, color:T.accentText, border:'none', borderRadius:T.radiusS, fontSize:12, cursor:'pointer' }}>Copy</button>
              </div>
              <button onClick={closeRoomModal} style={modalPrimaryBtn}>Done</button>
            </>)}
            {showRoomModal === 'join' && (<>
              <p style={{ margin:'0 0 18px', fontSize:16, fontWeight:700, color:T.text }}>Join a Room</p>
              <input autoFocus placeholder="Invite code (e.g. ABCD-EFGH)" value={roomModalCode} onChange={e => setRoomModalCode(e.target.value)} onKeyDown={e => e.key==='Enter' && handleJoinRoom()} style={modalInput} />
              <input placeholder="Room name (optional)" value={roomModalLabel} onChange={e => setRoomModalLabel(e.target.value)} onKeyDown={e => e.key==='Enter' && handleJoinRoom()} style={modalInput} />
              <button onClick={handleJoinRoom} style={modalPrimaryBtn}>Join</button>
              <button onClick={closeRoomModal} style={modalCancelBtn}>Cancel</button>
            </>)}
          </div>
        </div>
      )}

      {/* ── User context menu ── */}
      {userContextMenu && (
        <div style={{ position:'fixed', left:userContextMenu.x, top:userContextMenu.y, background:T.panelAlt, border:`1px solid ${T.borderStrong}`, borderRadius:T.radius, padding:4, zIndex:300, boxShadow:'0 12px 40px rgba(0,0,0,.35)', minWidth:160 }} onMouseLeave={() => setUserContextMenu(null)}>
          <div style={{ padding:'6px 10px 4px', fontSize:11, color:T.textFaint, fontFamily:T.fontMono, fontWeight:600, letterSpacing:0.5 }}>{userContextMenu.username}</div>
          <button style={{ display:'block', width:'100%', padding:'8px 12px', background:'none', border:'none', color:T.text, fontSize:13.5, cursor:'pointer', borderRadius:T.radiusS, textAlign:'left', fontFamily:T.font }}
            onMouseEnter={e => (e.currentTarget.style.background = T.accentSoft)}
            onMouseLeave={e => (e.currentTarget.style.background = 'none')}
            onClick={() => openDm(userContextMenu.peerId, userContextMenu.username)}>
            Message
          </button>
          {menuSafety && (
            <div style={{ padding:'8px 12px 6px', borderTop:`1px solid ${T.border}`, marginTop:4 }}>
              <div style={{ fontSize:10, color:T.textFaint, fontFamily:T.fontMono, letterSpacing:0.5, marginBottom:3 }}>SAFETY NUMBER</div>
              <div style={{ fontSize:12, color:T.text, fontFamily:T.fontMono, lineHeight:1.4 }}>{menuSafety}</div>
              <div style={{ fontSize:10, color:T.textFaint, marginTop:4, lineHeight:1.4 }}>Read this aloud together (e.g. in voice). If it matches on both sides, no one is intercepting.</div>
            </div>
          )}
        </div>
      )}

      {/* ── Exit-node warning ── */}
      {showExitWarning && (
        <div style={{ position:'fixed', inset:0, background:'rgba(0,0,0,.78)', display:'flex', alignItems:'center', justifyContent:'center', zIndex:400 }} onClick={() => setShowExitWarning(false)}>
          <div style={{ background:T.panel, padding:28, borderRadius:T.radius, width:430, boxShadow:'0 8px 32px rgba(0,0,0,.5)', border:`1px solid ${T.danger}55` }} onClick={e => e.stopPropagation()}>
            <div style={{ display:'flex', alignItems:'center', gap:10, marginBottom:14 }}>
              <div style={{ width:34, height:34, borderRadius:T.radiusS, background:`${T.danger}22`, color:T.danger, display:'flex', alignItems:'center', justifyContent:'center', flexShrink:0 }}><IGlobe width="18" height="18" /></div>
              <p style={{ margin:0, fontSize:17, fontWeight:700, color:T.text }}>Turn on Exit node?</p>
            </div>
            <p style={{ margin:'0 0 12px', fontSize:13, color:T.textMuted, lineHeight:1.6 }}>
              As an <strong style={{ color:T.text }}>exit node</strong>, your computer makes the actual web
              request for other people, <strong style={{ color:T.text }}>from your own IP address</strong>.
              The websites others visit will appear in logs as coming from <strong style={{ color:T.text }}>you</strong>.
            </p>
            <p style={{ margin:'0 0 12px', fontSize:13, color:T.textMuted, lineHeight:1.6 }}>
              If someone routes traffic to an illegal site through you, your IP is what shows up there — this is the
              same risk Tor exit-node operators take on. You cannot see or control what others browse.
            </p>
            <p style={{ margin:'0 0 18px', fontSize:12.5, color:T.textFaint, lineHeight:1.6 }}>
              Leaving this <strong style={{ color:T.online }}>off</strong> still lets you help as a forward-only
              relay (you only pass along encrypted data and never visit any site). Only enable exit if you
              understand and accept the risk.
            </p>
            <button onClick={() => { setShowExitWarning(false); setExitEnabled(true); }}
              style={{ width:'100%', padding:'11px', background:T.danger, color:'#fff', border:'none', borderRadius:T.radiusS, fontSize:14, fontWeight:600, cursor:'pointer', marginBottom:8, fontFamily:T.font }}>
              I understand the risk — enable exit
            </button>
            <button onClick={() => setShowExitWarning(false)} style={modalCancelBtn}>Keep it off (recommended)</button>
          </div>
        </div>
      )}

      {/* ── DM invite banner ── */}
      {pendingDmInvite && (
        <div style={{ position:'fixed', bottom:24, right:24, background:T.panel, border:`1px solid ${T.accent}55`, borderRadius:T.radius, padding:'14px 18px', zIndex:300, boxShadow:'0 4px 20px rgba(0,0,0,.6)', minWidth:240 }}>
          <p style={{ margin:'0 0 4px', fontSize:14, fontWeight:700, color:T.text }}>Friend request</p>
          <p style={{ margin:'0 0 12px', fontSize:12, color:T.textMuted }}>{pendingDmInvite.fromUsername} wants to message you</p>
          <div style={{ display:'flex', gap:8 }}>
            <button style={{ flex:1, padding:9, background:T.accent, color:T.accentText, border:'none', borderRadius:T.radiusS, cursor:'pointer', fontWeight:600, fontFamily:T.font }} onClick={acceptDmInvite}>Accept</button>
            <button style={{ flex:1, padding:9, background:'transparent', color:T.textMuted, border:`1px solid ${T.border}`, borderRadius:T.radiusS, cursor:'pointer', fontFamily:T.font }} onClick={() => setPendingDmInvite(null)}>Decline</button>
          </div>
        </div>
      )}

    </div>
  );
}

export default App;
