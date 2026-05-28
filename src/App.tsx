import { useState, useEffect, useRef, useCallback, type CSSProperties } from 'react';
import { joinRoom } from 'trystero';
import { invoke } from '@tauri-apps/api/core';
import { isPermissionGranted, requestPermission, sendNotification } from '@tauri-apps/plugin-notification';
import { getCurrentWindow } from '@tauri-apps/api/window';

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

interface PeerKeyMessage     { publicKeyBase64: string }

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
interface Message       { id: string; from: string; text: string; ts: number }
interface RelayPeerInfo { pubKey: string; rooms: Array<{ roomId: string; peerId: string; rt: RoomRuntime }> }

interface RoomDef { id: string; label: string; isDM?: boolean; dmFriend?: string }

// Encrypted envelope sent over the wire for all non-relay, non-key messages
interface EncMsgPacket { enc: EncryptedLayer }

type EncMsgPayload =
  | { type: 'chat';        username: string; text: string }
  | { type: 'username';    username: string }
  | { type: 'voiceStatus'; username: string; inVoice: boolean }
  | { type: 'relayAvail';  isRelay: boolean }
  | { type: 'dmInvite';    fromUsername: string; roomId: string }
  | { type: 'relayBatch';  deliveries: Array<{ peerId: string; enc: EncryptedLayer }> }
  | { type: 'chatHistory'; messages: Array<{ id: string; from: string; text: string; ts: number }> };

interface RoomReactState {
  peers:           string[];
  displayNames:    Record<string, string>;
  messages:        Message[];
  inVoiceUsers:    string[];
  availableRelays: string[];
  isInVoice:       boolean;
}

interface RoomRuntime {
  trysteroRoom:    any;
  sendEncMsg:      ((d: EncMsgPacket,        t?: string | string[]) => void) | null;
  sendPeerKey:     ((d: PeerKeyMessage,      t?: string | string[]) => void) | null;
  sendRelayFwd:    ((d: OnionForwardPacket,  t?: string | string[]) => void) | null;
  sendRelayResp:   ((d: OnionResponsePacket, t?: string | string[]) => void) | null;
  peerPublicKeys:  Record<string, string>;
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

// Sends `payload` to every peer in `rt`, routing through a random mixer when
// there are 2+ peers so that a network observer only sees traffic from us to
// one peer, not to all of them directly.
async function sendEncryptedToAll(rt: RoomRuntime, payload: EncMsgPayload): Promise<void> {
  const entries = Object.entries(rt.peerPublicKeys);
  if (entries.length === 0) return;

  if (entries.length === 1) {
    const [peerId, pubKey] = entries[0];
    const enc = await encryptForPeer(addPadding(JSON.stringify(payload)), pubKey);
    rt.sendEncMsg?.({ enc }, peerId);
    return;
  }

  // Pick a random peer as the one-hop mixer.
  const mixerIdx                   = Math.floor(Math.random() * entries.length);
  const [mixerPeerId, mixerPubKey] = entries[mixerIdx];
  const others                     = entries.filter((_, i) => i !== mixerIdx);

  // Encrypt the payload individually for every non-mixer peer.
  const deliveries = await Promise.all(
    others.map(async ([peerId, pubKey]) => ({
      peerId,
      enc: await encryptForPeer(addPadding(JSON.stringify(payload)), pubKey),
    }))
  );

  // Send the mixer a batch to forward to everyone else.
  const batchEnc = await encryptForPeer(
    addPadding(JSON.stringify({ type: 'relayBatch' as const, deliveries })),
    mixerPubKey
  );
  rt.sendEncMsg?.({ enc: batchEnc }, mixerPeerId);

  // Also send the mixer their own copy (they don't forward to themselves).
  const mixerEnc = await encryptForPeer(addPadding(JSON.stringify(payload)), mixerPubKey);
  rt.sendEncMsg?.({ enc: mixerEnc }, mixerPeerId);
}

// Sends `payload` directly to every peer without mixing — used for presence
// messages where peerId attribution must be the true sender, not a forwarder.
async function sendDirectToAll(rt: RoomRuntime, payload: EncMsgPayload): Promise<void> {
  await Promise.all(
    Object.entries(rt.peerPublicKeys).map(async ([peerId, pubKey]) => {
      const pkt = await encryptMsg(payload, pubKey);
      rt.sendEncMsg?.(pkt, peerId);
    })
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

function generateRoomCode(): string {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const pick = (n: number) =>
    Array.from({ length: n }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
  return `${pick(4)}-${pick(4)}`;
}

function emptyRoomState(): RoomReactState {
  return { peers: [], displayNames: {}, messages: [], inVoiceUsers: [], availableRelays: [], isInVoice: false };
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
  for (const [roomId, rt] of Object.entries(roomRuntimes)) {
    const state = roomStatesSnap[roomId];
    for (const peerId of (state?.availableRelays ?? [])) {
      const pubKey = rt.peerPublicKeys[peerId];
      if (!pubKey) continue;
      if (!byPubKey.has(pubKey)) byPubKey.set(pubKey, { pubKey, rooms: [] });
      byPubKey.get(pubKey)!.rooms.push({ roomId, peerId, rt });
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
  return results.sort(() => Math.random() - 0.5);
}

// ─── Styles ───────────────────────────────────────────────────────────────────

const S: Record<string, CSSProperties> = {
  setupRoot:         { display: 'flex', height: '100vh', background: '#202225', color: '#fff', alignItems: 'center', justifyContent: 'center' },
  setupBox:          { background: '#2f3136', padding: '40px', borderRadius: '8px', width: '400px', textAlign: 'center' },
  setupNote:         { margin: '16px 0', color: '#b9bbbe', fontSize: '13px', lineHeight: '1.6' },
  setupInput:        { width: '100%', padding: '12px', fontSize: '16px', background: '#40444b', border: 'none', borderRadius: '4px', color: '#fff', marginBottom: '16px', boxSizing: 'border-box' },
  setupButton:       { padding: '12px 40px', background: '#5865f2', color: 'white', border: 'none', borderRadius: '4px', fontSize: '15px', cursor: 'pointer' },
  root:              { display: 'flex', height: '100vh', background: '#202225', color: '#fff', fontFamily: 'system-ui, sans-serif', overflow: 'hidden' },
  sidebar:           { width: '230px', background: '#2f3136', padding: '16px', borderRight: '1px solid #202225', overflowY: 'auto', flexShrink: 0, display: 'flex', flexDirection: 'column', gap: '2px' },
  sidebarTitle:      { margin: '0 0 2px', fontSize: '15px', fontWeight: 700 },
  sidebarSub:        { margin: 0, fontSize: '12px', color: '#72767d' },
  connStatus:        { display: 'flex', alignItems: 'center', gap: '5px', marginTop: '6px' },
  hr:                { borderColor: '#40444b', margin: '12px 0', borderStyle: 'solid', borderWidth: '1px 0 0', flexShrink: 0 },
  sectionHeader:     { fontSize: '11px', fontWeight: 700, color: '#72767d', textTransform: 'uppercase' as const, letterSpacing: '0.5px', margin: '0 0 6px' },
  onlineUser:        { color: '#b9bbbe', margin: '3px 0', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '5px' },
  voiceUser:         { margin: '5px 0', display: 'flex', alignItems: 'center', gap: '6px' },
  voiceUserName:     { flex: 1, fontSize: '13px' },
  volumeSlider:      { width: '64px' },
  chatArea:          { flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0, position: 'relative' as const },
  chatHeader:        { padding: '10px 18px', background: '#36393f', borderBottom: '1px solid #202225', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '10px', flexShrink: 0, minHeight: '44px' },
  messageList:       { flex: 1, padding: '16px 20px', overflowY: 'auto' as const },
  msgRow:            { marginBottom: '10px', display: 'flex', flexDirection: 'column' as const, alignItems: 'flex-start' },
  msgRowOwn:         { marginBottom: '10px', display: 'flex', flexDirection: 'column' as const, alignItems: 'flex-end' },
  msgMeta:           { fontSize: '11px', color: '#72767d', marginBottom: '2px' },
  msgMetaOwn:        { fontSize: '11px', color: '#72767d', marginBottom: '2px', textAlign: 'right' as const },
  msgBubble:         { background: '#40444b', padding: '8px 12px', borderRadius: '4px 12px 12px 4px', maxWidth: '72%', wordBreak: 'break-word' as const, fontSize: '14px', lineHeight: '1.4' },
  msgBubbleOwn:      { background: '#5865f2', padding: '8px 12px', borderRadius: '12px 4px 4px 12px', maxWidth: '72%', wordBreak: 'break-word' as const, fontSize: '14px', lineHeight: '1.4' },
  scrollBtn:         { position: 'absolute' as const, bottom: '76px', right: '20px', background: '#5865f2', color: 'white', border: 'none', borderRadius: '50%', width: '34px', height: '34px', fontSize: '16px', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', boxShadow: '0 2px 8px rgba(0,0,0,0.5)', zIndex: 10 },
  inputRow:          { padding: '10px 14px', background: '#36393f', flexShrink: 0 },
  inputFlex:         { display: 'flex', gap: '8px' },
  messageInput:      { flex: 1, padding: '10px 14px', background: '#40444b', border: 'none', borderRadius: '4px', color: '#fff', outline: 'none', fontSize: '14px' },
  sendButton:        { padding: '10px 18px', background: '#5865f2', color: 'white', border: 'none', borderRadius: '4px', fontWeight: 600, cursor: 'pointer' },
  voicePanel:        { width: '230px', background: '#2f3136', padding: '16px', borderLeft: '1px solid #202225', overflowY: 'auto', flexShrink: 0 },
  relayRow:          { display: 'flex', alignItems: 'center', gap: '6px', margin: '5px 0 4px' },
  relayCount:        { fontSize: '12px', color: '#72767d' },
  searchInput:       { width: '100%', padding: '7px 10px', background: '#40444b', border: 'none', borderRadius: '4px', color: '#fff', outline: 'none', boxSizing: 'border-box' as const, marginBottom: '6px', fontSize: '13px' },
  searchInputDis:    { width: '100%', padding: '7px 10px', background: '#2c2f33', border: 'none', borderRadius: '4px', color: '#4f545c', outline: 'none', boxSizing: 'border-box' as const, marginBottom: '6px', cursor: 'not-allowed', fontSize: '13px' },
  resultsList:       { flex: 1, padding: '14px 18px', overflowY: 'auto' as const },
  resultItem:        { marginBottom: '16px', paddingBottom: '16px', borderBottom: '1px solid #40444b' },
  resultTitle:       { color: '#00b0f4', fontWeight: 600, fontSize: '14px', marginBottom: '2px', cursor: 'pointer' },
  resultUrl:         { color: '#3ba55c', fontSize: '12px', marginBottom: '4px', cursor: 'pointer' },
  resultSnippet:     { color: '#b9bbbe', fontSize: '13px', lineHeight: '1.5' },
  searchStatus:      { color: '#72767d', padding: '40px 0', textAlign: 'center' as const },
  searchError:       { color: '#ed4245', padding: '14px', background: '#2c2f33', borderRadius: '4px', fontSize: '13px' },
  backButton:        { padding: '4px 10px', background: '#40444b', color: '#b9bbbe', border: 'none', borderRadius: '4px', cursor: 'pointer', fontSize: '13px', flexShrink: 0 },
  circuitBadge:      { fontSize: '11px', color: '#3ba55c', background: '#1e2d22', padding: '2px 7px', borderRadius: '10px', marginLeft: 'auto', flexShrink: 0, whiteSpace: 'nowrap' as const },
  spinnerWrap:       { display: 'flex', flexDirection: 'column' as const, alignItems: 'center', gap: '14px', padding: '48px 0', color: '#72767d', fontSize: '13px' },
  searchHeaderInput: { flex: 1, minWidth: 0, padding: '4px 10px', background: '#40444b', border: 'none', borderRadius: '4px', color: '#fff', outline: 'none', fontSize: '13px' },
  searchHeaderBtn:   { padding: '4px 12px', background: '#5865f2', color: 'white', border: 'none', borderRadius: '4px', cursor: 'pointer', fontSize: '13px', fontWeight: 600, flexShrink: 0 },
  // Room list styles
  roomItem:          { display: 'flex', alignItems: 'center', gap: '6px', padding: '5px 8px', borderRadius: '4px', marginBottom: '2px', cursor: 'default' },
  roomItemActive:    { display: 'flex', alignItems: 'center', gap: '6px', padding: '5px 8px', borderRadius: '4px', marginBottom: '2px', background: '#40444b' },
  roomLabel:         { flex: 1, fontSize: '13px', color: '#dcddde', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' as const },
  roomLabelActive:   { flex: 1, fontSize: '13px', color: '#fff', fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' as const },
  roomJoinBtn:       { padding: '2px 8px', background: '#5865f2', color: 'white', border: 'none', borderRadius: '4px', fontSize: '11px', cursor: 'pointer', flexShrink: 0 },
  roomDeleteBtn:     { padding: '2px 6px', background: 'transparent', color: '#72767d', border: 'none', borderRadius: '4px', fontSize: '14px', cursor: 'pointer', flexShrink: 0, lineHeight: '1' },
  roomActionRow:     { display: 'flex', gap: '6px', marginTop: '6px' },
  roomCreateBtn:     { flex: 1, padding: '7px', background: '#3ba55c', color: 'white', border: 'none', borderRadius: '4px', fontSize: '12px', cursor: 'pointer' },
  roomJoinCodeBtn:   { flex: 1, padding: '7px', background: '#5865f2', color: 'white', border: 'none', borderRadius: '4px', fontSize: '12px', cursor: 'pointer' },
  // Modal styles
  modalOverlay:      { position: 'fixed' as const, inset: 0, background: 'rgba(0,0,0,0.75)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 200 },
  modalBox:          { background: '#2f3136', padding: '28px', borderRadius: '8px', width: '340px', boxShadow: '0 8px 32px rgba(0,0,0,0.5)' },
  modalTitle:        { margin: '0 0 18px', fontSize: '16px', fontWeight: 700 },
  modalInput:        { width: '100%', padding: '10px', background: '#40444b', border: 'none', borderRadius: '4px', color: '#fff', fontSize: '14px', marginBottom: '10px', boxSizing: 'border-box' as const, outline: 'none' },
  modalCode:         { display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: '#40444b', padding: '12px 14px', borderRadius: '4px', marginBottom: '16px' },
  modalCodeText:     { fontFamily: 'monospace', fontSize: '18px', letterSpacing: '3px', color: '#fff', fontWeight: 700 },
  modalCopyBtn:      { padding: '4px 10px', background: '#5865f2', color: 'white', border: 'none', borderRadius: '4px', fontSize: '12px', cursor: 'pointer', flexShrink: 0 },
  modalBtn:          { width: '100%', padding: '10px', background: '#5865f2', color: 'white', border: 'none', borderRadius: '4px', fontSize: '14px', cursor: 'pointer', marginBottom: '8px', fontWeight: 600 },
  modalNote:         { color: '#b9bbbe', fontSize: '12px', marginBottom: '16px', lineHeight: '1.5' },
  modalCancelBtn:    { width: '100%', padding: '8px', background: 'transparent', color: '#72767d', border: '1px solid #40444b', borderRadius: '4px', fontSize: '13px', cursor: 'pointer' },
  // DM / friends styles
  onlineUserBtn:     { color: '#b9bbbe', margin: '3px 0', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '5px', width: '100%', background: 'none', border: 'none', padding: '2px 4px', borderRadius: '4px', cursor: 'pointer', textAlign: 'left' as const },
  ctxMenu:           { position: 'fixed' as const, background: '#18191c', border: '1px solid #40444b', borderRadius: '6px', padding: '6px', zIndex: 300, boxShadow: '0 4px 16px rgba(0,0,0,0.6)', minWidth: '140px' },
  ctxMenuItem:       { display: 'block', width: '100%', padding: '8px 12px', background: 'none', border: 'none', color: '#dcddde', fontSize: '13px', cursor: 'pointer', borderRadius: '4px', textAlign: 'left' as const },
  dmBanner:          { position: 'fixed' as const, bottom: '24px', right: '24px', background: '#2f3136', border: '1px solid #5865f2', borderRadius: '8px', padding: '14px 18px', zIndex: 300, boxShadow: '0 4px 20px rgba(0,0,0,0.6)', minWidth: '240px' },
  dmBannerTitle:     { margin: '0 0 6px', fontSize: '14px', fontWeight: 700 },
  dmBannerSub:       { margin: '0 0 12px', fontSize: '12px', color: '#b9bbbe' },
  dmBannerRow:       { display: 'flex', gap: '8px' },
  dmItem:            { display: 'flex', alignItems: 'center', gap: '6px', padding: '5px 8px', borderRadius: '4px', marginBottom: '2px', cursor: 'default' },
  dmItemActive:      { display: 'flex', alignItems: 'center', gap: '6px', padding: '5px 8px', borderRadius: '4px', marginBottom: '2px', background: '#40444b' },
  dmLabel:           { flex: 1, fontSize: '13px', color: '#dcddde', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' as const },
  dmLabelActive:     { flex: 1, fontSize: '13px', color: '#fff', fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' as const },
};

const joinButtonOn:       CSSProperties = { width: '100%', padding: '11px', background: '#ed4245', color: 'white', border: 'none', borderRadius: '4px', fontSize: '14px', fontWeight: 600, marginBottom: '8px', cursor: 'pointer' };
const joinButtonOff:      CSSProperties = { width: '100%', padding: '11px', background: '#3ba55c', color: 'white', border: 'none', borderRadius: '4px', fontSize: '14px', fontWeight: 600, marginBottom: '8px', cursor: 'pointer' };
const muteButtonOn:       CSSProperties = { width: '100%', padding: '9px', background: '#ed4245', color: 'white', border: 'none', borderRadius: '4px', cursor: 'pointer' };
const muteButtonOff:      CSSProperties = { width: '100%', padding: '9px', background: '#5865f2', color: 'white', border: 'none', borderRadius: '4px', cursor: 'pointer' };
const relayButtonOn:      CSSProperties = { width: '100%', padding: '9px', background: '#3ba55c', color: 'white', border: 'none', borderRadius: '4px', marginBottom: '2px', fontSize: '13px', cursor: 'pointer' };
const relayButtonOff:     CSSProperties = { width: '100%', padding: '9px', background: '#40444b', color: '#b9bbbe', border: 'none', borderRadius: '4px', marginBottom: '2px', fontSize: '13px', cursor: 'pointer' };
const searchButtonSafe:   CSSProperties = { width: '100%', padding: '9px', background: '#5865f2', color: 'white', border: 'none', borderRadius: '4px', fontSize: '13px', cursor: 'pointer', fontWeight: 600 };
const searchButtonUnsafe: CSSProperties = { width: '100%', padding: '9px', background: '#2c2f33', color: '#4f545c', border: '1px solid #40444b', borderRadius: '4px', fontSize: '13px', cursor: 'not-allowed' };

// ─── Component ────────────────────────────────────────────────────────────────

function App() {
  // ── Global state ─────────────────────────────────────────────────────────────
  const [username, setUsername]             = useState('');
  const [isMuted, setIsMuted]               = useState(false);
  const [isInVoice, setIsInVoice]           = useState(false);
  const [newMessage, setNewMessage]         = useState('');
  const [showSetup, setShowSetup]           = useState(false);
  const [isRelayEnabled, setIsRelayEnabled] = useState(true);
  const [acceptHistory, setAcceptHistory]   = useState(true);
  const [searchQuery, setSearchQuery]       = useState('');
  const [activeView, setActiveView]         = useState<'chat' | 'search' | 'browse'>('chat');
  const [isSearching, setIsSearching]       = useState(false);
  const [searchResults, setSearchResults]   = useState<SearchResult[]>([]);
  const [searchError, setSearchError]       = useState<string | null>(null);
  const [activeCircuit, setActiveCircuit]   = useState<string[]>([]);
  const [isAtBottom, setIsAtBottom]         = useState(true);
  const [isSpeaking, setIsSpeaking]         = useState(false);
  const [speakingPeers, setSpeakingPeers]   = useState<Record<string, boolean>>({});
  const [browseUrl, setBrowseUrl]           = useState('');
  const [browseHtml, setBrowseHtml]         = useState('');
  const [isBrowsing, setIsBrowsing]         = useState(false);
  const [browseCircuit, setBrowseCircuit]   = useState<string[]>([]);

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

  // ── Refs ─────────────────────────────────────────────────────────────────────
  const usernameInputRef  = useRef<HTMLInputElement>(null);
  const messageListRef    = useRef<HTMLDivElement>(null);
  const audioCtxRef       = useRef<AudioContext | null>(null);
  const speakingTimerRef  = useRef<ReturnType<typeof setInterval> | null>(null);
  const volumesRef        = useRef<Record<string, number>>({});
  const myPublicKeyRef    = useRef('');
  const myPrivateKeyRef   = useRef<CryptoKey | null>(null);
  const isRelayEnabledRef  = useRef(true);
  const acceptHistoryRef   = useRef(true);
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
        const plaintext = await decryptLayer(data.enc, myPrivateKeyRef.current);
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
            upd(s => ({
              ...s,
              displayNames: s.displayNames[peerId] ? s.displayNames : { ...s.displayNames, [peerId]: payload.username },
              messages:     [...s.messages, { id: crypto.randomUUID(), from: payload.username, text: payload.text, ts: Date.now() }],
            }));
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
            }));
            break;
          case 'dmInvite':
            setPendingDmInvite({ fromUsername: payload.fromUsername, roomId: payload.roomId, peerId });
            break;
          case 'relayBatch':
            // We are acting as a one-hop mixer: forward each delivery to its target peer.
            for (const { peerId: targetPeerId, enc } of payload.deliveries) {
              runtime.sendEncMsg?.({ enc }, targetPeerId);
            }
            break;
          case 'chatHistory':
            if (!acceptHistoryRef.current) break;
            upd(s => {
              const existingIds = new Set(s.messages.map(m => m.id));
              const incoming    = payload.messages.filter(m => !existingIds.has(m.id));
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
      runtime.peerPublicKeys[peerId] = data.publicKeyBase64;
      const pubKey = data.publicKeyBase64;
      const [usernamePacket, relayPacket, voicePacket] = await Promise.all([
        encryptMsg({ type: 'username',    username: usernameRef.current }, pubKey),
        encryptMsg({ type: 'relayAvail',  isRelay: isRelayEnabledRef.current }, pubKey),
        encryptMsg({ type: 'voiceStatus', username: usernameRef.current, inVoice: runtime.isInVoice }, pubKey),
      ]);
      runtime.sendEncMsg?.(usernamePacket, peerId);
      runtime.sendEncMsg?.(relayPacket,    peerId);
      runtime.sendEncMsg?.(voicePacket,    peerId);

      const savedRaw = localStorage.getItem(`p2p-history-${roomId}`);
      if (savedRaw) {
        try {
          const messages = JSON.parse(savedRaw);
          const histPacket = await encryptMsg({ type: 'chatHistory', messages }, pubKey);
          runtime.sendEncMsg?.(histPacket, peerId);
        } catch { /* corrupt save — ignore */ }
      }
    });

    const [sendRelayFwd, getRelayFwd] = trysteroRoom.makeAction('relayFwd');
    runtime.sendRelayFwd = sendRelayFwd;
    getRelayFwd(async (data: OnionForwardPacket, senderPeerId: string) => {
      if (!isRelayEnabledRef.current || !myPrivateKeyRef.current) return;
      circuitTableRef.current[data.circuitId] = { returnRuntime: runtime, returnPeer: senderPeerId, expiresAt: Date.now() + 60_000 };
      try {
        const plaintext    = await decryptLayer(data.layer, myPrivateKeyRef.current);
        const instruction: PlainInstruction = JSON.parse(plaintext);
        if (instruction.nextHop === 'exit') {
          try {
            const html = await invoke<string>('relay_fetch', { url: instruction.payload });
            runtime.sendRelayResp?.({ circuitId: data.circuitId, data: html, isError: false }, senderPeerId);
          } catch (e) {
            runtime.sendRelayResp?.({ circuitId: data.circuitId, data: String(e), isError: true }, senderPeerId);
          }
        } else {
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
      if (myPublicKeyRef.current) runtime.sendPeerKey?.({ publicKeyBase64: myPublicKeyRef.current }, peerId);
    });

    trysteroRoom.onPeerLeave((peerId: string) => {
      const leavingUsername = runtime.peerUsername[peerId];
      upd(s => ({
        ...s,
        peers:           s.peers.filter(id => id !== peerId),
        displayNames:    Object.fromEntries(Object.entries(s.displayNames).filter(([k]) => k !== peerId)),
        inVoiceUsers:    leavingUsername ? s.inVoiceUsers.filter(u => u !== leavingUsername) : s.inVoiceUsers,
        availableRelays: s.availableRelays.filter(id => id !== peerId),
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
      audio.autoplay  = true;
      const peerName = runtime.peerUsername[peerId];
      const saved    = peerName ? volumesRef.current[peerName] : undefined;
      if (saved !== undefined) audio.volume = saved;
      runtime.remoteAudios[peerId] = audio;
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
    if (myPublicKeyRef.current) runtime.sendPeerKey?.({ publicKeyBase64: myPublicKeyRef.current });

    // Re-announce periodically so late joiners who missed the initial broadcast
    // pick up our key and then receive encrypted status via the getPeerKey handler.
    runtime.announceInterval = setInterval(async () => {
      if (myPublicKeyRef.current) runtime.sendPeerKey?.({ publicKeyBase64: myPublicKeyRef.current });
      if (usernameRef.current) {
        await sendDirectToAll(runtime, { type: 'username',   username: usernameRef.current });
        await sendDirectToAll(runtime, { type: 'relayAvail', isRelay: isRelayEnabledRef.current });
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
      const kp = await crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']
      );
      myPrivateKeyRef.current = kp.privateKey;
      const raw = await crypto.subtle.exportKey('raw', kp.publicKey);
      myPublicKeyRef.current = uint8ToBase64(new Uint8Array(raw));
    })();
  }, []);

  useEffect(() => {
    const savedUsername = localStorage.getItem('p2p-username');
    if (savedUsername) setUsername(savedUsername);
    else setShowSetup(true);

    const savedVols = localStorage.getItem('p2p-volumes');
    if (savedVols) volumesRef.current = JSON.parse(savedVols);

    if (localStorage.getItem('p2p-accept-history') === 'false') {
      setAcceptHistory(false);
      acceptHistoryRef.current = false;
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
      const rt = roomRuntimesRef.current[activeRoomId];
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
  }, [isInVoice, activeRoomId]);

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
    await sendEncryptedToAll(rt, { type: 'chat', username, text: newMessage });
    setRoomStates(prev => {
      const s = prev[activeRoomId] ?? emptyRoomState();
      return { ...prev, [activeRoomId]: { ...s, messages: [...s.messages, { id: crypto.randomUUID(), from: 'You', text: newMessage, ts: Date.now() }] } };
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
    await sendDirectToAll(rt, { type: 'voiceStatus', username: myUsername, inVoice: false });
    setRoomStates(prev => {
      const s = prev[roomId];
      if (!s) return prev;
      return { ...prev, [roomId]: { ...s, inVoiceUsers: s.inVoiceUsers.filter(u => u !== myUsername), isInVoice: false } };
    });
  };

  const toggleVoice = async () => {
    const rt = roomRuntimesRef.current[activeRoomId];
    if (!rt) return;
    if (rt.isInVoice) {
      leaveVoiceInRoom(activeRoomId);
      setIsInVoice(false);
      setIsMuted(false);
    } else {
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
        await sendDirectToAll(rt, { type: 'voiceStatus', username, inVoice: true });
        setRoomStates(prev => {
          const s = prev[activeRoomId] ?? emptyRoomState();
          return { ...prev, [activeRoomId]: { ...s, inVoiceUsers: s.inVoiceUsers.includes(username) ? s.inVoiceUsers : [...s.inVoiceUsers, username], isInVoice: true } };
        });
        setIsInVoice(true);
      } catch {
        alert('Could not access microphone');
      }
    }
  };

  const toggleMute = () => {
    const rt = roomRuntimesRef.current[activeRoomId];
    if (!rt?.selfStream) return;
    const track = rt.selfStream.getAudioTracks()[0];
    if (track) track.enabled = !track.enabled;
    setIsMuted(!track?.enabled);
  };

  const changeVolume = (targetUsername: string, value: number) => {
    const volume = value / 100;
    volumesRef.current[targetUsername] = volume;
    localStorage.setItem('p2p-volumes', JSON.stringify(volumesRef.current));
    const rt = roomRuntimesRef.current[activeRoomId];
    if (!rt) return;
    const peerId = rt.usernamePeer[targetUsername];
    const audio  = peerId ? rt.remoteAudios[peerId] : undefined;
    if (audio) audio.volume = volume;
  };

  const saveChat = () => {
    const msgs = roomStates[activeRoomId]?.messages ?? [];
    if (msgs.length === 0) return;
    const savable = msgs
      .slice(-MAX_HISTORY)
      .map(m => ({ ...m, from: m.from === 'You' ? username : m.from }));
    localStorage.setItem(`p2p-history-${activeRoomId}`, JSON.stringify(savable));
  };

  const toggleAcceptHistory = () => {
    const next = !acceptHistory;
    setAcceptHistory(next);
    acceptHistoryRef.current = next;
    localStorage.setItem('p2p-accept-history', String(next));
  };

  const toggleRelay = async () => {
    const next = !isRelayEnabled;
    setIsRelayEnabled(next);
    isRelayEnabledRef.current = next;
    await Promise.all(
      Object.values(roomRuntimesRef.current).map(rt =>
        sendDirectToAll(rt, { type: 'relayAvail', isRelay: next })
      )
    );
  };

  const switchRoom = (roomId: string) => {
    if (roomId === activeRoomId) return;
    leaveVoiceInRoom(activeRoomId);
    setIsInVoice(roomRuntimesRef.current[roomId]?.isInVoice ?? false);
    setIsMuted(false);
    setActiveRoomId(roomId);
    activeRoomIdRef.current = roomId;
    setActiveView('chat');
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
          pendingCircuitsRef.current[packet.circuitId] = { resolve, reject };
          setTimeout(() => {
            if (pendingCircuitsRef.current[packet.circuitId]) {
              delete pendingCircuitsRef.current[packet.circuitId];
              reject('Search timed out — a relay may have gone offline.');
            }
          }, 30_000);
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
      if (uddg) url = uddg;
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
          pendingCircuitsRef.current[packet.circuitId] = { resolve, reject };
          setTimeout(() => {
            if (pendingCircuitsRef.current[packet.circuitId]) {
              delete pendingCircuitsRef.current[packet.circuitId];
              reject('Page load timed out.');
            }
          }, 30_000);
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
      csp.setAttribute('content', "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src https: http: data: blob:; font-src https: http: data:; media-src https: http: data: blob:;");
      doc.head.prepend(csp);
      const base = doc.createElement('base');
      base.setAttribute('href', url);
      doc.head.prepend(base);
      doc.querySelectorAll('script').forEach(s => s.remove());
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

  // Count unique relay peers (by public key) across all joined rooms
  const _seenRelayKeys = new Set<string>();
  for (const [roomId, rt] of Object.entries(roomRuntimesRef.current)) {
    const state = roomStates[roomId];
    for (const peerId of (state?.availableRelays ?? [])) {
      const k = rt.peerPublicKeys[peerId];
      if (k) _seenRelayKeys.add(k);
    }
  }
  const globalRelayCount = _seenRelayKeys.size;
  const canSearch        = globalRelayCount >= 3;
  const relayShortfall   = Math.max(0, 3 - globalRelayCount);
  const relayDotColor    = globalRelayCount >= 3 ? '#3ba55c' : globalRelayCount >= 1 ? '#faa61a' : '#ed4245';

  // ── Render ────────────────────────────────────────────────────────────────────

  if (showSetup) {
    return (
      <div style={S.setupRoot}>
        <div style={S.setupBox}>
          <h2>Welcome to BunChat</h2>
          <p style={S.setupNote}>
            Choose a username to get started. Relay will be active automatically,
            helping your friends stay connected and search safely.
          </p>
          <input
            ref={usernameInputRef}
            type="text"
            placeholder="Enter username"
            maxLength={18}
            onKeyDown={e => e.key === 'Enter' && saveUsername(usernameInputRef.current?.value ?? '')}
            style={S.setupInput}
          />
          <button onClick={() => saveUsername(usernameInputRef.current?.value ?? '')} style={S.setupButton}>
            Join
          </button>
        </div>
      </div>
    );
  }

  return (
    <div style={S.root}>

      {/* ── Sidebar ── */}
      <div style={S.sidebar}>
        <p style={S.sidebarTitle}>BunChat</p>
        <p style={S.sidebarSub}>Room: {activeRoomLabel}</p>
        <p style={S.sidebarSub}>You: {username}</p>
        <div style={S.connStatus}>
          <span style={{ color: isConnected ? '#3ba55c' : '#faa61a', fontSize: '14px' }}>●</span>
          <span style={{ color: '#72767d', fontSize: '12px' }}>
            {isConnected ? 'Connected' : 'Searching for peers…'}
          </span>
        </div>
        <hr style={S.hr} />

        <div style={S.sectionHeader}>Online — {onlineList.length}</div>
        {onlineList.map(user => (
          <button
            key={`online-${user}`}
            style={S.onlineUserBtn}
            onClick={e => {
              if (user === username) return;
              const peerId = activeRuntime?.usernamePeer[user];
              if (!peerId) return;
              setUserContextMenu({ username: user, peerId, x: e.clientX, y: e.clientY });
            }}
          >
            <span style={{ color: '#3ba55c', fontSize: '13px' }}>●</span>{user}
          </button>
        ))}

        <hr style={S.hr} />

        <div style={S.sectionHeader}>In Voice — {activeState.inVoiceUsers.length}</div>
        {activeState.inVoiceUsers.map(user => {
          const peerId   = activeRuntime?.usernamePeer[user];
          const speaking = user === username ? isSpeaking : (peerId ? speakingPeers[peerId] ?? false : false);
          const savedVol = Math.round((volumesRef.current[user] ?? 1) * 100);
          return (
            <div key={`voice-${user}`} style={S.voiceUser}>
              <span style={{ color: speaking ? '#3ba55c' : '#4f545c', fontSize: '14px', transition: 'color 0.1s' }}>●</span>
              <span style={S.voiceUserName}>{user}</span>
              {user !== username && (
                <input
                  type="range" min="0" max="200"
                  defaultValue={savedVol}
                  onChange={e => changeVolume(user, Number(e.currentTarget.value))}
                  style={S.volumeSlider}
                />
              )}
            </div>
          );
        })}

        {/* ── Direct Messages ── */}
        {roomDefs.some(d => d.isDM) && (
          <>
            <hr style={S.hr} />
            <div style={S.sectionHeader}>Direct Messages</div>
            {roomDefs.filter(d => d.isDM).map(def => (
              <div key={def.id} style={activeRoomId === def.id ? S.dmItemActive : S.dmItem}>
                <span style={{ fontSize: '13px', color: '#72767d' }}>@</span>
                <span style={activeRoomId === def.id ? S.dmLabelActive : S.dmLabel} title={def.label}>
                  {def.label}
                </span>
                {activeRoomId !== def.id && (
                  <button onClick={() => switchRoom(def.id)} style={S.roomJoinBtn}>Open</button>
                )}
                <button onClick={() => removeRoom(def.id)} style={S.roomDeleteBtn} title="Remove">×</button>
              </div>
            ))}
          </>
        )}
      </div>

      {/* ── Main area: Chat / Search / Browse ── */}
      <div style={S.chatArea}>
        {activeView === 'browse' ? (
          <>
            <div style={S.chatHeader}>
              <button onClick={() => setActiveView('search')} style={S.backButton}>← Results</button>
              <div style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: '#b9bbbe', fontSize: '12px', padding: '0 6px' }}>
                {browseUrl}
              </div>
              {browseCircuit.length === 3 && (
                <span style={S.circuitBadge}>
                  3-hop · {browseCircuit.map(id => id.slice(0, 4)).join(' → ')}
                </span>
              )}
            </div>
            <div style={{ flex: 1, position: 'relative', overflow: 'hidden' }}>
              {isBrowsing && (
                <div style={{ position: 'absolute', inset: 0, background: '#36393f', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: '14px', color: '#72767d', fontSize: '13px', zIndex: 1 }}>
                  <div className="spinner" />
                  Loading through relays…
                </div>
              )}
              <iframe
                srcDoc={browseHtml}
                sandbox="allow-scripts allow-same-origin"
                style={{ width: '100%', height: '100%', border: 'none', background: 'white' }}
                title="Browse"
              />
            </div>
          </>
        ) : activeView === 'chat' ? (
          <>
            <div style={S.chatHeader}>{activeRoomLabel}</div>
            <div ref={messageListRef} style={S.messageList} onScroll={handleScroll}>
              {activeState.messages.map(m => {
                const own = m.from === 'You';
                return (
                  <div key={m.id} style={own ? S.msgRowOwn : S.msgRow}>
                    <div style={own ? S.msgMetaOwn : S.msgMeta}>
                      {own ? 'You' : m.from} · {formatTime(m.ts)}
                    </div>
                    <div style={own ? S.msgBubbleOwn : S.msgBubble}>{m.text}</div>
                  </div>
                );
              })}
            </div>
            {!isAtBottom && (
              <button style={S.scrollBtn} onClick={scrollToBottom} title="Jump to latest">↓</button>
            )}
            <div style={S.inputRow}>
              <div style={S.inputFlex}>
                <input
                  value={newMessage}
                  onChange={e => setNewMessage(e.target.value.slice(0, 800))}
                  onKeyDown={e => e.key === 'Enter' && sendMessage()}
                  placeholder="Type a message…"
                  maxLength={800}
                  style={S.messageInput}
                />
                <button onClick={sendMessage} style={S.sendButton}>Send</button>
              </div>
            </div>
          </>
        ) : (
          <>
            <div style={S.chatHeader}>
              <button onClick={() => setActiveView('chat')} style={S.backButton}>← Chat</button>
              <input
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleSearch()}
                placeholder="Refine search…"
                style={S.searchHeaderInput}
              />
              <button onClick={() => handleSearch()} disabled={isSearching} style={S.searchHeaderBtn}>
                {isSearching ? '…' : 'Go'}
              </button>
              {activeCircuit.length === 3 && (
                <span style={S.circuitBadge}>
                  3-hop · {activeCircuit.map(id => id.slice(0, 4)).join(' → ')}
                </span>
              )}
            </div>
            <div style={S.resultsList}>
              {isSearching && (
                <div style={S.spinnerWrap}>
                  <div className="spinner" />
                  Routing through {activeCircuit.map(id => id.slice(0, 6)).join(' → ')}…
                </div>
              )}
              {searchError && <div style={S.searchError}>{searchError}</div>}
              {!isSearching && !searchError && searchResults.length === 0 && (
                <div style={S.searchStatus}>No results found</div>
              )}
              {searchResults.map((r, i) => (
                <div key={i} style={S.resultItem}>
                  <div style={S.resultTitle} onClick={() => browsePage(r.href)}>{r.title}</div>
                  <div style={S.resultUrl} onClick={() => browsePage(r.href)}>{r.url}</div>
                  <div style={S.resultSnippet}>{r.snippet}</div>
                </div>
              ))}
            </div>
          </>
        )}
      </div>

      {/* ── Right panel ── */}
      <div style={S.voicePanel}>
        <button onClick={toggleVoice} style={isInVoice ? joinButtonOn : joinButtonOff}>
          {isInVoice ? 'Leave Voice' : 'Join Voice'}
        </button>
        {isInVoice && (
          <button onClick={toggleMute} style={isMuted ? muteButtonOn : muteButtonOff}>
            {isMuted ? 'Unmute' : 'Mute'}
          </button>
        )}

        <hr style={S.hr} />

        <button onClick={saveChat} style={{ width: '100%', padding: '9px', background: '#40444b', color: '#dcddde', border: 'none', borderRadius: '4px', marginBottom: '4px', fontSize: '13px', cursor: 'pointer' }}>
          Save Chat
        </button>
        <button onClick={toggleAcceptHistory} style={{ width: '100%', padding: '9px', background: acceptHistory ? '#3ba55c' : '#40444b', color: acceptHistory ? 'white' : '#b9bbbe', border: 'none', borderRadius: '4px', marginBottom: '2px', fontSize: '13px', cursor: 'pointer' }}>
          {acceptHistory ? 'Accept History: ON' : 'Accept History: OFF'}
        </button>

        <hr style={S.hr} />

        <button onClick={toggleRelay} style={isRelayEnabled ? relayButtonOn : relayButtonOff}>
          {isRelayEnabled ? 'Relay: ON' : 'Relay: OFF'}
        </button>
        <div style={S.relayRow}>
          <span style={{ color: relayDotColor, fontSize: '14px' }}>●</span>
          <span style={S.relayCount}>
            {globalRelayCount} relay{globalRelayCount !== 1 ? 's' : ''} online
          </span>
        </div>

        <hr style={S.hr} />

        {activeView !== 'search' && (isSearching || searchResults.length > 0 || searchError) && (
          <button
            onClick={() => setActiveView('search')}
            style={{ width: '100%', padding: '9px', background: '#40444b', color: '#b9bbbe', border: 'none', borderRadius: '4px', fontSize: '13px', cursor: 'pointer', marginBottom: '6px' }}
          >
            {isSearching ? '⟳ Searching…' : '← Back to results'}
          </button>
        )}

        <input
          value={searchQuery}
          onChange={e => setSearchQuery(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handleSearch()}
          placeholder={canSearch ? 'Search…' : 'Need more relays…'}
          disabled={!canSearch}
          style={canSearch ? S.searchInput : S.searchInputDis}
        />
        <button
          onClick={() => handleSearch()}
          disabled={!canSearch || isSearching}
          style={canSearch ? searchButtonSafe : searchButtonUnsafe}
        >
          {isSearching
            ? 'Searching…'
            : canSearch
              ? 'Search'
              : `Unsafe, ${relayShortfall} peer${relayShortfall !== 1 ? 's' : ''} needed`}
        </button>

        <hr style={S.hr} />

        {/* ── Room list ── */}
        <div style={S.sectionHeader}>Rooms</div>
        {roomDefs.filter(d => !d.isDM).map(def => (
          <div key={def.id} style={activeRoomId === def.id ? S.roomItemActive : S.roomItem}>
            <span style={activeRoomId === def.id ? S.roomLabelActive : S.roomLabel} title={def.label}>
              {def.label}
            </span>
            {activeRoomId === def.id && def.id !== DEFAULT_ROOM_ID && (
              <button onClick={() => navigator.clipboard.writeText(def.id)} style={S.roomJoinBtn} title="Copy invite code">ID</button>
            )}
            {activeRoomId !== def.id && (
              <button onClick={() => switchRoom(def.id)} style={S.roomJoinBtn}>Join</button>
            )}
            {def.id !== DEFAULT_ROOM_ID && (
              <button onClick={() => removeRoom(def.id)} style={S.roomDeleteBtn} title="Remove room">×</button>
            )}
          </div>
        ))}
        <div style={S.roomActionRow}>
          <button onClick={() => { setShowRoomModal('create'); setCreatedRoomCode(''); }} style={S.roomCreateBtn}>
            + Create
          </button>
          <button onClick={() => setShowRoomModal('join')} style={S.roomJoinCodeBtn}>
            Join
          </button>
        </div>
      </div>

      {/* ── Room modal ── */}
      {showRoomModal && (
        <div style={S.modalOverlay} onClick={closeRoomModal}>
          <div style={S.modalBox} onClick={e => e.stopPropagation()}>

            {showRoomModal === 'create' && !createdRoomCode && (
              <>
                <p style={S.modalTitle}>Create a Room</p>
                <input
                  autoFocus
                  placeholder="Room name (e.g. Gaming Squad)"
                  value={roomModalLabel}
                  onChange={e => setRoomModalLabel(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && handleCreateRoom()}
                  style={S.modalInput}
                />
                <button onClick={handleCreateRoom} style={S.modalBtn}>Create</button>
                <button onClick={closeRoomModal} style={S.modalCancelBtn}>Cancel</button>
              </>
            )}

            {showRoomModal === 'create' && createdRoomCode && (
              <>
                <p style={S.modalTitle}>Room Created!</p>
                <p style={S.modalNote}>
                  Share this code with anyone you want to invite. They click "Join" and enter it.
                  The code is saved in your room list — you won't lose it.
                </p>
                <div style={S.modalCode}>
                  <span style={S.modalCodeText}>{createdRoomCode}</span>
                  <button
                    onClick={() => navigator.clipboard.writeText(createdRoomCode)}
                    style={S.modalCopyBtn}
                  >
                    Copy
                  </button>
                </div>
                <button onClick={closeRoomModal} style={S.modalBtn}>Done</button>
              </>
            )}

            {showRoomModal === 'join' && (
              <>
                <p style={S.modalTitle}>Join a Room</p>
                <input
                  autoFocus
                  placeholder="Invite code (e.g. ABCD-EFGH)"
                  value={roomModalCode}
                  onChange={e => setRoomModalCode(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && handleJoinRoom()}
                  style={S.modalInput}
                />
                <input
                  placeholder="Room name (optional)"
                  value={roomModalLabel}
                  onChange={e => setRoomModalLabel(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && handleJoinRoom()}
                  style={S.modalInput}
                />
                <button onClick={handleJoinRoom} style={S.modalBtn}>Join</button>
                <button onClick={closeRoomModal} style={S.modalCancelBtn}>Cancel</button>
              </>
            )}

          </div>
        </div>
      )}

      {/* ── User context menu ── */}
      {userContextMenu && (
        <div
          style={{ ...S.ctxMenu, left: userContextMenu.x, top: userContextMenu.y }}
          onMouseLeave={() => setUserContextMenu(null)}
        >
          <div style={{ padding: '4px 12px 8px', fontSize: '12px', color: '#72767d', fontWeight: 700 }}>
            {userContextMenu.username}
          </div>
          <button
            style={S.ctxMenuItem}
            onMouseEnter={e => (e.currentTarget.style.background = '#5865f2')}
            onMouseLeave={e => (e.currentTarget.style.background = 'none')}
            onClick={() => openDm(userContextMenu.peerId, userContextMenu.username)}
          >
            Message
          </button>
        </div>
      )}

      {/* ── DM invite banner ── */}
      {pendingDmInvite && (
        <div style={S.dmBanner}>
          <p style={S.dmBannerTitle}>Friend request</p>
          <p style={S.dmBannerSub}>{pendingDmInvite.fromUsername} wants to message you</p>
          <div style={S.dmBannerRow}>
            <button style={{ ...S.modalBtn, margin: 0, flex: 1 }} onClick={acceptDmInvite}>Accept</button>
            <button style={{ ...S.modalCancelBtn, flex: 1 }} onClick={() => setPendingDmInvite(null)}>Decline</button>
          </div>
        </div>
      )}

    </div>
  );
}

export default App;
