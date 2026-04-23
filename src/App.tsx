import { useState, useEffect, useRef, useCallback, type CSSProperties } from 'react';
import { joinRoom } from 'trystero';
import { invoke } from '@tauri-apps/api/core';

const APP_ID             = 'norway-friends-p2p-v1';
const DEFAULT_ROOM_ID    = 'southern-norway-20';
const DEFAULT_ROOM_LABEL = 'Global-1';

const RTC_CONFIG = {
  iceServers: [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun1.l.google.com:19302' },
    { urls: 'stun:stun.cloudflare.com:3478' },
  ],
};

// ─── Interfaces ───────────────────────────────────────────────────────────────

interface ChatMessage        { username: string; text: string }
interface VoiceStatusMessage { username: string; inVoice: boolean }
interface PeerKeyMessage     { publicKeyBase64: string }
interface RelayAvailMessage  { isRelay: boolean }
interface UsernameMessage    { username: string }

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

interface SearchResult { title: string; url: string; snippet: string; href: string }
interface Message      { id: string; from: string; text: string; ts: number }

interface RoomDef { id: string; label: string }

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
  sendChat:        ((d: ChatMessage,         t?: string | string[]) => void) | null;
  sendUsername:    ((d: UsernameMessage,     t?: string | string[]) => void) | null;
  sendVoiceStatus: ((d: VoiceStatusMessage,  t?: string | string[]) => void) | null;
  sendPeerKey:     ((d: PeerKeyMessage,      t?: string | string[]) => void) | null;
  sendRelay:       ((d: RelayAvailMessage,   t?: string | string[]) => void) | null;
  sendRelayFwd:    ((d: OnionForwardPacket,  t?: string | string[]) => void) | null;
  sendRelayResp:   ((d: OnionResponsePacket, t?: string | string[]) => void) | null;
  peerPublicKeys:  Record<string, string>;
  peerUsername:    Record<string, string>;
  usernamePeer:    Record<string, string>;
  circuitTable:    Record<string, { returnPeer: string; expiresAt: number }>;
  pendingCircuits: Record<string, { resolve: (d: string) => void; reject: (e: string) => void }>;
  remoteAudios:    Record<string, HTMLAudioElement>;
  remoteAnalysers: Record<string, AnalyserNode>;
  selfStream:      MediaStream | null;
  selfAnalyser:    AnalyserNode | null;
  isInVoice:       boolean;
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

  // ── Refs ─────────────────────────────────────────────────────────────────────
  const usernameInputRef  = useRef<HTMLInputElement>(null);
  const messageListRef    = useRef<HTMLDivElement>(null);
  const audioCtxRef       = useRef<AudioContext | null>(null);
  const speakingTimerRef  = useRef<ReturnType<typeof setInterval> | null>(null);
  const volumesRef        = useRef<Record<string, number>>({});
  const myPublicKeyRef    = useRef('');
  const myPrivateKeyRef   = useRef<CryptoKey | null>(null);
  const isRelayEnabledRef = useRef(true);
  const usernameRef       = useRef('');
  const browsePageRef     = useRef<((href: string) => void) | null>(null);
  const roomRuntimesRef   = useRef<Record<string, RoomRuntime>>({});

  // ── Room connection helper ────────────────────────────────────────────────────

  const setupRoom = (roomId: string) => {
    if (roomRuntimesRef.current[roomId]) return;

    const runtime: RoomRuntime = {
      trysteroRoom:    null,
      sendChat:        null,
      sendUsername:    null,
      sendVoiceStatus: null,
      sendPeerKey:     null,
      sendRelay:       null,
      sendRelayFwd:    null,
      sendRelayResp:   null,
      peerPublicKeys:  {},
      peerUsername:    {},
      usernamePeer:    {},
      circuitTable:    {},
      pendingCircuits: {},
      remoteAudios:    {},
      remoteAnalysers: {},
      selfStream:      null,
      selfAnalyser:    null,
      isInVoice:       false,
    };
    roomRuntimesRef.current[roomId] = runtime;

    const trysteroRoom = joinRoom({ appId: APP_ID, rtcConfig: RTC_CONFIG }, roomId);
    runtime.trysteroRoom = trysteroRoom;

    const upd = (fn: (s: RoomReactState) => RoomReactState) =>
      setRoomStates(prev => ({ ...prev, [roomId]: fn(prev[roomId] ?? emptyRoomState()) }));

    const [sendUsername, getUsername] = trysteroRoom.makeAction('username');
    runtime.sendUsername = sendUsername;
    getUsername((data: UsernameMessage, peerId: string) => {
      runtime.peerUsername[peerId]        = data.username;
      runtime.usernamePeer[data.username] = peerId;
      upd(s => ({ ...s, displayNames: { ...s.displayNames, [peerId]: data.username } }));
    });

    const [sendChat, getChat] = trysteroRoom.makeAction('chat');
    runtime.sendChat = sendChat;
    getChat((data: ChatMessage, peerId: string) => {
      runtime.peerUsername[peerId]        = data.username;
      runtime.usernamePeer[data.username] = peerId;
      upd(s => ({
        ...s,
        displayNames: s.displayNames[peerId] ? s.displayNames : { ...s.displayNames, [peerId]: data.username },
        messages:     [...s.messages, { id: crypto.randomUUID(), from: data.username, text: data.text, ts: Date.now() }],
      }));
    });

    const [sendVoiceStatus, getVoiceStatus] = trysteroRoom.makeAction('voiceStatus');
    runtime.sendVoiceStatus = sendVoiceStatus;
    getVoiceStatus((data: VoiceStatusMessage, peerId: string) => {
      runtime.peerUsername[peerId]        = data.username;
      runtime.usernamePeer[data.username] = peerId;
      upd(s => ({
        ...s,
        displayNames: s.displayNames[peerId] ? s.displayNames : { ...s.displayNames, [peerId]: data.username },
        inVoiceUsers: data.inVoice
          ? s.inVoiceUsers.includes(data.username) ? s.inVoiceUsers : [...s.inVoiceUsers, data.username]
          : s.inVoiceUsers.filter(u => u !== data.username),
      }));
    });

    const [sendPeerKey, getPeerKey] = trysteroRoom.makeAction('peerKey');
    runtime.sendPeerKey = sendPeerKey;
    getPeerKey((data: PeerKeyMessage, peerId: string) => {
      runtime.peerPublicKeys[peerId] = data.publicKeyBase64;
    });

    const [sendRelay, getRelay] = trysteroRoom.makeAction('relayAvail');
    runtime.sendRelay = sendRelay;
    getRelay((data: RelayAvailMessage, peerId: string) => {
      upd(s => ({
        ...s,
        availableRelays: data.isRelay
          ? s.availableRelays.includes(peerId) ? s.availableRelays : [...s.availableRelays, peerId]
          : s.availableRelays.filter(id => id !== peerId),
      }));
    });

    const [sendRelayFwd, getRelayFwd] = trysteroRoom.makeAction('relayFwd');
    runtime.sendRelayFwd = sendRelayFwd;
    getRelayFwd(async (data: OnionForwardPacket, senderPeerId: string) => {
      if (!isRelayEnabledRef.current || !myPrivateKeyRef.current) return;
      runtime.circuitTable[data.circuitId] = { returnPeer: senderPeerId, expiresAt: Date.now() + 60_000 };
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
          runtime.sendRelayFwd?.({ circuitId: data.circuitId, layer: nextLayer }, instruction.nextHop);
        }
      } catch { /* malformed packet — discard */ }
    });

    const [sendRelayResp, getRelayResp] = trysteroRoom.makeAction('relayResp');
    runtime.sendRelayResp = sendRelayResp;
    getRelayResp((data: OnionResponsePacket) => {
      const pending = runtime.pendingCircuits[data.circuitId];
      if (pending) {
        delete runtime.pendingCircuits[data.circuitId];
        if (data.isError) pending.reject(data.data);
        else              pending.resolve(data.data);
        return;
      }
      const entry = runtime.circuitTable[data.circuitId];
      if (entry) {
        runtime.sendRelayResp?.(data, entry.returnPeer);
        delete runtime.circuitTable[data.circuitId];
      }
    });

    trysteroRoom.onPeerJoin((peerId: string) => {
      upd(s => ({ ...s, peers: s.peers.includes(peerId) ? s.peers : [...s.peers, peerId] }));
      if (myPublicKeyRef.current) runtime.sendPeerKey?.({ publicKeyBase64: myPublicKeyRef.current }, peerId);
      runtime.sendRelay?.({ isRelay: isRelayEnabledRef.current }, peerId);
      runtime.sendUsername?.({ username: usernameRef.current }, peerId);
      runtime.sendVoiceStatus?.({ username: usernameRef.current, inVoice: runtime.isInVoice }, peerId);
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
      Object.keys(runtime.circuitTable).forEach(cid => {
        if (runtime.circuitTable[cid].returnPeer === peerId) delete runtime.circuitTable[cid];
      });
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

    if (myPublicKeyRef.current) runtime.sendPeerKey?.({ publicKeyBase64: myPublicKeyRef.current });
    runtime.sendRelay?.({ isRelay: isRelayEnabledRef.current });
    runtime.sendUsername?.({ username: usernameRef.current });
  };

  // ── Effects ───────────────────────────────────────────────────────────────────

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

    const savedRooms = localStorage.getItem('p2p-rooms');
    let defs: RoomDef[] = savedRooms
      ? JSON.parse(savedRooms)
      : [{ id: DEFAULT_ROOM_ID, label: DEFAULT_ROOM_LABEL }];
    if (!defs.find(d => d.id === DEFAULT_ROOM_ID)) {
      defs = [{ id: DEFAULT_ROOM_ID, label: DEFAULT_ROOM_LABEL }, ...defs];
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
    localStorage.setItem('p2p-username', name);
    setUsername(name);
    setShowSetup(false);
  };

  const sendMessage = () => {
    const rt = roomRuntimesRef.current[activeRoomId];
    if (!newMessage.trim() || !rt?.sendChat) return;
    rt.sendChat({ username, text: newMessage });
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

  const leaveVoiceInRoom = (roomId: string) => {
    const rt = roomRuntimesRef.current[roomId];
    if (!rt?.isInVoice) return;
    const myUsername = usernameRef.current;
    rt.selfStream?.getTracks().forEach(t => t.stop());
    rt.selfStream   = null;
    rt.selfAnalyser = null;
    rt.isInVoice    = false;
    rt.sendVoiceStatus?.({ username: myUsername, inVoice: false });
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
        rt.sendVoiceStatus?.({ username, inVoice: true });
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

  const toggleRelay = () => {
    const next = !isRelayEnabled;
    setIsRelayEnabled(next);
    isRelayEnabledRef.current = next;
    Object.values(roomRuntimesRef.current).forEach(rt => rt.sendRelay?.({ isRelay: next }));
  };

  const switchRoom = (roomId: string) => {
    if (roomId === activeRoomId) return;
    leaveVoiceInRoom(activeRoomId);
    setIsInVoice(roomRuntimesRef.current[roomId]?.isInVoice ?? false);
    setIsMuted(false);
    setActiveRoomId(roomId);
    setActiveView('chat');
    setIsAtBottom(true);
  };

  const addRoom = (def: RoomDef) => {
    setRoomDefs(prev => {
      if (prev.find(d => d.id === def.id)) return prev;
      const next = [...prev, def];
      localStorage.setItem('p2p-rooms', JSON.stringify(next));
      return next;
    });
    if (usernameRef.current) setupRoom(def.id);
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
    const rt          = roomRuntimesRef.current[activeRoomId];
    const activeState = roomStates[activeRoomId];
    if (!rt) return;
    const q = (queryOverride ?? searchQuery).trim();
    if (!q) return;
    const ready = (activeState?.availableRelays ?? []).filter(id => rt.peerPublicKeys[id]);
    if (ready.length < 3) return;
    const circuit = [...ready].sort(() => Math.random() - 0.5).slice(0, 3) as [string, string, string];
    const url     = `https://lite.duckduckgo.com/lite/?q=${encodeURIComponent(q)}`;
    setActiveView('search');
    setIsSearching(true);
    setSearchError(null);
    setSearchResults([]);
    setActiveCircuit(circuit);
    if (queryOverride !== undefined) setSearchQuery(queryOverride);
    try {
      const packet = await buildOnionPacket(url, circuit, rt.peerPublicKeys);
      const html = await new Promise<string>((resolve, reject) => {
        rt.pendingCircuits[packet.circuitId] = { resolve, reject };
        setTimeout(() => {
          if (rt.pendingCircuits[packet.circuitId]) {
            delete rt.pendingCircuits[packet.circuitId];
            reject('Search timed out — a relay may have gone offline. Try again.');
          }
        }, 30_000);
        rt.sendRelayFwd?.({ circuitId: packet.circuitId, layer: packet.layer }, circuit[0]);
      });
      setSearchResults(parseSearchResults(html));
    } catch (err) {
      setSearchError(String(err));
    } finally {
      setIsSearching(false);
    }
  };

  const browsePage = async (href: string) => {
    const rt          = roomRuntimesRef.current[activeRoomId];
    const activeState = roomStates[activeRoomId];
    if (!rt) return;
    let url = href;
    if (url.startsWith('//')) url = 'https:' + url;
    try {
      const parsed = new URL(url);
      const uddg   = parsed.searchParams.get('uddg');
      if (uddg) url = uddg;
    } catch { return; }

    const ready = (activeState?.availableRelays ?? []).filter(id => rt.peerPublicKeys[id]);
    if (ready.length < 3) return;

    const circuit = [...ready].sort(() => Math.random() - 0.5).slice(0, 3) as [string, string, string];

    setIsBrowsing(true);
    setBrowseUrl(url);
    setBrowseCircuit(circuit);
    setActiveView('browse');

    try {
      const packet = await buildOnionPacket(url, circuit, rt.peerPublicKeys);
      const html = await new Promise<string>((resolve, reject) => {
        rt.pendingCircuits[packet.circuitId] = { resolve, reject };
        setTimeout(() => {
          if (rt.pendingCircuits[packet.circuitId]) {
            delete rt.pendingCircuits[packet.circuitId];
            reject('Page load timed out.');
          }
        }, 30_000);
        rt.sendRelayFwd?.({ circuitId: packet.circuitId, layer: packet.layer }, circuit[0]);
      });

      const doc = new DOMParser().parseFromString(html, 'text/html');
      const csp = doc.createElement('meta');
      csp.setAttribute('http-equiv', 'Content-Security-Policy');
      csp.setAttribute('content', "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; font-src data:;");
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
  const canSearch       = activeState.availableRelays.length >= 3;
  const relayShortfall  = Math.max(0, 3 - activeState.availableRelays.length);
  const relayDotColor   = activeState.availableRelays.length >= 3 ? '#3ba55c' : activeState.availableRelays.length >= 1 ? '#faa61a' : '#ed4245';
  const isConnected     = activeState.peers.length > 0;
  const activeRoomLabel = roomDefs.find(d => d.id === activeRoomId)?.label ?? activeRoomId;

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
          <div key={`online-${user}`} style={S.onlineUser}>
            <span style={{ color: '#3ba55c', fontSize: '13px' }}>●</span>{user}
          </div>
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
                sandbox="allow-scripts"
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
                  onChange={e => setNewMessage(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && sendMessage()}
                  placeholder="Type a message…"
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

        <button onClick={toggleRelay} style={isRelayEnabled ? relayButtonOn : relayButtonOff}>
          {isRelayEnabled ? 'Relay: ON' : 'Relay: OFF'}
        </button>
        <div style={S.relayRow}>
          <span style={{ color: relayDotColor, fontSize: '14px' }}>●</span>
          <span style={S.relayCount}>
            {activeState.availableRelays.length} relay{activeState.availableRelays.length !== 1 ? 's' : ''} online
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
        {roomDefs.map(def => (
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

    </div>
  );
}

export default App;
