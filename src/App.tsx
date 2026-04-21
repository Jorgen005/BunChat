import { useState, useEffect, useRef, type CSSProperties } from 'react';
import { joinRoom } from 'trystero';
import { invoke } from '@tauri-apps/api/core';

const APP_ID = 'norway-friends-p2p-v1';
const ROOM_ID = 'southern-norway-20';

// ─── Interfaces ──────────────────────────────────────────────────────────────

interface ChatMessage       { username: string; text: string }
interface VoiceStatusMessage { username: string; inVoice: boolean }
interface PeerKeyMessage    { publicKeyBase64: string }
interface RelayAvailMessage { isRelay: boolean }

interface EncryptedLayer {
  ephemeralPub: string; // base64 – ephemeral ECDH public key for this layer
  iv:           string; // base64 – AES-GCM IV
  ciphertext:   string; // base64 – encrypted PlainInstruction
}

interface PlainInstruction {
  nextHop: string; // peerId of next relay, or 'exit'
  payload: string; // base64-encoded next EncryptedLayer JSON, or the URL when nextHop==='exit'
}

interface OnionForwardPacket  { circuitId: string; layer: EncryptedLayer }
interface OnionResponsePacket { circuitId: string; data: string; isError: boolean }

interface SearchResult { title: string; url: string; snippet: string }

// ─── Crypto helpers ───────────────────────────────────────────────────────────

function uint8ToBase64(arr: Uint8Array): string {
  let s = '';
  for (const b of arr) s += String.fromCharCode(b);
  return btoa(s);
}

function base64ToUint8(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

// Encrypt `plaintext` so only the holder of `peerPublicKeyBase64` can read it.
// Uses ECDH-P256 key agreement (ephemeral per-layer) + AES-GCM-256.
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
  // TODO(security): replace raw shared bits with HKDF derivation before production use
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

// Decrypt a layer using our own private key.
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

// Wrap a URL in three nested encryption layers, one per relay hop.
// Built inside-out: layer for C → wrapped by B → wrapped by A.
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

// Parse DuckDuckGo HTML search results into a clean list.
function parseSearchResults(html: string): SearchResult[] {
  const doc = new DOMParser().parseFromString(html, 'text/html');
  const out: SearchResult[] = [];
  doc.querySelectorAll('.result').forEach(el => {
    const title   = el.querySelector('.result__title')?.textContent?.trim()   ?? '';
    const url     = el.querySelector('.result__url')?.textContent?.trim()     ?? '';
    const snippet = el.querySelector('.result__snippet')?.textContent?.trim() ?? '';
    if (title) out.push({ title, url, snippet });
  });
  return out.slice(0, 10);
}

// ─── Style constants ──────────────────────────────────────────────────────────

const S: Record<string, CSSProperties> = {
  setupRoot:           { display: 'flex', height: '100vh', background: '#202225', color: '#fff', alignItems: 'center', justifyContent: 'center' },
  setupBox:            { background: '#2f3136', padding: '40px', borderRadius: '8px', width: '400px', textAlign: 'center' },
  setupNote:           { margin: '20px 0' },
  setupInput:          { width: '100%', padding: '12px', fontSize: '18px', background: '#40444b', border: 'none', borderRadius: '4px', color: '#fff', marginBottom: '20px' },
  setupButton:         { padding: '12px 40px', background: '#5865f2', color: 'white', border: 'none', borderRadius: '4px', fontSize: '16px' },
  root:                { display: 'flex', height: '100vh', background: '#202225', color: '#fff', fontFamily: 'system-ui, sans-serif', overflow: 'hidden' },
  sidebar:             { width: '280px', background: '#2f3136', padding: '20px', borderRight: '1px solid #202225', overflowY: 'auto' },
  hr:                  { borderColor: '#40444b', margin: '20px 0' },
  hrVoice:             { borderColor: '#40444b', margin: '30px 0 10px' },
  onlineUser:          { color: '#b9bbbe', margin: '6px 0' },
  voiceUser:           { margin: '8px 0', display: 'flex', alignItems: 'center', gap: '8px' },
  voiceDot:            { color: '#3ba55c' },
  voiceUserFlex:       { flex: 1 },
  volumeSlider:        { width: '80px' },
  chatArea:            { flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 },
  chatHeader:          { padding: '12px 20px', background: '#36393f', borderBottom: '1px solid #202225', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '12px' },
  messageList:         { flex: 1, padding: '20px', overflowY: 'auto' },
  message:             { marginBottom: '16px' },
  inputRow:            { padding: '16px', background: '#36393f' },
  inputFlex:           { display: 'flex' },
  messageInput:        { flex: 1, padding: '12px', background: '#40444b', border: 'none', borderRadius: '4px', color: '#fff', outline: 'none' },
  sendButton:          { marginLeft: '8px', padding: '12px 24px', background: '#5865f2', color: 'white', border: 'none', borderRadius: '4px', fontWeight: 600 },
  voicePanel:          { width: '260px', background: '#2f3136', padding: '20px', borderLeft: '1px solid #202225', overflowY: 'auto' },
  relayCount:          { fontSize: '12px', color: '#72767d', textAlign: 'center', margin: '6px 0 4px' },
  searchInput:         { width: '100%', padding: '8px', background: '#40444b', border: 'none', borderRadius: '4px', color: '#fff', outline: 'none', boxSizing: 'border-box', marginBottom: '6px' },
  searchInputDisabled: { width: '100%', padding: '8px', background: '#2c2f33', border: 'none', borderRadius: '4px', color: '#4f545c', outline: 'none', boxSizing: 'border-box', marginBottom: '6px', cursor: 'not-allowed' },
  // Search results view
  resultsList:         { flex: 1, padding: '16px 20px', overflowY: 'auto' },
  resultItem:          { marginBottom: '20px', paddingBottom: '20px', borderBottom: '1px solid #40444b' },
  resultTitle:         { color: '#00b0f4', fontWeight: 600, fontSize: '15px', marginBottom: '2px' },
  resultUrl:           { color: '#3ba55c', fontSize: '12px', marginBottom: '4px' },
  resultSnippet:       { color: '#b9bbbe', fontSize: '13px', lineHeight: '1.5' },
  searchStatus:        { color: '#72767d', padding: '40px 0', textAlign: 'center' },
  searchError:         { color: '#ed4245', padding: '16px', background: '#2c2f33', borderRadius: '4px', fontSize: '13px' },
  backButton:          { padding: '4px 12px', background: '#40444b', color: '#b9bbbe', border: 'none', borderRadius: '4px', cursor: 'pointer', fontSize: '13px' },
  circuitBadge:        { fontSize: '11px', color: '#3ba55c', background: '#1e2d22', padding: '2px 8px', borderRadius: '10px', marginLeft: 'auto' },
};

const joinButtonOn:       CSSProperties = { width: '100%', padding: '14px', background: '#ed4245', color: 'white', border: 'none', borderRadius: '4px', fontSize: '16px', fontWeight: 600, marginBottom: '12px' };
const joinButtonOff:      CSSProperties = { width: '100%', padding: '14px', background: '#3ba55c', color: 'white', border: 'none', borderRadius: '4px', fontSize: '16px', fontWeight: 600, marginBottom: '12px' };
const muteButtonOn:       CSSProperties = { width: '100%', padding: '12px', background: '#ed4245', color: 'white', border: 'none', borderRadius: '4px' };
const muteButtonOff:      CSSProperties = { width: '100%', padding: '12px', background: '#5865f2', color: 'white', border: 'none', borderRadius: '4px' };
const relayButtonOn:      CSSProperties = { width: '100%', padding: '10px', background: '#3ba55c', color: 'white', border: 'none', borderRadius: '4px', marginBottom: '4px', fontSize: '14px', cursor: 'pointer' };
const relayButtonOff:     CSSProperties = { width: '100%', padding: '10px', background: '#40444b', color: '#b9bbbe', border: 'none', borderRadius: '4px', marginBottom: '4px', fontSize: '14px', cursor: 'pointer' };
const searchButtonSafe:   CSSProperties = { width: '100%', padding: '10px', background: '#5865f2', color: 'white', border: 'none', borderRadius: '4px', fontSize: '14px', cursor: 'pointer', fontWeight: 600 };
const searchButtonUnsafe: CSSProperties = { width: '100%', padding: '10px', background: '#2c2f33', color: '#4f545c', border: '1px solid #40444b', borderRadius: '4px', fontSize: '13px', cursor: 'not-allowed' };

// ─── Component ────────────────────────────────────────────────────────────────

function App() {
  const [username, setUsername]         = useState('');
  const [messages, setMessages]         = useState<{ id: string; from: string; text: string }[]>([]);
  const [onlineUsers, setOnlineUsers]   = useState<string[]>([]);
  const [inVoiceUsers, setInVoiceUsers] = useState<string[]>([]);
  const [isInVoice, setIsInVoice]       = useState(false);
  const [isMuted, setIsMuted]           = useState(false);
  const [newMessage, setNewMessage]     = useState('');
  const [showSetup, setShowSetup]       = useState(false);
  const [isRelayEnabled, setIsRelayEnabled]   = useState(false);
  const [availableRelays, setAvailableRelays] = useState<string[]>([]);
  const [searchQuery, setSearchQuery]   = useState('');
  const [activeView, setActiveView]     = useState<'chat' | 'search'>('chat');
  const [isSearching, setIsSearching]   = useState(false);
  const [searchResults, setSearchResults] = useState<SearchResult[]>([]);
  const [searchError, setSearchError]   = useState<string | null>(null);
  const [activeCircuit, setActiveCircuit] = useState<string[]>([]);

  // ── Refs ──────────────────────────────────────────────────────────────────
  const roomRef           = useRef<any>(null);
  const selfStreamRef     = useRef<MediaStream | null>(null);
  const remoteAudiosRef   = useRef<Record<string, HTMLAudioElement>>({});
  const volumesRef        = useRef<Record<string, number>>({});
  const sendChatRef       = useRef<((data: ChatMessage) => void) | null>(null);
  const sendVoiceStatusRef = useRef<((data: VoiceStatusMessage) => void) | null>(null);
  const peerUsernameRef   = useRef<Record<string, string>>({});
  const usernamePeerRef   = useRef<Record<string, string>>({});
  const usernameInputRef  = useRef<HTMLInputElement>(null);
  // Crypto
  const myPublicKeyRef    = useRef('');
  const myPrivateKeyRef   = useRef<CryptoKey | null>(null);
  const peerPublicKeysRef = useRef<Record<string, string>>({});
  // Relay availability
  const isRelayEnabledRef = useRef(false);
  const sendPeerKeyRef    = useRef<((d: PeerKeyMessage,    t?: string | string[]) => void) | null>(null);
  const sendRelayRef      = useRef<((d: RelayAvailMessage, t?: string | string[]) => void) | null>(null);
  // Circuit routing
  // Each entry maps circuitId → the peerId that sent us the forward packet (our return path)
  const circuitTableRef     = useRef<Record<string, { returnPeer: string; expiresAt: number }>>({});
  // Pending circuits we originated; resolve/reject when response arrives or times out
  const pendingCircuitsRef  = useRef<Record<string, { resolve: (d: string) => void; reject: (e: string) => void }>>({});
  const sendRelayFwdRef     = useRef<((d: OnionForwardPacket,  t?: string | string[]) => void) | null>(null);
  const sendRelayRespRef    = useRef<((d: OnionResponsePacket, t?: string | string[]) => void) | null>(null);

  // ── Effects ───────────────────────────────────────────────────────────────

  // Generate ECDH P-256 keypair once. Private key stays in memory only.
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
    const saved = localStorage.getItem('p2p-username');
    if (saved) setUsername(saved);
    else setShowSetup(true);
  }, []);

  useEffect(() => {
    if (!username) return;

    const room = joinRoom({
      appId: APP_ID,
      rtcConfig: { iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] }
    }, ROOM_ID);
    roomRef.current = room;

    // ── Chat ─────────────────────────────────────────────────────────────
    const [sendChat, getChat] = room.makeAction('chat');
    sendChatRef.current = sendChat;
    getChat((data: ChatMessage, peerId: string) => {
      peerUsernameRef.current[peerId]       = data.username;
      usernamePeerRef.current[data.username] = peerId;
      setMessages(prev => [...prev, { id: Date.now().toString(), from: data.username, text: data.text }]);
    });

    // ── Voice status ─────────────────────────────────────────────────────
    const [sendVoiceStatus, getVoiceStatus] = room.makeAction('voiceStatus');
    sendVoiceStatusRef.current = sendVoiceStatus;
    getVoiceStatus((data: VoiceStatusMessage, peerId: string) => {
      peerUsernameRef.current[peerId]       = data.username;
      usernamePeerRef.current[data.username] = peerId;
      if (data.inVoice) setInVoiceUsers(prev => prev.includes(data.username) ? prev : [...prev, data.username]);
      else              setInVoiceUsers(prev => prev.filter(u => u !== data.username));
    });

    // ── Key exchange ─────────────────────────────────────────────────────
    const [sendPeerKey, getPeerKey] = room.makeAction('peerKey');
    sendPeerKeyRef.current = sendPeerKey;
    getPeerKey((data: PeerKeyMessage, peerId: string) => {
      peerPublicKeysRef.current[peerId] = data.publicKeyBase64;
    });

    // ── Relay availability ────────────────────────────────────────────────
    const [sendRelay, getRelay] = room.makeAction('relayAvail');
    sendRelayRef.current = sendRelay;
    getRelay((data: RelayAvailMessage, peerId: string) => {
      if (data.isRelay) setAvailableRelays(prev => prev.includes(peerId) ? prev : [...prev, peerId]);
      else              setAvailableRelays(prev => prev.filter(id => id !== peerId));
    });

    // ── Onion forward ─────────────────────────────────────────────────────
    // Each relay receives an onion packet, peels one layer, and either forwards
    // it or makes the exit HTTP request.
    const [sendRelayFwd, getRelayFwd] = room.makeAction('relayFwd');
    sendRelayFwdRef.current = sendRelayFwd;
    getRelayFwd(async (data: OnionForwardPacket, senderPeerId: string) => {
      if (!isRelayEnabledRef.current) return;
      if (!myPrivateKeyRef.current)   return;

      // Record return path so we can route the response back
      circuitTableRef.current[data.circuitId] = {
        returnPeer: senderPeerId,
        expiresAt:  Date.now() + 60_000,
      };

      try {
        const plaintext   = await decryptLayer(data.layer, myPrivateKeyRef.current);
        const instruction: PlainInstruction = JSON.parse(plaintext);

        if (instruction.nextHop === 'exit') {
          // We are the exit node — fetch the URL from our Rust backend
          try {
            const html = await invoke<string>('relay_fetch', { url: instruction.payload });
            sendRelayRespRef.current?.(
              { circuitId: data.circuitId, data: html, isError: false },
              senderPeerId
            );
          } catch (fetchErr) {
            sendRelayRespRef.current?.(
              { circuitId: data.circuitId, data: String(fetchErr), isError: true },
              senderPeerId
            );
          }
        } else {
          // Middle relay — unwrap and forward to next hop
          const nextLayer: EncryptedLayer = JSON.parse(atob(instruction.payload));
          sendRelayFwdRef.current?.(
            { circuitId: data.circuitId, layer: nextLayer },
            instruction.nextHop
          );
        }
      } catch {
        // Decryption error — malformed packet, silently discard
      }
    });

    // ── Onion response ────────────────────────────────────────────────────
    // Response travels back through the circuit in reverse.
    const [sendRelayResp, getRelayResp] = room.makeAction('relayResp');
    sendRelayRespRef.current = sendRelayResp;
    getRelayResp((data: OnionResponsePacket) => {
      // Are we the original requester?
      const pending = pendingCircuitsRef.current[data.circuitId];
      if (pending) {
        delete pendingCircuitsRef.current[data.circuitId];
        if (data.isError) pending.reject(data.data);
        else              pending.resolve(data.data);
        return;
      }
      // We're a relay — route the response back to the previous hop
      const entry = circuitTableRef.current[data.circuitId];
      if (entry) {
        sendRelayRespRef.current?.(data, entry.returnPeer);
        delete circuitTableRef.current[data.circuitId];
      }
    });

    // ── Peer join / leave ─────────────────────────────────────────────────
    const updateOnline = () => {
      const peers = room.getPeers ? Object.keys(room.getPeers()) : [];
      setOnlineUsers([username, ...peers.map((p: string) => `User-${p.slice(0, 6)}`)]);
    };

    room.onPeerJoin((peerId: string) => {
      if (myPublicKeyRef.current) sendPeerKeyRef.current?.({ publicKeyBase64: myPublicKeyRef.current }, peerId);
      sendRelayRef.current?.({ isRelay: isRelayEnabledRef.current }, peerId);
      updateOnline();
    });

    room.onPeerLeave((peerId: string) => {
      const audio = remoteAudiosRef.current[peerId];
      if (audio) {
        audio.pause();
        (audio.srcObject as MediaStream | null)?.getTracks().forEach(t => t.stop());
        audio.srcObject = null;
        delete remoteAudiosRef.current[peerId];
      }
      const leavingUsername = peerUsernameRef.current[peerId];
      if (leavingUsername) {
        setInVoiceUsers(prev => prev.filter(u => u !== leavingUsername));
        delete usernamePeerRef.current[leavingUsername];
        delete peerUsernameRef.current[peerId];
      }
      setAvailableRelays(prev => prev.filter(id => id !== peerId));
      delete peerPublicKeysRef.current[peerId];
      // Clean up any open circuit entries routed through this peer
      Object.keys(circuitTableRef.current).forEach(cid => {
        if (circuitTableRef.current[cid].returnPeer === peerId)
          delete circuitTableRef.current[cid];
      });
      updateOnline();
    });

    updateOnline();

    // Broadcast our state to everyone already in the room
    if (myPublicKeyRef.current) sendPeerKeyRef.current?.({ publicKeyBase64: myPublicKeyRef.current });
    sendRelayRef.current?.({ isRelay: isRelayEnabledRef.current });

    room.onPeerStream((stream: MediaStream, peerId: string) => {
      const audio = new Audio();
      audio.srcObject = stream;
      audio.autoplay  = true;
      const saved = peerUsernameRef.current[peerId]
        ? volumesRef.current[peerUsernameRef.current[peerId]]
        : undefined;
      if (saved !== undefined) audio.volume = saved;
      remoteAudiosRef.current[peerId] = audio;
    });

    return () => {
      room.leave();
      Object.keys(remoteAudiosRef.current).forEach(pid => {
        const a = remoteAudiosRef.current[pid];
        a.pause();
        (a.srcObject as MediaStream | null)?.getTracks().forEach(t => t.stop());
        a.srcObject = null;
      });
      remoteAudiosRef.current  = {};
      peerUsernameRef.current  = {};
      usernamePeerRef.current  = {};
      peerPublicKeysRef.current = {};
      circuitTableRef.current  = {};
    };
  }, [username]);

  // ── Handlers ──────────────────────────────────────────────────────────────

  const saveUsername = (name: string) => {
    if (!name.trim()) return;
    localStorage.setItem('p2p-username', name);
    setUsername(name);
    setShowSetup(false);
  };

  const sendMessage = () => {
    if (!newMessage.trim() || !sendChatRef.current) return;
    sendChatRef.current({ username, text: newMessage });
    setMessages(prev => [...prev, { id: Date.now().toString(), from: 'You', text: newMessage }]);
    setNewMessage('');
  };

  const toggleVoice = async () => {
    if (isInVoice) {
      selfStreamRef.current?.getTracks().forEach(t => t.stop());
      sendVoiceStatusRef.current?.({ username, inVoice: false });
      setInVoiceUsers(prev => prev.filter(u => u !== username));
      setIsInVoice(false);
    } else {
      try {
        const stream = await navigator.mediaDevices.getUserMedia({
          audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true }
        });
        selfStreamRef.current = stream;
        setIsInVoice(true);
        roomRef.current.addStream(stream);
        sendVoiceStatusRef.current?.({ username, inVoice: true });
        setInVoiceUsers(prev => prev.includes(username) ? prev : [...prev, username]);
      } catch {
        alert('Could not access microphone');
      }
    }
  };

  const toggleMute = () => {
    if (!selfStreamRef.current) return;
    const track = selfStreamRef.current.getAudioTracks()[0];
    if (track) track.enabled = !track.enabled;
    setIsMuted(!track?.enabled);
  };

  const changeVolume = (targetUsername: string, value: number) => {
    const volume = value / 100;
    volumesRef.current[targetUsername] = volume;
    const peerId = usernamePeerRef.current[targetUsername];
    const audio  = peerId ? remoteAudiosRef.current[peerId] : undefined;
    if (audio) audio.volume = volume;
  };

  const toggleRelay = () => {
    const next = !isRelayEnabled;
    setIsRelayEnabled(next);
    isRelayEnabledRef.current = next;
    sendRelayRef.current?.({ isRelay: next });
  };

  const handleSearch = async () => {
    if (!canSearch || !searchQuery.trim()) return;

    // Select 3 relay peers that have also shared their public key
    const ready = availableRelays.filter(id => peerPublicKeysRef.current[id]);
    if (ready.length < 3) return;

    const circuit = [...ready].sort(() => Math.random() - 0.5).slice(0, 3) as [string, string, string];
    const url     = `https://html.duckduckgo.com/html/?q=${encodeURIComponent(searchQuery.trim())}`;

    setActiveView('search');
    setIsSearching(true);
    setSearchError(null);
    setSearchResults([]);
    setActiveCircuit(circuit);

    try {
      const packet = await buildOnionPacket(url, circuit, peerPublicKeysRef.current);

      const html = await new Promise<string>((resolve, reject) => {
        pendingCircuitsRef.current[packet.circuitId] = { resolve, reject };

        // Abort after 30 s — handles dropped relays and slow connections
        setTimeout(() => {
          if (pendingCircuitsRef.current[packet.circuitId]) {
            delete pendingCircuitsRef.current[packet.circuitId];
            reject('Search timed out — a relay may have gone offline');
          }
        }, 30_000);

        sendRelayFwdRef.current?.({ circuitId: packet.circuitId, layer: packet.layer }, circuit[0]);
      });

      setSearchResults(parseSearchResults(html));
    } catch (err) {
      setSearchError(String(err));
    } finally {
      setIsSearching(false);
    }
  };

  // ── Computed ──────────────────────────────────────────────────────────────

  const canSearch      = availableRelays.length >= 3;
  const relayShortfall = Math.max(0, 3 - availableRelays.length);

  // ── Render ────────────────────────────────────────────────────────────────

  if (showSetup) {
    return (
      <div style={S.setupRoot}>
        <div style={S.setupBox}>
          <h2>Welcome to Norway Friends</h2>
          <p style={S.setupNote}>Choose your permanent username (cannot be changed later)</p>
          <input
            ref={usernameInputRef}
            type="text"
            placeholder="Enter username"
            onKeyDown={e => e.key === 'Enter' && saveUsername(usernameInputRef.current?.value ?? '')}
            style={S.setupInput}
          />
          <button onClick={() => saveUsername(usernameInputRef.current?.value ?? '')} style={S.setupButton}>
            Continue
          </button>
        </div>
      </div>
    );
  }

  return (
    <div style={S.root}>

      {/* ── Sidebar ── */}
      <div style={S.sidebar}>
        <h2>Norway Friends</h2>
        <p>Room: {ROOM_ID}</p>
        <p>Your name: {username}</p>
        <hr style={S.hr} />

        <h3>Online ({onlineUsers.length})</h3>
        {onlineUsers.map(user => (
          <div key={`online-${user}`} style={S.onlineUser}>● {user}</div>
        ))}

        <hr style={S.hrVoice} />

        <h3>In Voice ({inVoiceUsers.length})</h3>
        {inVoiceUsers.map(user => (
          <div key={`voice-${user}`} style={S.voiceUser}>
            <span style={S.voiceDot}>●</span>
            <span style={S.voiceUserFlex}>{user}</span>
            <input
              type="range" min="0" max="200" defaultValue="100"
              onChange={e => changeVolume(user, Number(e.currentTarget.value))}
              style={S.volumeSlider}
            />
          </div>
        ))}
      </div>

      {/* ── Main area: Chat or Search results ── */}
      <div style={S.chatArea}>
        {activeView === 'chat' ? (
          <>
            <div style={S.chatHeader}>General Chat • Voice Meeting</div>
            <div style={S.messageList}>
              {messages.map(m => (
                <div key={m.id} style={S.message}><strong>{m.from}:</strong> {m.text}</div>
              ))}
            </div>
            <div style={S.inputRow}>
              <div style={S.inputFlex}>
                <input
                  value={newMessage}
                  onChange={e => setNewMessage(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && sendMessage()}
                  placeholder="Type a message..."
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
              <span>Results: {searchQuery}</span>
              {activeCircuit.length === 3 && (
                <span style={S.circuitBadge}>
                  3-hop circuit • {activeCircuit.map(id => id.slice(0, 4)).join(' → ')}
                </span>
              )}
            </div>
            <div style={S.resultsList}>
              {isSearching && (
                <div style={S.searchStatus}>
                  Routing through circuit: {activeCircuit.map(id => id.slice(0, 6)).join(' → ')} → internet
                </div>
              )}
              {searchError && <div style={S.searchError}>{searchError}</div>}
              {!isSearching && !searchError && searchResults.length === 0 && (
                <div style={S.searchStatus}>No results found</div>
              )}
              {searchResults.map((r, i) => (
                <div key={i} style={S.resultItem}>
                  <div style={S.resultTitle}>{r.title}</div>
                  <div style={S.resultUrl}>{r.url}</div>
                  <div style={S.resultSnippet}>{r.snippet}</div>
                </div>
              ))}
            </div>
          </>
        )}
      </div>

      {/* ── Right panel: Voice + Relay + Search ── */}
      <div style={S.voicePanel}>
        <button onClick={toggleVoice} style={isInVoice ? joinButtonOn : joinButtonOff}>
          {isInVoice ? 'Leave Voice Meeting' : 'Join Voice Meeting'}
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
        <div style={S.relayCount}>
          {availableRelays.length} relay{availableRelays.length !== 1 ? 's' : ''} online
        </div>

        <hr style={S.hr} />

        <input
          value={searchQuery}
          onChange={e => setSearchQuery(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handleSearch()}
          placeholder={canSearch ? 'Search...' : 'Need more relays...'}
          disabled={!canSearch}
          style={canSearch ? S.searchInput : S.searchInputDisabled}
        />
        <button onClick={handleSearch} disabled={!canSearch || isSearching}
          style={canSearch ? searchButtonSafe : searchButtonUnsafe}>
          {isSearching
            ? 'Searching...'
            : canSearch
              ? 'Search'
              : `Unsafe, ${relayShortfall} peer${relayShortfall !== 1 ? 's' : ''} needed`}
        </button>
      </div>

    </div>
  );
}

export default App;
