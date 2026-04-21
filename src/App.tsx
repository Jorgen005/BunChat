import { useState, useEffect, useRef, type CSSProperties } from 'react';
import { joinRoom } from 'trystero';

const APP_ID = 'norway-friends-p2p-v1';
const ROOM_ID = 'southern-norway-20';

interface ChatMessage {
  username: string;
  text: string;
}

interface VoiceStatusMessage {
  username: string;
  inVoice: boolean;
}

// Hoisted outside component — no new object allocated per render
const S: Record<string, CSSProperties> = {
  setupRoot:    { display: 'flex', height: '100vh', background: '#202225', color: '#fff', alignItems: 'center', justifyContent: 'center' },
  setupBox:     { background: '#2f3136', padding: '40px', borderRadius: '8px', width: '400px', textAlign: 'center' },
  setupNote:    { margin: '20px 0' },
  setupInput:   { width: '100%', padding: '12px', fontSize: '18px', background: '#40444b', border: 'none', borderRadius: '4px', color: '#fff', marginBottom: '20px' },
  setupButton:  { padding: '12px 40px', background: '#5865f2', color: 'white', border: 'none', borderRadius: '4px', fontSize: '16px' },
  root:         { display: 'flex', height: '100vh', background: '#202225', color: '#fff', fontFamily: 'system-ui, sans-serif', overflow: 'hidden' },
  sidebar:      { width: '280px', background: '#2f3136', padding: '20px', borderRight: '1px solid #202225' },
  hr:           { borderColor: '#40444b', margin: '20px 0' },
  hrVoice:      { borderColor: '#40444b', margin: '30px 0 10px' },
  onlineUser:   { color: '#b9bbbe', margin: '6px 0' },
  voiceUser:    { margin: '8px 0', display: 'flex', alignItems: 'center', gap: '8px' },
  voiceDot:     { color: '#3ba55c' },
  voiceUserFlex:{ flex: 1 },
  volumeSlider: { width: '80px' },
  chatArea:     { flex: 1, display: 'flex', flexDirection: 'column' },
  chatHeader:   { padding: '12px 20px', background: '#36393f', borderBottom: '1px solid #202225', fontWeight: 600 },
  messageList:  { flex: 1, padding: '20px', overflowY: 'auto' },
  message:      { marginBottom: '16px' },
  inputRow:     { padding: '16px', background: '#36393f' },
  inputFlex:    { display: 'flex' },
  messageInput: { flex: 1, padding: '12px', background: '#40444b', border: 'none', borderRadius: '4px', color: '#fff', outline: 'none' },
  sendButton:   { marginLeft: '8px', padding: '12px 24px', background: '#5865f2', color: 'white', border: 'none', borderRadius: '4px', fontWeight: 600 },
  voicePanel:   { width: '260px', background: '#2f3136', padding: '20px', borderLeft: '1px solid #202225' },
};

// Two constant objects per dynamic button — avoids allocating a new object every render
const joinButtonOn:  CSSProperties = { width: '100%', padding: '14px', background: '#ed4245', color: 'white', border: 'none', borderRadius: '4px', fontSize: '16px', fontWeight: 600, marginBottom: '12px' };
const joinButtonOff: CSSProperties = { width: '100%', padding: '14px', background: '#3ba55c', color: 'white', border: 'none', borderRadius: '4px', fontSize: '16px', fontWeight: 600, marginBottom: '12px' };
const muteButtonOn:  CSSProperties = { width: '100%', padding: '12px', background: '#ed4245', color: 'white', border: 'none', borderRadius: '4px' };
const muteButtonOff: CSSProperties = { width: '100%', padding: '12px', background: '#5865f2', color: 'white', border: 'none', borderRadius: '4px' };

function App() {
  const [username, setUsername] = useState('');
  const [messages, setMessages] = useState<{ id: string; from: string; text: string }[]>([]);
  const [onlineUsers, setOnlineUsers] = useState<string[]>([]);
  const [inVoiceUsers, setInVoiceUsers] = useState<string[]>([]);
  const [isInVoice, setIsInVoice] = useState(false);
  const [isMuted, setIsMuted] = useState(false);
  const [newMessage, setNewMessage] = useState('');
  const [showSetup, setShowSetup] = useState(false);

  const roomRef = useRef<any>(null);
  const selfStreamRef = useRef<MediaStream | null>(null);
  const remoteAudiosRef = useRef<{ [peerId: string]: HTMLAudioElement }>({});
  const volumesRef = useRef<{ [username: string]: number }>({});
  // Cached send functions — created once in the effect, not on every call
  const sendChatRef = useRef<((data: ChatMessage) => void) | null>(null);
  const sendVoiceStatusRef = useRef<((data: VoiceStatusMessage) => void) | null>(null);
  // Bidirectional username <-> peerId mapping for correct per-user volume control
  const peerUsernameRef = useRef<{ [peerId: string]: string }>({});
  const usernamePeerRef = useRef<{ [username: string]: string }>({});
  const usernameInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const saved = localStorage.getItem('p2p-username');
    if (saved) {
      setUsername(saved);
    } else {
      setShowSetup(true);
    }
  }, []);

  useEffect(() => {
    if (!username) return;

    const room = joinRoom({
      appId: APP_ID,
      rtcConfig: { iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] }
    }, ROOM_ID);

    roomRef.current = room;

    const [sendChat, getChat] = room.makeAction('chat');
    sendChatRef.current = sendChat;
    getChat((data: ChatMessage, peerId: string) => {
      peerUsernameRef.current[peerId] = data.username;
      usernamePeerRef.current[data.username] = peerId;
      setMessages(prev => [...prev, { id: Date.now().toString(), from: data.username, text: data.text }]);
    });

    const [sendVoiceStatus, getVoiceStatus] = room.makeAction('voiceStatus');
    sendVoiceStatusRef.current = sendVoiceStatus;
    getVoiceStatus((data: VoiceStatusMessage, peerId: string) => {
      peerUsernameRef.current[peerId] = data.username;
      usernamePeerRef.current[data.username] = peerId;
      if (data.inVoice) {
        setInVoiceUsers(prev => prev.includes(data.username) ? prev : [...prev, data.username]);
      } else {
        setInVoiceUsers(prev => prev.filter(u => u !== data.username));
      }
    });

    const updateOnline = () => {
      const peers = room.getPeers ? Object.keys(room.getPeers()) : [];
      setOnlineUsers([username, ...peers.map((p: string) => `User-${p.slice(0, 6)}`)]);
    };

    room.onPeerJoin(updateOnline);
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
      updateOnline();
    });

    updateOnline();

    room.onPeerStream((stream: MediaStream, peerId: string) => {
      const audio = new Audio();
      audio.srcObject = stream;
      audio.autoplay = true;
      // Apply any volume the user already set before the stream arrived
      const savedVolume = peerUsernameRef.current[peerId]
        ? volumesRef.current[peerUsernameRef.current[peerId]]
        : undefined;
      if (savedVolume !== undefined) audio.volume = savedVolume;
      remoteAudiosRef.current[peerId] = audio;
    });

    return () => {
      room.leave();
      Object.keys(remoteAudiosRef.current).forEach(peerId => {
        const audio = remoteAudiosRef.current[peerId];
        audio.pause();
        (audio.srcObject as MediaStream | null)?.getTracks().forEach(t => t.stop());
        audio.srcObject = null;
      });
      remoteAudiosRef.current = {};
      peerUsernameRef.current = {};
      usernamePeerRef.current = {};
    };
  }, [username]);

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
      if (selfStreamRef.current) selfStreamRef.current.getTracks().forEach(t => t.stop());
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
      } catch (err) {
        alert('Could not access microphone');
      }
    }
  };

  const toggleMute = () => {
    if (selfStreamRef.current) {
      const track = selfStreamRef.current.getAudioTracks()[0];
      if (track) track.enabled = !track.enabled;
      setIsMuted(!track?.enabled);
    }
  };

  const changeVolume = (targetUsername: string, value: number) => {
    const volume = value / 100;
    volumesRef.current[targetUsername] = volume;
    const peerId = usernamePeerRef.current[targetUsername];
    if (peerId) {
      const audio = remoteAudiosRef.current[peerId];
      if (audio) audio.volume = volume;
    }
  };

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
            onKeyDown={(e) => e.key === 'Enter' && saveUsername(usernameInputRef.current?.value || '')}
            style={S.setupInput}
          />
          <button onClick={() => saveUsername(usernameInputRef.current?.value || '')} style={S.setupButton}>
            Continue
          </button>
        </div>
      </div>
    );
  }

  return (
    <div style={S.root}>
      {/* Sidebar */}
      <div style={S.sidebar}>
        <h2>Norway Friends</h2>
        <p>Room: {ROOM_ID}</p>
        <p>Your name: {username}</p>
        <hr style={S.hr} />

        <h3>Online ({onlineUsers.length})</h3>
        {onlineUsers.map((user) => (
          <div key={`online-${user}`} style={S.onlineUser}>
            ● {user}
          </div>
        ))}

        <hr style={S.hrVoice} />

        <h3>In Voice ({inVoiceUsers.length})</h3>
        {inVoiceUsers.map((user) => (
          <div key={`voice-${user}`} style={S.voiceUser}>
            <span style={S.voiceDot}>●</span>
            <span style={S.voiceUserFlex}>{user}</span>
            <input
              type="range"
              min="0"
              max="200"
              defaultValue="100"
              onChange={(e) => changeVolume(user, Number(e.currentTarget.value))}
              style={S.volumeSlider}
            />
          </div>
        ))}
      </div>

      {/* Main Chat */}
      <div style={S.chatArea}>
        <div style={S.chatHeader}>
          General Chat • Voice Meeting
        </div>

        <div style={S.messageList}>
          {messages.map(m => (
            <div key={m.id} style={S.message}>
              <strong>{m.from}:</strong> {m.text}
            </div>
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
            <button onClick={sendMessage} style={S.sendButton}>
              Send
            </button>
          </div>
        </div>
      </div>

      {/* Voice Panel */}
      <div style={S.voicePanel}>
        <button
          onClick={toggleVoice}
          style={isInVoice ? joinButtonOn : joinButtonOff}
        >
          {isInVoice ? 'Leave Voice Meeting' : 'Join Voice Meeting'}
        </button>

        {isInVoice && (
          <button
            onClick={toggleMute}
            style={isMuted ? muteButtonOn : muteButtonOff}
          >
            {isMuted ? 'Unmute' : 'Mute'}
          </button>
        )}
      </div>
    </div>
  );
}

export default App;
