import { useState, useEffect, useRef } from 'react';
import { joinRoom, selfId } from 'trystero';

const APP_ID = 'norway-friends-p2p-v1';
const ROOM_ID = 'southern-norway-20';

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

  // Username setup
  useEffect(() => {
    const saved = localStorage.getItem('p2p-username');
    if (saved) {
      setUsername(saved);
    } else {
      setShowSetup(true);
    }
  }, []);

  // Join room
  useEffect(() => {
    if (!username) return;

    const room = joinRoom({
      appId: APP_ID,
      rtcConfig: { iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] }
    }, ROOM_ID);

    roomRef.current = room;

    const [sendChat, getChat] = room.makeAction('chat');
    getChat((data: any) => {
      setMessages(prev => [...prev, { id: Date.now().toString(), from: data.username, text: data.text }]);
    });

    // Voice status from others
    const [sendVoiceStatus, getVoiceStatus] = room.makeAction('voiceStatus');
    getVoiceStatus((data: any) => {
      if (data.inVoice) {
        setInVoiceUsers(prev => prev.includes(data.username) ? prev : [...prev, data.username]);
      } else {
        setInVoiceUsers(prev => prev.filter(u => u !== data.username));
      }
    });

    // Online list
    const updateOnline = () => {
      const peers = room.getPeers ? Object.keys(room.getPeers()) : [];
      setOnlineUsers([username, ...peers.map(p => `User-${p.slice(0,6)}`)]);
    };
    room.onPeerJoin(updateOnline);
    room.onPeerLeave(updateOnline);
    const interval = setInterval(updateOnline, 2000);
    updateOnline();

    // Real voice streaming
    room.onPeerStream((stream: MediaStream, peerId: string) => {
      const audio = new Audio();
      audio.srcObject = stream;
      audio.autoplay = true;
      remoteAudiosRef.current[peerId] = audio;
    });

    return () => {
      clearInterval(interval);
      room.leave();
    };
  }, [username]);

  const saveUsername = (name: string) => {
    if (!name.trim()) return;
    localStorage.setItem('p2p-username', name);
    setUsername(name);
    setShowSetup(false);
  };

  const sendMessage = () => {
    if (!newMessage.trim() || !roomRef.current) return;
    const [sendChat] = roomRef.current.makeAction('chat');
    sendChat({ username, text: newMessage });
    setMessages(prev => [...prev, { id: Date.now().toString(), from: 'You', text: newMessage }]);
    setNewMessage('');
  };

  const toggleVoice = async () => {
    if (isInVoice) {
      if (selfStreamRef.current) selfStreamRef.current.getTracks().forEach(t => t.stop());
      const [sendVoiceStatus] = roomRef.current.makeAction('voiceStatus');
      sendVoiceStatus({ username, inVoice: false });
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

        const [sendVoiceStatus] = roomRef.current.makeAction('voiceStatus');
        sendVoiceStatus({ username, inVoice: true });
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
    volumesRef.current[targetUsername] = value / 100;
    Object.keys(remoteAudiosRef.current).forEach(key => {
      const audio = remoteAudiosRef.current[key];
      if (audio) audio.volume = volumesRef.current[targetUsername] || 1;
    });
  };

  if (showSetup) {
    return (
      <div style={{ display: 'flex', height: '100vh', background: '#202225', color: '#fff', alignItems: 'center', justifyContent: 'center' }}>
        <div style={{ background: '#2f3136', padding: '40px', borderRadius: '8px', width: '400px', textAlign: 'center' }}>
          <h2>Welcome to Norway Friends</h2>
          <p style={{ margin: '20px 0' }}>Choose your permanent username (cannot be changed later)</p>
          <input
            type="text"
            placeholder="Enter username"
            onKeyDown={(e) => e.key === 'Enter' && saveUsername((e.target as HTMLInputElement).value)}
            style={{ width: '100%', padding: '12px', fontSize: '18px', background: '#40444b', border: 'none', borderRadius: '4px', color: '#fff', marginBottom: '20px' }}
          />
          <button onClick={() => saveUsername((document.querySelector('input') as HTMLInputElement).value)} style={{ padding: '12px 40px', background: '#5865f2', color: 'white', border: 'none', borderRadius: '4px', fontSize: '16px' }}>
            Continue
          </button>
        </div>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', height: '100vh', background: '#202225', color: '#fff', fontFamily: 'system-ui, sans-serif', overflow: 'hidden' }}>
      {/* Sidebar */}
      <div style={{ width: '280px', background: '#2f3136', padding: '20px', borderRight: '1px solid #202225' }}>
        <h2>Norway Friends</h2>
        <p>Room: {ROOM_ID}</p>
        <p>Your name: {username}</p>
        <hr style={{ borderColor: '#40444b', margin: '20px 0' }} />

        <h3>Online ({onlineUsers.length})</h3>
        {onlineUsers.map((user, i) => (
          <div key={i} style={{ color: '#b9bbbe', margin: '6px 0' }}>
            ● {user}
          </div>
        ))}

        <hr style={{ borderColor: '#40444b', margin: '30px 0 10px' }} />

        <h3>In Voice ({inVoiceUsers.length})</h3>
        {inVoiceUsers.map((user, i) => (
          <div key={i} style={{ margin: '8px 0', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ color: '#3ba55c' }}>●</span>
            <span style={{ flex: 1 }}>{user}</span>
            <input
              type="range"
              min="0"
              max="200"
              defaultValue="100"
              onChange={(e) => changeVolume(user, parseInt(e.target.value))}
              style={{ width: '80px' }}
            />
          </div>
        ))}
      </div>

      {/* Main Chat */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
        <div style={{ padding: '12px 20px', background: '#36393f', borderBottom: '1px solid #202225', fontWeight: '600' }}>
          General Chat • Voice Meeting
        </div>

        <div style={{ flex: 1, padding: '20px', overflowY: 'auto' }}>
          {messages.map(m => (
            <div key={m.id} style={{ marginBottom: '16px' }}>
              <strong>{m.from}:</strong> {m.text}
            </div>
          ))}
        </div>

        <div style={{ padding: '16px', background: '#36393f' }}>
          <div style={{ display: 'flex' }}>
            <input
              value={newMessage}
              onChange={e => setNewMessage(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && sendMessage()}
              placeholder="Type a message..."
              style={{ flex: 1, padding: '12px', background: '#40444b', border: 'none', borderRadius: '4px', color: '#fff', outline: 'none' }}
            />
            <button onClick={sendMessage} style={{ marginLeft: '8px', padding: '12px 24px', background: '#5865f2', color: 'white', border: 'none', borderRadius: '4px', fontWeight: '600' }}>
              Send
            </button>
          </div>
        </div>
      </div>

      {/* Voice Panel */}
      <div style={{ width: '260px', background: '#2f3136', padding: '20px', borderLeft: '1px solid #202225' }}>
        <button
          onClick={toggleVoice}
          style={{
            width: '100%',
            padding: '14px',
            background: isInVoice ? '#ed4245' : '#3ba55c',
            color: 'white',
            border: 'none',
            borderRadius: '4px',
            fontSize: '16px',
            fontWeight: '600',
            marginBottom: '12px'
          }}
        >
          {isInVoice ? 'Leave Voice Meeting' : 'Join Voice Meeting'}
        </button>

        {isInVoice && (
          <button
            onClick={toggleMute}
            style={{ width: '100%', padding: '12px', background: isMuted ? '#ed4245' : '#5865f2', color: 'white', border: 'none', borderRadius: '4px' }}
          >
            {isMuted ? 'Unmute' : 'Mute'}
          </button>
        )}
      </div>
    </div>
  );
}

export default App;
