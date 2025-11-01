'use strict';

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const axios = require('axios');
const cookieParser = require('cookie-parser');

const app = express();
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

const server = http.createServer(app);
const io = new Server(server, { pingInterval: 10000, pingTimeout: 5000 });

// --- Helpers ---
function cookieExpiryAtUTCMidnight() {
  const d = new Date();
  d.setUTCHours(23, 59, 59, 999);
  return d;
}

function flagEmoji(code) {
  if (!code || code.length !== 2) return '';
  return String.fromCodePoint(...[...code.toUpperCase()].map(c => 0x1F1E6 - 65 + c.charCodeAt(0)));
}

function normalizeISP(raw) {
  if (!raw) return 'Unknown';
  const low = raw.toLowerCase();
  const map = [
    { k: ['ethionet', 'ethiotelecom'], n: 'Ethio Telecom' },
    { k: ['safaricom', 'vodafone'], n: 'Safaricom Ethiopia' },
    { k: ['mtn'], n: 'MTN Group' },
    { k: ['airtel'], n: 'Airtel' },
    { k: ['aws', 'amazon'], n: 'Amazon Web Services' },
    { k: ['azure', 'microsoft'], n: 'Microsoft Azure' },
    { k: ['oracle'], n: 'Oracle Cloud' },
    { k: ['ovh'], n: 'OVHcloud' },
    { k: ['hetzner'], n: 'Hetzner' },
    { k: ['cloudflare'], n: 'Cloudflare' },
    { k: ['starlink'], n: 'Starlink' },
    { k: ['contabo'], n: 'Contabo' }
  ];
  for (const e of map) if (e.k.some(k => low.includes(k))) return e.n;
  return raw;
}

async function lookupIP(ip) {
  if (!ip || ip.startsWith('127.') || ip.startsWith('::1')) {
    return { ip, city: 'Local', region: 'Local', country: 'Local', countryFlag: '🏠', isp: 'Local Network', vpn: false };
  }
  try {
    const r = await axios.get(`https://ipapi.co/${ip}/json/`);
    return {
      ip,
      city: r.data.city || 'Unknown',
      region: r.data.region || 'Unknown',
      country: r.data.country_name || 'Unknown',
      countryFlag: flagEmoji(r.data.country_code || ''),
      isp: normalizeISP(r.data.org || r.data.isp),
      vpn: !!(r.data.proxy || r.data.anonymous)
    };
  } catch {
    return { ip, city: 'Unknown', region: 'Unknown', country: 'Unknown', countryFlag: '', isp: 'Unknown', vpn: false };
  }
}

// --- Routes ---
app.get('/login', (_, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.post('/api/login', (req, res) => {
  const username = req.body.username?.trim();
  if (!username) return res.status(400).send('Username required');
  res.cookie('username', username, { expires: cookieExpiryAtUTCMidnight(), httpOnly: true, sameSite: 'Lax' });
  res.redirect('/');
});
app.get('/broadcast', (_, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/', (req, res) => {
  if (!req.cookies.username) return res.redirect('/login');
  res.sendFile(path.join(__dirname, 'public', 'client.html'));
});

// --- Socket.IO ---
let adminSocket = null;
const clients = new Map();
let isStreaming = false;
let isHidden = false;
let currentQrValue = null;

function getClientList() {
  return Array.from(clients.entries()).map(([id, c]) => ({ id, ...c }));
}

// --- SOCKET HANDLERS ---
io.on('connection', (socket) => {
  // 1️⃣ Guest connects before login
  socket.on('join_guest', async (guestLabel = 'Unknown') => {
    const ip = socket.handshake.headers['x-forwarded-for']?.split(',')[0] || socket.handshake.address;
    const info = await lookupIP(ip);
    clients.set(socket.id, {
      username: `${guestLabel} (Not logged in yet)`,
      ...info,
      ping: 0
    });
    socket.join('clients');
    if (adminSocket) adminSocket.emit('client_list', getClientList());
    console.log(`Guest joined (${ip})`);
  });

  // 2️⃣ Normal client joins after login
  socket.on('join', async (role) => {
    if (role === 'admin') {
      if (adminSocket) {
        socket.emit('error', 'Admin already connected');
        socket.disconnect();
        return;
      }
      adminSocket = socket;
      socket.emit('state', { isStreaming, isHidden, currentQrValue });
      socket.emit('client_list', getClientList());
      console.log('Admin connected');
      return;
    }

    if (role === 'client') {
      const username = socket.handshake.headers.cookie?.split('username=')[1]?.split(';')[0];
      const ip = socket.handshake.headers['x-forwarded-for']?.split(',')[0] || socket.handshake.address;
      const info = await lookupIP(ip);

      // If same socket already exists as guest, update username
      if (clients.has(socket.id)) {
        clients.set(socket.id, { ...clients.get(socket.id), username });
      } else {
        clients.set(socket.id, { username, ...info, ping: 0 });
      }

      socket.join('clients');
      if (isStreaming && !isHidden && currentQrValue) socket.emit('qr_update', currentQrValue);
      if (adminSocket) adminSocket.emit('client_list', getClientList());
      console.log(`Client logged in: ${username} (${ip})`);
    }
  });

  // 3️⃣ Admin starts/stops QR stream
  socket.on('start_stream', () => {
    if (socket !== adminSocket) return;
    isStreaming = true;
    io.to('clients').emit('stream_status', true);
  });

  socket.on('stop_stream', () => {
    if (socket !== adminSocket) return;
    isStreaming = false;
    currentQrValue = null;
    io.to('clients').emit('qr_update', null);
  });

  // 4️⃣ Admin toggles QR visibility
  socket.on('toggle_hide', (hide) => {
    if (socket !== adminSocket) return;
    isHidden = !!hide;
    io.to('clients').emit('qr_update', isHidden ? null : currentQrValue);
    if (adminSocket) adminSocket.emit('hide_state', isHidden);
  });

  // 5️⃣ Admin QR updates
  socket.on('qr_update', (val) => {
    if (socket !== adminSocket || !isStreaming) return;
    if (val && val !== currentQrValue) {
      currentQrValue = val;
      if (!isHidden) io.to('clients').emit('qr_update', val);
      if (adminSocket) adminSocket.emit('qr_preview', val);
    }
  });

  // 6️⃣ Ping/Pong updates
  socket.on('pong', (t) => {
    const ping = Date.now() - t;
    if (clients.has(socket.id)) {
      const c = clients.get(socket.id);
      clients.set(socket.id, { ...c, ping });
      if (adminSocket) adminSocket.emit('client_list', getClientList());
    }
  });

  // 7️⃣ Disconnect cleanup
  socket.on('disconnect', () => {
    if (socket === adminSocket) {
      adminSocket = null;
      isStreaming = false;
      console.log('Admin disconnected');
    } else {
      clients.delete(socket.id);
      if (adminSocket) adminSocket.emit('client_list', getClientList());
    }
  });
});

setInterval(() => io.emit('ping', Date.now()), 5000);

const PORT = process.env.PORT || 5000;
server.listen(PORT, '0.0.0.0', () => console.log(`✅ Server running on port ${PORT}`));
