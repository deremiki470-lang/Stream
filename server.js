'use strict';

const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const axios = require('axios');

const app = express();

let cookieParser;
try {
  cookieParser = require('cookie-parser');
  app.use(cookieParser());
} catch (err) {
  console.log('cookie-parser not installed. Run: npm install cookie-parser');
}

app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

const server = http.createServer(app);
const io = new socketIo.Server(server, { pingInterval: 10000, pingTimeout: 5000 });

// --- Helpers ---
function cookieExpiryAtUTCMidnight() {
  const expiry = new Date();
  expiry.setUTCHours(23, 59, 59, 999);
  return expiry;
}

function parseCookies(header) {
  const list = {};
  if (!header) return list;
  header.split(';').forEach(cookie => {
    const parts = cookie.split('=');
    const name = parts.shift().trim();
    if (name) list[name] = decodeURIComponent(parts.join('='));
  });
  return list;
}

function flagEmoji(code) {
  if (!code || code.length !== 2) return '';
  const upper = code.toUpperCase();
  return String.fromCodePoint(
    upper.charCodeAt(0) - 65 + 0x1f1e6,
    upper.charCodeAt(1) - 65 + 0x1f1e6
  );
}

function normalizeISP(raw) {
  if (!raw) return 'Unknown';
  const low = raw.toLowerCase();
  const map = [
    { k: ['ethionet', 'ethiotelecom', 'ethio telecom'], n: 'Ethio Telecom' },
    { k: ['safaricom', 'vodafone'], n: 'Safaricom Ethiopia PLC' },
    { k: ['mtn'], n: 'MTN Group' },
    { k: ['airtel'], n: 'Airtel Africa' },
    { k: ['aws', 'amazon'], n: 'Amazon Web Services' },
    { k: ['azure', 'microsoft'], n: 'Microsoft Azure' },
    { k: ['oracle'], n: 'Oracle Cloud' },
    { k: ['ovh'], n: 'OVHcloud' },
    { k: ['hetzner'], n: 'Hetzner Online' },
    { k: ['cloudflare'], n: 'Cloudflare' },
    { k: ['starlink'], n: 'Starlink Internet' },
    { k: ['hostinger'], n: 'Hostinger' },
    { k: ['contabo'], n: 'Contabo GmbH' },
    { k: ['linode'], n: 'Linode (Akamai)' }
  ];
  for (const e of map) if (e.k.some(k => low.includes(k))) return e.n;
  return raw;
}

function normalizeAddress(ip) {
  if (!ip) return 'Unknown';
  ip = String(ip).trim();
  if (ip.startsWith('::ffff:')) return ip.slice(7);
  if (ip === '::1') return '127.0.0.1';
  return ip;
}

function isPrivate(ip) {
  if (!ip) return false;
  return (
    ip === '127.0.0.1' ||
    ip.startsWith('10.') ||
    ip.startsWith('192.168.') ||
    (ip.startsWith('172.') && (() => {
      const s = parseInt(ip.split('.')[1]);
      return s >= 16 && s <= 31;
    })())
  );
}

async function lookupIP(ip) {
  ip = normalizeAddress(ip);
  if (isPrivate(ip)) {
    return {
      ip,
      city: 'Local Network',
      region: 'Local',
      country: 'Local',
      countryCode: '',
      isp: 'Local',
      vpn: false
    };
  }
  try {
    const { data } = await axios.get(
      `http://ip-api.com/json/${ip}?fields=status,country,countryCode,regionName,city,isp,proxy,hosting`
    );
    if (data.status === 'success') {
      return {
        ip,
        city: data.city || 'Unknown',
        region: data.regionName || 'Unknown',
        country: data.country || 'Unknown',
        countryCode: data.countryCode || '',
        isp: normalizeISP(data.isp),
        vpn: data.proxy || data.hosting
      };
    }
  } catch {}
  return { ip, city: 'Unknown', region: 'Unknown', country: 'Unknown', countryCode: '', isp: 'Unknown', vpn: false };
}

// --- Routes ---
app.get('/login', (_, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.post('/api/login', (req, res) => {
  const username = req.body.username;
  if (!username || !username.trim()) return res.status(400).send('Username required');
  res.cookie('username', username.trim(), { expires: cookieExpiryAtUTCMidnight(), httpOnly: true, sameSite: 'Lax' });
  res.redirect('/');
});
app.get('/api/verify', (req, res) => {
  const username = req.cookies?.username;
  if (username) return res.json({ valid: true, username });
  res.json({ valid: false });
});
app.get('/broadcast', (_, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/', (req, res) => {
  if (!req.cookies?.username) return res.redirect('/login');
  res.sendFile(path.join(__dirname, 'public', 'client.html'));
});

// --- Socket.IO ---
let adminSocket = null;
let clients = new Map();
let isStreaming = false;
let currentQrValue = null;
let isHidden = false;

function getClientList() {
  return Array.from(clients.entries()).map(([id, c]) => ({ id, ...c }));
}
function updateAdmin() {
  if (adminSocket) adminSocket.emit('client_list', getClientList());
}

io.on('connection', (socket) => {
  socket.on('join_guest', async (guestId) => {
    const ip = socket.handshake.headers['x-forwarded-for']?.split(',')[0] || socket.handshake.address;
    const info = await lookupIP(ip);
    clients.set(socket.id, {
      username: `${guestId} (Not logged in yet)`,
      ...info,
      countryFlag: flagEmoji(info.countryCode),
      ping: 0
    });
    socket.join('clients');
    updateAdmin();
  });

  socket.on('join', async (role) => {
    if (role === 'admin') {
      if (adminSocket) return socket.emit('error', 'Admin already connected');
      adminSocket = socket;
      socket.emit('state', { isStreaming, isHidden, currentQrValue });
      updateAdmin();
      return;
    }

    if (role === 'client') {
      const parsed = parseCookies(socket.handshake.headers.cookie || '');
      const username = parsed.username;
      if (!username) return socket.disconnect(true);
      const ip = socket.handshake.headers['x-forwarded-for']?.split(',')[0] || socket.handshake.address;
      const info = await lookupIP(ip);
      clients.set(socket.id, {
        username,
        ...info,
        countryFlag: flagEmoji(info.countryCode),
        ping: 0
      });
      socket.join('clients');
      if (isStreaming && !isHidden && currentQrValue) socket.emit('qr_update', currentQrValue);
      updateAdmin();
    }
  });

  socket.on('start_stream', () => {
    if (socket !== adminSocket) return;
    isStreaming = true;
    if (adminSocket) adminSocket.emit('state', { isStreaming, isHidden, currentQrValue });
  });

  socket.on('stop_stream', () => {
    if (socket !== adminSocket) return;
    isStreaming = false;
    currentQrValue = null;
    io.to('clients').emit('qr_update', null);
    if (adminSocket) adminSocket.emit('state', { isStreaming, isHidden, currentQrValue });
  });

  socket.on('toggle_hide', (hide) => {
    if (socket !== adminSocket) return;
    isHidden = !!hide;
    io.to('clients').emit('qr_update', isHidden ? null : currentQrValue);
    if (adminSocket) adminSocket.emit('hide_state', isHidden);
  });

  socket.on('qr_update', (val) => {
    if (socket !== adminSocket || !isStreaming) return;
    if (val && val !== currentQrValue) {
      currentQrValue = val;
      if (!isHidden) io.to('clients').emit('qr_update', val);
      if (adminSocket) adminSocket.emit('qr_preview', val);
    }
  });

  socket.on('request_client_list', () => {
    if (socket === adminSocket) socket.emit('client_list', getClientList());
  });

  socket.on('pong', (t) => {
    const ping = Date.now() - t;
    if (clients.has(socket.id)) {
      const c = clients.get(socket.id);
      clients.set(socket.id, { ...c, ping });
      updateAdmin();
    } else if (socket === adminSocket) {
      socket.emit('your_ping', ping);
    }
  });

  socket.on('disconnect', () => {
    if (socket === adminSocket) {
      adminSocket = null;
      isStreaming = false;
      currentQrValue = null;
      io.to('clients').emit('qr_update', null);
    } else {
      clients.delete(socket.id);
      updateAdmin();
    }
  });
});

setInterval(() => io.emit('ping', Date.now()), 5000);
const PORT = process.env.PORT || 5000;
server.listen(PORT, '0.0.0.0', () => console.log(`Server running on ${PORT}`));
