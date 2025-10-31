const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const axios = require('axios');

const app = express();

let cookieParser;
try {
  cookieParser = require('cookie-parser');
  app.use(cookieParser());
} catch {
  console.log('cookie-parser not installed. Run: npm install cookie-parser');
}

app.use(express.urlencoded({ extended: true }));
const server = http.createServer(app);
const io = new Server(server, { pingInterval: 10000, pingTimeout: 5000 });

// --- Helpers ---
function cookieExpiryAtUTCMidnight() {
  const d = new Date();
  d.setUTCHours(23, 59, 59, 999);
  return d;
}

function parseCookies(header) {
  const list = {};
  if (!header) return list;
  header.split(';').forEach(c => {
    const p = c.split('=');
    const name = p.shift().trim();
    const value = decodeURIComponent(p.join('='));
    if (name) list[name] = value;
  });
  return list;
}

app.use(express.static(path.join(__dirname, 'public')));

// --- Routes ---
app.get('/login', (_, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.post('/api/login', (req, res) => {
  const { username } = req.body;
  if (!username || username.trim() === '') return res.status(400).send('Username is required.');
  res.cookie('username', username.trim(), {
    expires: cookieExpiryAtUTCMidnight(),
    httpOnly: true,
    sameSite: 'Lax',
  });
  res.redirect('/');
});
app.get('/api/verify', (req, res) => {
  const u = req.cookies.username;
  if (u) return res.json({ valid: true, username: u });
  res.json({ valid: false });
});
app.get('/broadcast', (_, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/', (req, res) => {
  if (!req.cookies.username) return res.redirect('/login');
  res.sendFile(path.join(__dirname, 'public', 'client.html'));
});

// --- SOCKET.IO ---
let adminSocket = null;
let clients = new Map();

function getClientList() {
  return Array.from(clients.entries()).map(([id, c]) => ({
    id,
    username: c.username,
    ip: c.ip,
    isp: c.isp,
    country: c.country,
    vpn: c.vpn,
    ping: c.ping,
  }));
}

io.on('connection', socket => {
  // --- Guest connect ---
  socket.on('join_guest', async guestId => {
    const ip = socket.handshake.headers['x-forwarded-for']?.split(',')[0] || socket.handshake.address;

    let isp = 'Pending login', country = 'Unknown', vpn = false;
    try {
      const r = await axios.get(`http://ip-api.com/json/${ip}?fields=status,country,isp,proxy,hosting,query`);
      if (r.data.status === 'success') {
        isp = normalizeISP(r.data.isp);
        country = r.data.country || 'Unknown';
        vpn = r.data.proxy || r.data.hosting;
      }
    } catch {}

    clients.set(socket.id, {
      ping: 0,
      username: `${guestId} (Not logged in yet)`,
      ip,
      isp,
      country,
      vpn,
    });
    socket.join('clients');
    if (adminSocket) adminSocket.emit('client_list', getClientList());
    console.log(`Guest joined: ${guestId} IP=${ip} ISP=${isp} Country=${country} VPN=${vpn}`);
  });

  // --- Client join ---
  socket.on('join', async role => {
    if (role === 'admin') {
      if (adminSocket) {
        socket.emit('error', 'Admin already connected');
        socket.disconnect();
        return;
      }
      adminSocket = socket;
      socket.emit('client_list', getClientList());
      console.log('Admin connected:', socket.id);
      return;
    }

    if (role !== 'client') return;

    const cookieHeader = socket.handshake.headers.cookie || '';
    const parsed = parseCookies(cookieHeader);
    const username = parsed.username;
    if (!username) {
      socket.emit('forbidden', 'Login required.');
      setTimeout(() => socket.disconnect(true), 50);
      return;
    }

    if (clients.has(socket.id)) {
      const prev = clients.get(socket.id);
      if (prev.username.includes('Guest-')) {
        clients.set(socket.id, { ...prev, username });
        if (adminSocket) adminSocket.emit('client_list', getClientList());
        console.log(`Guest upgraded → user: ${username}`);
      }
    }

    const ip = socket.handshake.headers['x-forwarded-for']?.split(',')[0] || socket.handshake.address;
    let isp = 'Unknown', country = 'Unknown', vpn = false;

    try {
      const r = await axios.get(`http://ip-api.com/json/${ip}?fields=status,country,isp,proxy,hosting,query`);
      if (r.data.status === 'success') {
        isp = normalizeISP(r.data.isp);
        country = r.data.country;
        vpn = r.data.proxy || r.data.hosting;
      }
    } catch {}

    clients.set(socket.id, { ping: 0, username, ip, isp, country, vpn });
    socket.join('clients');
    socket.emit('connected', true);
    if (adminSocket) adminSocket.emit('client_list', getClientList());
    console.log(`Client ${username} connected IP=${ip} ISP=${isp} ${country} VPN=${vpn}`);
  });

  socket.on('pong', t => {
    const ping = Date.now() - t;
    if (clients.has(socket.id)) {
      const c = clients.get(socket.id);
      clients.set(socket.id, { ...c, ping });
      if (adminSocket) adminSocket.emit('client_list', getClientList());
    }
  });

  socket.on('disconnect', reason => {
    if (socket === adminSocket) {
      adminSocket = null;
      console.log('Admin disconnected.');
    } else {
      const c = clients.get(socket.id);
      const name = c ? c.username : 'Unknown';
      clients.delete(socket.id);
      if (adminSocket) adminSocket.emit('client_list', getClientList());
      console.log(`Disconnected: ${name} (${socket.id}) reason=${reason}`);
    }
  });
});

function normalizeISP(raw) {
  if (!raw) return 'Unknown';
  const low = raw.toLowerCase();
  const map = [
    { k: ['ethionet', 'ethiotelecom', 'ethio telecom'], n: 'Ethio Telecom' },
    { k: ['safaricom', 'vodafone'], n: 'Safaricom Ethiopia PLC' },
    { k: ['mtn'], n: 'MTN Group' },
    { k: ['airtel'], n: 'Airtel Africa' },
    { k: ['google'], n: 'Google Cloud' },
    { k: ['aws', 'amazon'], n: 'Amazon Web Services' },
    { k: ['azure', 'microsoft'], n: 'Microsoft Azure' },
    { k: ['oracle'], n: 'Oracle Cloud' },
    { k: ['ovh'], n: 'OVHcloud' },
    { k: ['hetzner'], n: 'Hetzner Online' },
    { k: ['cloudflare'], n: 'Cloudflare' },
    { k: ['starlink'], n: 'Starlink Internet' },
    { k: ['hostinger'], n: 'Hostinger' },
    { k: ['contabo'], n: 'Contabo GmbH' },
    { k: ['linode'], n: 'Linode (Akamai)' },
  ];
  for (const e of map) if (e.k.some(k => low.includes(k))) return e.n;
  return raw;
}

setInterval(() => io.emit('ping', Date.now()), 5000);
server.listen(process.env.PORT || 5000, '0.0.0.0', () => console.log('Server running...'));
