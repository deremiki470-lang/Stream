const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const axios = require('axios');

const app = express();

// Optional cookie parser
let cookieParser;
try {
  cookieParser = require('cookie-parser');
  app.use(cookieParser());
} catch (e) {
  console.log('cookie-parser not installed. Run: npm install cookie-parser');
}

app.use(express.urlencoded({ extended: true }));
const server = http.createServer(app);
const io = new Server(server, {
  pingInterval: 10000,
  pingTimeout: 5000,
});

// ----------------- Helpers -----------------
function cookieExpiryAtUTCMidnight() {
  const expiry = new Date();
  expiry.setUTCHours(23, 59, 59, 999);
  return expiry;
}

function parseCookies(cookieHeader) {
  const list = {};
  if (!cookieHeader) return list;
  cookieHeader.split(';').forEach(function (cookie) {
    const parts = cookie.split('=');
    const name = parts.shift().trim();
    const value = decodeURIComponent(parts.join('='));
    if (name) list[name] = value;
  });
  return list;
}

// ----------------- Static -----------------
app.use(express.static(path.join(__dirname, 'public')));

// ----------------- Routes -----------------
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/api/login', (req, res) => {
  const { username } = req.body;
  if (!username || username.trim().length === 0) {
    return res.status(400).send('Username is required.');
  }
  res.cookie('username', username.trim(), {
    expires: cookieExpiryAtUTCMidnight(),
    httpOnly: true,
    sameSite: 'Lax',
  });
  return res.redirect('/');
});

app.get('/api/verify', (req, res) => {
  const username = req.cookies.username;
  if (username) return res.json({ valid: true, username });
  else return res.json({ valid: false });
});

app.get('/broadcast', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/', (req, res) => {
  if (!req.cookies.username) return res.redirect('/login');
  return res.sendFile(path.join(__dirname, 'public', 'client.html'));
});

// ----------------- Socket.IO -----------------
let adminSocket = null;
let clients = new Map();
let currentQrValue = null;
let isStreaming = false;
let isHidden = false;

function getClientList() {
  return Array.from(clients.entries()).map(([id, { ping, username, ip, isp, country, vpn }]) => ({
    id,
    ping,
    username,
    ip,
    isp,
    country,
    vpn,
  }));
}

io.on('connection', (socket) => {
  socket.on('join', (role) => {
    // ---------- ADMIN ----------
    if (role === 'admin') {
      if (adminSocket) {
        socket.emit('error', 'Admin already connected');
        socket.disconnect();
        return;
      }
      adminSocket = socket;
      socket.emit('state', { isStreaming, isHidden, currentQrValue });
      io.to('clients').emit('admin_present', true);
      socket.emit('client_list', getClientList());
      console.log('Admin connected:', socket.id);
      return;
    }

    // ---------- CLIENT ----------
    if (role === 'client') {
      const cookieHeader = socket.handshake.headers.cookie || '';
      const parsed = parseCookies(cookieHeader);
      const username = parsed.username;
      if (!username) {
        socket.emit('forbidden', 'Login required. Please refresh.');
        setTimeout(() => socket.disconnect(true), 50);
        return;
      }

      // Get IP address
      const ip = socket.handshake.headers['x-forwarded-for']?.split(',')[0] || socket.handshake.address;

      // Query IP details
      axios
        .get(`http://ip-api.com/json/${ip}?fields=status,message,country,isp,org,as,proxy,hosting,query`)
        .then((res) => {
          const info =
            res.data.status === 'success'
              ? res.data
              : { isp: 'Unknown', country: 'Unknown', hosting: false, proxy: false, query: ip };
          clients.set(socket.id, {
            ping: 0,
            username,
            ip: info.query,
            isp: info.isp,
            country: info.country,
            vpn: info.hosting || info.proxy,
          });
          socket.join('clients');
          socket.emit('connected', true);
          if (isStreaming && !isHidden && currentQrValue) socket.emit('qr_update', currentQrValue);
          if (adminSocket) adminSocket.emit('client_list', getClientList());
          console.log(
            `Client connected: ${username} (${socket.id}) IP=${info.query} ISP=${info.isp} Country=${info.country} VPN=${info.hosting || info.proxy}`
          );
        })
        .catch((err) => {
          clients.set(socket.id, {
            ping: 0,
            username,
            ip,
            isp: 'Unknown',
            country: 'Unknown',
            vpn: false,
          });
          socket.join('clients');
          socket.emit('connected', true);
          if (isStreaming && !isHidden && currentQrValue) socket.emit('qr_update', currentQrValue);
          if (adminSocket) adminSocket.emit('client_list', getClientList());
          console.log(`Client connected: ${username} (${socket.id}) IP lookup failed (${err.message})`);
        });

      return;
    }

    socket.emit('error', 'Unknown role');
    socket.disconnect(true);
  });

  // ------------------ Admin-only socket events ------------------
  socket.on('start_stream', () => {
    if (socket !== adminSocket) return;
    isStreaming = true;
    io.to('clients').emit('connected', true);
    if (adminSocket) adminSocket.emit('state', { isStreaming, isHidden, currentQrValue });
    console.log('Streaming started by admin');
  });

  socket.on('stop_stream', () => {
    if (socket !== adminSocket) return;
    isStreaming = false;
    currentQrValue = null;
    io.to('clients').emit('connected', false);
    if (adminSocket) adminSocket.emit('state', { isStreaming, isHidden, currentQrValue });
    console.log('Streaming stopped by admin');
  });

  socket.on('toggle_hide', (hide) => {
    if (socket !== adminSocket) return;
    isHidden = !!hide;
    if (isHidden) io.to('clients').emit('qr_update', null);
    else if (currentQrValue) io.to('clients').emit('qr_update', currentQrValue);
    if (adminSocket) adminSocket.emit('hide_state', isHidden);
    console.log('Hide toggled:', isHidden);
  });

  socket.on('qr_update', (value) => {
    if (socket !== adminSocket || !isStreaming) return;
    if (value !== currentQrValue) {
      currentQrValue = value;
      if (!isHidden) io.to('clients').emit('qr_update', value);
      if (adminSocket) adminSocket.emit('qr_preview', value);
      console.log('QR updated and broadcasted');
    }
  });

  socket.on('request_client_list', () => {
    if (socket !== adminSocket) return;
    socket.emit('client_list', getClientList());
  });

  socket.on('pong', (startTime) => {
    const ping = Date.now() - startTime;
    if (clients.has(socket.id)) {
      const c = clients.get(socket.id);
      clients.set(socket.id, { ...c, ping });
      if (adminSocket) adminSocket.emit('client_list', getClientList());
    } else if (socket === adminSocket) socket.emit('your_ping', ping);
  });

  socket.on('disconnect', (reason) => {
    if (socket === adminSocket) {
      adminSocket = null;
      isStreaming = false;
      currentQrValue = null;
      io.to('clients').emit('connected', false);
      io.to('clients').emit('admin_present', false);
      console.log('Admin disconnected.');
    } else {
      const c = clients.get(socket.id);
      const username = c ? c.username : 'Unknown';
      const ip = c ? c.ip : 'Unknown';
      clients.delete(socket.id);
      if (adminSocket) adminSocket.emit('client_list', getClientList());
      console.log(`Client disconnected: ${username} (${socket.id}) IP=${ip}, reason=${reason}`);
    }
  });
});

setInterval(() => {
  io.emit('ping', Date.now());
}, 5000);

const PORT = process.env.PORT || 5000;
server.listen(PORT, '0.0.0.0', () => console.log(`Server running on port ${PORT}`));
