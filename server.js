// server.js
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');

const app = express();
// optional cookie parser for future use (install with `npm install cookie-parser`)
let cookieParser;
try {
  cookieParser = require('cookie-parser');
  app.use(cookieParser());
} catch (e) {
  // cookie-parser not installed; log a hint. Installing is optional but recommended for cookie handling.
  console.log('cookie-parser not installed. To enable cookie parsing run: npm install cookie-parser');
}
app.use(express.urlencoded({ extended: true })); // Middleware for form data
const server = http.createServer(app);
const io = new Server(server, {
  pingInterval: 10000,
  pingTimeout: 5000,
});

const https = require('https');

// ----------------- Helpers -----------------
// We can keep this to expire the username cookie at a set time
function cookieExpiryAtUTCMidnight() {
  const expiry = new Date();
  expiry.setUTCHours(23, 59, 59, 999);
  return expiry;
}

// ----------------- Static -----------------
app.use(express.static(path.join(__dirname, 'public')));

// ----------------- API Endpoints & Routes -----------------

// 1) Login page route (anyone can access)
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// 2) Handle login form submission
app.post('/api/login', (req, res) => {
  const { username } = req.body;
  if (!username || username.trim().length === 0) {
    return res.status(400).send('Username is required.');
  }
  // Set the username cookie, valid until midnight UTC
  res.cookie('username', username.trim(), {
    expires: cookieExpiryAtUTCMidnight(),
    httpOnly: true,
    sameSite: 'Lax',
  });
  return res.redirect('/');
});

// 3) Client-side verification endpoint: checks for username cookie
app.get('/api/verify', (req, res) => {
  const username = req.cookies.username;
  if (username) {
    return res.json({ valid: true, username });
  } else {
    return res.json({ valid: false });
  }
});

// Admin route
app.get('/broadcast', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Root route: redirect to login if username cookie is missing
app.get('/', (req, res) => {
  if (!req.cookies.username) {
    return res.redirect('/login');
  }
  return res.sendFile(path.join(__dirname, 'public', 'client.html'));
});

// ----------------- Socket.IO logic -----------------

let adminSocket = null;
// socket.id -> { ping, username, role, ip, country, region, isp, vpn }
let clients = new Map();

// In-memory server action logs (most recent first)
let serverLogs = [];

function advancedLog(item) {
  const ts = item.ts || new Date().toISOString();
  const role = item.role || (item.socketId && clients.get(item.socketId) && clients.get(item.socketId).role) || '';
  const username = item.username || (item.socketId && clients.get(item.socketId) && clients.get(item.socketId).username) || '';
  const ip = item.ip || (item.socketId && clients.get(item.socketId) && clients.get(item.socketId).ip) || '';
  const country = item.country || (item.socketId && clients.get(item.socketId) && clients.get(item.socketId).country) || '';
  const region = item.region || (item.socketId && clients.get(item.socketId) && clients.get(item.socketId).region) || '';
  const isp = item.isp || (item.socketId && clients.get(item.socketId) && clients.get(item.socketId).isp) || '';
  const vpn = typeof item.vpn !== 'undefined' ? item.vpn : (item.socketId && clients.get(item.socketId) && clients.get(item.socketId).vpn);
  const msg = item.msg || '';
  const details = Object.entries(item.info || {}).map(([k,v]) => `${k}=${v}`).join(' ');
  const line = `[${ts}] [${role}] [${username}] [${ip}] [${country}] [${region}] [${isp}] [VPN:${vpn ? 'ON' : 'OFF'}] [Socket:${item.socketId||''}] ${msg} ${details}`;
  console.log(line);
}

function pushLog(entry) {
  const item = { ts: new Date().toISOString(), ...entry };
  serverLogs.unshift(item);
  if (serverLogs.length > 1000) serverLogs.length = 1000;
  if (adminSocket) adminSocket.emit('server_logs', serverLogs.slice(0, 200));
  advancedLog(item);
}

let currentQrValue = null;
let isStreaming = false;
let isHidden = false;

function getClientList() {
  return Array.from(clients.entries()).map(([id, data]) => ({ id, ...data }));
}

function getRemoteIpFromSocket(socket) {
  // prefer x-forwarded-for then handshake address
  const h = socket.handshake || {};
  const headers = (h.headers) || {};
  const xff = headers['x-forwarded-for'];
  if (xff) return xff.split(',')[0].trim();
  // socket.handshake.address often contains ::ffff:ip
  const addr = socket.handshake.address || (socket.request && socket.request.connection && socket.request.connection.remoteAddress) || '';
  if (!addr) return '';
  return addr.replace('::ffff:', '');
}

function fetchIpInfo(ip, cb) {
  if (!ip) return cb(null, {});
  // use ip-api.com which provides country, regionName, isp, proxy (as basic VPN/proxy detection)
  const url = `https://ip-api.com/json/${ip}?fields=status,country,regionName,isp,proxy,query,message`;
  https.get(url, (res) => {
    let raw = '';
    res.on('data', (d) => raw += d);
    res.on('end', () => {
      try {
        const obj = JSON.parse(raw);
        if (obj && obj.status === 'success') {
          return cb(null, {
            ip: obj.query,
            country: obj.country || '',
            region: obj.regionName || '',
            isp: obj.isp || '',
            vpn: !!obj.proxy,
          });
        }
        return cb(null, { ip, country: '', region: '', isp: '', vpn: false });
      } catch (e) {
        return cb(e);
      }
    });
  }).on('error', (err) => cb(err));
}

io.on('connection', (socket) => {
  socket.on('join', (role) => {
    if (role === 'admin') {
      if (adminSocket) {
        // log attempt
        pushLog({ level: 'warn', msg: 'Admin connection attempt while admin already present', socketId: socket.id });
        socket.emit('error', 'Admin already connected');
        socket.disconnect();
        return;
      }
      adminSocket = socket;
      socket.emit('state', { isStreaming, isHidden, currentQrValue });
      // send recent server logs and client list
      socket.emit('server_logs', serverLogs.slice(0, 200));
      socket.emit('client_list', getClientList());
      // inform existing clients that an admin is present
      io.to('clients').emit('admin_present', true);
  const adminIp = getRemoteIpFromSocket(socket);
  pushLog({ level: 'info', msg: 'Admin connected', socketId: socket.id, role: 'admin', ip: adminIp });
  // Show admin link and IP in terminal
  const port = PORT || 5000;
  const adminUrl = `http://localhost:${port}/broadcast`;
  console.log(`[ADMIN LINK] ${adminUrl}`);
  console.log(`[ADMIN IP] ${adminIp}`);
      return;
    }

    if (role === 'visitor') {
      // someone opened the login page and wants to be visible to admin as not-logged-in yet
      const ip = getRemoteIpFromSocket(socket);
      const username = 'has not logged in yet';
      // register visitor immediately with placeholder values; we'll fetch details async
      const base = { ping: 0, username, role: 'visitor', ip: ip || '', country: '', region: '', isp: '', vpn: false };
      socket.join('clients');
      clients.set(socket.id, base);
      socket.emit('visitor_registered', true);
  pushLog({ level: 'info', msg: 'Visitor registered (login page)', socketId: socket.id, role: 'visitor', username, ip });
      // async fetch ip info and update
      fetchIpInfo(ip, (err, info) => {
        if (!err && info) {
          const prev = clients.get(socket.id) || {};
          clients.set(socket.id, { ...prev, ...info });
          if (adminSocket) adminSocket.emit('client_list', getClientList());
        }
      });
      if (adminSocket) adminSocket.emit('client_list', getClientList());
      return;
    }

    if (role === 'client') {
      const cookieHeader = (socket.handshake && socket.handshake.headers && socket.handshake.headers.cookie) || '';
      const parsed = parseCookies(cookieHeader);
      const username = parsed.username;

      // The only validation now is the presence of a username cookie
      if (!username) {
        socket.emit('forbidden', 'Login required. Please refresh the page.');
        setTimeout(() => socket.disconnect(true), 50);
        return;
      }

      const ip = getRemoteIpFromSocket(socket);
      // register client with basic data then enrich with ip info async
      const base = { ping: 0, username, role: 'client', ip: ip || '', country: '', region: '', isp: '', vpn: false };
      socket.join('clients');
      clients.set(socket.id, base);
      socket.emit('connected', true);
  pushLog({ level: 'info', msg: 'Client connected', socketId: socket.id, role: 'client', username, ip });
      // immediate QR if available
      if (isStreaming && !isHidden && currentQrValue) {
        socket.emit('qr_update', currentQrValue);
      }
      // async enrich
      fetchIpInfo(ip, (err, info) => {
        if (!err && info) {
          const prev = clients.get(socket.id) || {};
          clients.set(socket.id, { ...prev, ...info });
          if (adminSocket) adminSocket.emit('client_list', getClientList());
          pushLog({ level: 'info', msg: 'Client metadata enriched', socketId: socket.id, role: 'client', username, ...info });
        }
      });
      if (adminSocket) adminSocket.emit('client_list', getClientList());
  // ...existing code...
      return;
    }

    socket.emit('error', 'Unknown role');
    socket.disconnect(true);
  });

  // ... (rest of the socket event handlers are unchanged from your previous version)

  socket.on('start_stream', () => {
    if (socket !== adminSocket) return;
    isStreaming = true;
    io.to('clients').emit('connected', true);
    if (adminSocket) adminSocket.emit('state', { isStreaming, isHidden, currentQrValue });
  pushLog({ level: 'info', msg: 'Streaming started by admin', socketId: socket.id, role: 'admin' });
  });

  socket.on('stop_stream', () => {
    if (socket !== adminSocket) return;
    isStreaming = false;
    currentQrValue = null;
    io.to('clients').emit('connected', false);
    if (adminSocket) adminSocket.emit('state', { isStreaming, isHidden, currentQrValue });
  pushLog({ level: 'info', msg: 'Streaming stopped by admin', socketId: socket.id, role: 'admin' });
  });

  socket.on('toggle_hide', (hide) => {
    if (socket !== adminSocket) return;
    isHidden = !!hide;
    if (isHidden) {
      io.to('clients').emit('qr_update', null);
    } else if (currentQrValue) {
      io.to('clients').emit('qr_update', currentQrValue);
    }
    if (adminSocket) adminSocket.emit('hide_state', isHidden);
  pushLog({ level: 'info', msg: 'Hide toggled', socketId: socket.id, role: 'admin', isHidden });
  });

  socket.on('qr_update', (value) => {
    if (socket !== adminSocket) return;
    if (!isStreaming) return;
    if (value !== currentQrValue) {
      currentQrValue = value;
      if (!isHidden) {
        io.to('clients').emit('qr_update', value);
      }
      if (adminSocket) adminSocket.emit('qr_preview', value);
  pushLog({ level: 'info', msg: 'QR updated by admin', socketId: socket.id, role: 'admin', value: value });
    }
  });

  socket.on('request_client_list', () => {
    if (socket !== adminSocket) return;
  socket.emit('client_list', getClientList());
  pushLog({ level: 'info', msg: 'Admin requested client list', socketId: socket.id, role: 'admin' });
  });

  socket.on('pong', (startTime) => {
    const ping = Date.now() - startTime;
    if (clients.has(socket.id)) {
      const clientData = clients.get(socket.id);
      clients.set(socket.id, { ...clientData, ping });
      if (adminSocket) adminSocket.emit('client_list', getClientList());
    } else if (socket === adminSocket) {
      socket.emit('your_ping', ping);
    }
  });

  socket.on('disconnect', (reason) => {
    if (socket === adminSocket) {
      adminSocket = null;
      isStreaming = false;
      currentQrValue = null;
      io.to('clients').emit('connected', false);
      // notify clients that admin is no longer present
      io.to('clients').emit('admin_present', false);
  pushLog({ level: 'info', msg: 'Admin disconnected', socketId: socket.id, role: 'admin', reason });
    } else {
      const clientData = clients.get(socket.id);
      const username = clientData ? clientData.username : 'Unknown';
      clients.delete(socket.id);
      if (adminSocket) adminSocket.emit('client_list', getClientList());
      pushLog({
        level: 'info',
        msg: 'Client disconnected',
        socketId: socket.id,
        role: clientData ? clientData.role : '',
        username,
        ip: clientData ? clientData.ip : '',
        country: clientData ? clientData.country : '',
        region: clientData ? clientData.region : '',
        isp: clientData ? clientData.isp : '',
        vpn: clientData ? clientData.vpn : false,
        reason
      });
    }
  });
});

function parseCookies(cookieHeader) {
  const list = {};
  if (!cookieHeader) return list;
  cookieHeader.split(';').forEach(function(cookie) {
    const parts = cookie.split('=');
    const name = parts.shift().trim();
    const value = decodeURIComponent(parts.join('='));
    if (name) list[name] = value;
  });
  return list;
}

setInterval(() => {
  io.emit('ping', Date.now());
}, 5000);

const PORT = process.env.PORT || 5000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});
