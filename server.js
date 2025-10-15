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
let clients = new Map(); // socket.id -> { ping, username }

let currentQrValue = null;
let isStreaming = false;
let isHidden = false;

function getClientList() {
  return Array.from(clients.entries()).map(([id, { ping, username }]) => ({ id, ping, username }));
}

io.on('connection', (socket) => {
  socket.on('join', (role) => {
    if (role === 'admin') {
      if (adminSocket) {
        socket.emit('error', 'Admin already connected');
        socket.disconnect();
        return;
      }
      adminSocket = socket;
      socket.emit('state', { isStreaming, isHidden, currentQrValue });
      // inform existing clients that an admin is present
      io.to('clients').emit('admin_present', true);
      // send current client list to admin
      socket.emit('client_list', getClientList());
      console.log('Admin connected:', socket.id);
      return;
    }

    if (role === 'client') {
      const cookieHeader = socket.handshake.headers.cookie || '';
      const parsed = parseCookies(cookieHeader);
      const username = parsed.username;

      // The only validation now is the presence of a username cookie
      if (!username) {
        socket.emit('forbidden', 'Login required. Please refresh the page.');
        setTimeout(() => socket.disconnect(true), 50);
        return;
      }

      socket.join('clients');
      clients.set(socket.id, { ping: 0, username });
      socket.emit('connected', true);
      if (isStreaming && !isHidden && currentQrValue) {
        socket.emit('qr_update', currentQrValue);
      }
      if (adminSocket) adminSocket.emit('client_list', getClientList());
      console.log(`Authorized client connected: ${username} (${socket.id})`);
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
    if (isHidden) {
      io.to('clients').emit('qr_update', null);
    } else if (currentQrValue) {
      io.to('clients').emit('qr_update', currentQrValue);
    }
    if (adminSocket) adminSocket.emit('hide_state', isHidden);
    console.log('Hide toggled:', isHidden);
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
      console.log('QR updated and broadcast (if not hidden).');
    }
  });

  socket.on('request_client_list', () => {
    if (socket !== adminSocket) return;
    socket.emit('client_list', getClientList());
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
      console.log('Admin disconnected.');
    } else {
      const clientData = clients.get(socket.id);
      const username = clientData ? clientData.username : 'Unknown';
      clients.delete(socket.id);
      if (adminSocket) adminSocket.emit('client_list', getClientList());
      console.log(`Client disconnected: ${username} (${socket.id}), reason: ${reason}`);
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