
-const express = require('express');
-const http = require('http');
-const { Server } = require('socket.io');
-const path = require('path');
-const axios = require('axios');
-
-const app = express();
-let cookieParser;
-try {
-  cookieParser = require('cookie-parser');
-  app.use(cookieParser());
-} catch {
-  console.log('cookie-parser not installed. Run: npm install cookie-parser');
-}
-
-app.use(express.urlencoded({ extended: true }));
-const server = http.createServer(app);
-const io = new Server(server, { pingInterval: 10000, pingTimeout: 5000 });
-
-// -------- Helpers --------
-function cookieExpiryAtUTCMidnight() {
-  const d = new Date();
-  d.setUTCHours(23, 59, 59, 999);
-  return d;
-}
-function parseCookies(header) {
-  const list = {};
-  if (!header) return list;
-  header.split(';').forEach(c => {
-    const p = c.split('=');
-    const name = p.shift().trim();
-    const value = decodeURIComponent(p.join('='));
-    if (name) list[name] = value;
-  });
-  return list;
-}
-function flagEmoji(code) {
-  if (!code || code.length !== 2) return '';
-  return String.fromCodePoint(...[...code.toUpperCase()].map(c => 0x1F1E6 - 65 + c.charCodeAt(0)));
-}
-function normalizeISP(raw) {
-  if (!raw) return 'Unknown';
-  const low = raw.toLowerCase();
-  const map = [
-    { k: ['ethionet', 'ethiotelecom', 'ethio telecom'], n: 'Ethio Telecom' },
-    { k: ['safaricom', 'vodafone'], n: 'Safaricom Ethiopia PLC' },
-    { k: ['mtn'], n: 'MTN Group' },
-    { k: ['airtel'], n: 'Airtel Africa' },
-    { k: ['aws', 'amazon'], n: 'Amazon Web Services' },
-    { k: ['azure', 'microsoft'], n: 'Microsoft Azure' },
-    { k: ['oracle'], n: 'Oracle Cloud' },
-    { k: ['ovh'], n: 'OVHcloud' },
-    { k: ['hetzner'], n: 'Hetzner Online' },
-    { k: ['cloudflare'], n: 'Cloudflare' },
-    { k: ['starlink'], n: 'Starlink Internet' },
-    { k: ['hostinger'], n: 'Hostinger' },
-    { k: ['contabo'], n: 'Contabo GmbH' },
-    { k: ['linode'], n: 'Linode (Akamai)' }
-  ];
-  for (const e of map) if (e.k.some(k => low.includes(k))) return e.n;
-  return raw;
-}
-
-// -------- Routes --------
-app.use(express.static(path.join(__dirname, 'public')));
-app.get('/login', (_, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
-app.post('/api/login', (req, res) => {
-  const { username } = req.body;
-  if (!username || username.trim() === '') return res.status(400).send('Username required');
-  res.cookie('username', username.trim(), {
-    expires: cookieExpiryAtUTCMidnight(),
-    httpOnly: true,
-    sameSite: 'Lax'
-  });
-  res.redirect('/');
-});
-app.get('/api/verify', (req, res) => {
-  const u = req.cookies.username;
-  if (u) return res.json({ valid: true, username: u });
-  res.json({ valid: false });
-});
-app.get('/broadcast', (_, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
-app.get('/', (req, res) => {
-  if (!req.cookies.username) return res.redirect('/login');
-  res.sendFile(path.join(__dirname, 'public', 'client.html'));
-});
-
-// -------- Socket.IO --------
-let adminSocket = null;
-let clients = new Map();
-let isStreaming = false;
-let currentQrValue = null;
-let isHidden = false;
-
-function getClientList() {
-  return Array.from(clients.entries()).map(([id, c]) => ({
-    id,
-    username: c.username,
-    ip: c.ip,
-    city: c.city,
-    region: c.region,
-    country: c.country,
-    countryFlag: c.countryFlag,
-    isp: c.isp,
-    vpn: c.vpn,
-    ping: c.ping
-  }));
-}
-
-io.on('connection', (socket) => {
-  // Guest joins before login
-  socket.on('join_guest', async guestId => {
-    const ip = socket.handshake.headers['x-forwarded-for']?.split(',')[0] || socket.handshake.address;
-    let isp='Pending', city='Unknown', region='Unknown', country='Unknown', flag='', vpn=false;
-    try {
-      const r = await axios.get(`http://ip-api.com/json/${ip}?fields=status,country,countryCode,regionName,city,isp,proxy,hosting`);
-      if (r.data.status === 'success') {
-        isp = normalizeISP(r.data.isp);
-        city = r.data.city || 'Unknown';
-        region = r.data.regionName || 'Unknown';
-        country = r.data.country || 'Unknown';
-        flag = flagEmoji(r.data.countryCode);
-        vpn = r.data.proxy || r.data.hosting;
-      }
-    } catch {}
-    clients.set(socket.id, { ping: 0, username: `${guestId} (Not logged in yet)`, ip, city, region, country, countryFlag: flag, isp, vpn });
-    socket.join('clients');
-    if (adminSocket) adminSocket.emit('client_list', getClientList());
-    console.log(`Guest joined: ${guestId} (${ip})`);
-  });
-
-  socket.on('join', async role => {
-    if (role === 'admin') {
-      if (adminSocket) { socket.emit('error', 'Admin already connected'); socket.disconnect(); return; }
-      adminSocket = socket;
-      socket.emit('client_list', getClientList());
-      console.log('Admin connected');
-      return;
-    }
-
-    if (role !== 'client') return;
-
-    const parsed = parseCookies(socket.handshake.headers.cookie || '');
-    const username = parsed.username;
-    if (!username) { socket.emit('forbidden', 'Login required'); socket.disconnect(true); return; }
-
-    const ip = socket.handshake.headers['x-forwarded-for']?.split(',')[0] || socket.handshake.address;
-    let isp='Unknown', city='Unknown', region='Unknown', country='Unknown', flag='', vpn=false;
-    try {
-      const r = await axios.get(`http://ip-api.com/json/${ip}?fields=status,country,countryCode,regionName,city,isp,proxy,hosting`);
-      if (r.data.status === 'success') {
-        isp = normalizeISP(r.data.isp);
-        city = r.data.city || 'Unknown';
-        region = r.data.regionName || 'Unknown';
-        country = r.data.country || 'Unknown';
-        flag = flagEmoji(r.data.countryCode);
-        vpn = r.data.proxy || r.data.hosting;
-      }
-    } catch {}
-
-    clients.set(socket.id, { ping: 0, username, ip, city, region, country, countryFlag: flag, isp, vpn });
-    socket.join('clients');
-    socket.emit('connected', true);
-    if (adminSocket) adminSocket.emit('client_list', getClientList());
-    console.log(`Client connected: ${username} (${ip})`);
-  });
-
-  // QR stream handling
-  socket.on('start_stream', () => {
-    if (socket !== adminSocket) return;
-    isStreaming = true;
-    console.log('Streaming started by admin');
-  });
-
-  socket.on('stop_stream', () => {
-    if (socket !== adminSocket) return;
-    isStreaming = false;
-    currentQrValue = null;
-    io.to('clients').emit('qr_update', null);
-    console.log('Streaming stopped');
-  });
-
-  socket.on('qr_update', (value) => {
-    if (socket !== adminSocket) return;
-    if (!isStreaming) {
-      isStreaming = true;
-      console.log('Auto-enabled streaming on first QR update');
-    }
-    if (value && value !== currentQrValue) {
-      currentQrValue = value;
-      if (!isHidden) io.to('clients').emit('qr_update', value);
-      adminSocket.emit('qr_preview', value);
-      console.log('QR updated and broadcast');
-    }
-  });
-
-  socket.on('toggle_hide', (hide) => {
-    if (socket !== adminSocket) return;
-    isHidden = !!hide;
-    io.to('clients').emit('qr_update', isHidden ? null : currentQrValue);
-    console.log('Hide toggled:', isHidden);
-  });
-
-  socket.on('pong', (t) => {
-    const ping = Date.now() - t;
-    if (clients.has(socket.id)) {
-      const c = clients.get(socket.id);
-      clients.set(socket.id, { ...c, ping });
-      if (adminSocket) adminSocket.emit('client_list', getClientList());
-    }
-  });
-
-  socket.on('disconnect', () => {
-    if (socket === adminSocket) {
-      adminSocket = null;
-      isStreaming = false;
-      currentQrValue = null;
-      console.log('Admin disconnected');
-    } else {
-      clients.delete(socket.id);
-      if (adminSocket) adminSocket.emit('client_list', getClientList());
-    }
-  });
-});
-
-setInterval(() => io.emit('ping', Date.now()), 5000);
-server.listen(process.env.PORT || 5000, '0.0.0.0', () => console.log('Server running...'));
+const express = require('express');
+const http = require('http');
+const { Server } = require('socket.io');
+const path = require('path');
+const axios = require('axios');
+
+const app = express();
+
+let cookieParser;
+try {
+  cookieParser = require('cookie-parser');
+  app.use(cookieParser());
+} catch (err) {
+  console.log('cookie-parser not installed. Run: npm install cookie-parser');
+}
+
+app.use(express.urlencoded({ extended: true }));
+
+const server = http.createServer(app);
+const io = new Server(server, {
+  pingInterval: 10000,
+  pingTimeout: 5000,
+});
+
+// ----------------- Helpers -----------------
+function cookieExpiryAtUTCMidnight() {
+  const expiry = new Date();
+  expiry.setUTCHours(23, 59, 59, 999);
+  return expiry;
+}
+
+function parseCookies(cookieHeader) {
+  const list = {};
+  if (!cookieHeader) return list;
+  cookieHeader.split(';').forEach((cookie) => {
+    const parts = cookie.split('=');
+    const name = parts.shift().trim();
+    const value = decodeURIComponent(parts.join('='));
+    if (name) list[name] = value;
+  });
+  return list;
+}
+
+function flagEmoji(code) {
+  if (!code || code.length !== 2) return '';
+  return String.fromCodePoint(
+    ...[...code.toUpperCase()].map((c) => 0x1f1e6 - 65 + c.charCodeAt(0))
+  );
+}
+
+function normalizeISP(raw) {
+  if (!raw) return 'Unknown';
+  const low = raw.toLowerCase();
+  const map = [
+    { k: ['ethionet', 'ethiotelecom', 'ethio telecom'], n: 'Ethio Telecom' },
+    { k: ['safaricom', 'vodafone'], n: 'Safaricom Ethiopia PLC' },
+    { k: ['mtn'], n: 'MTN Group' },
+    { k: ['airtel'], n: 'Airtel Africa' },
+    { k: ['aws', 'amazon'], n: 'Amazon Web Services' },
+    { k: ['azure', 'microsoft'], n: 'Microsoft Azure' },
+    { k: ['oracle'], n: 'Oracle Cloud' },
+    { k: ['ovh'], n: 'OVHcloud' },
+    { k: ['hetzner'], n: 'Hetzner Online' },
+    { k: ['cloudflare'], n: 'Cloudflare' },
+    { k: ['starlink'], n: 'Starlink Internet' },
+    { k: ['hostinger'], n: 'Hostinger' },
+    { k: ['contabo'], n: 'Contabo GmbH' },
+    { k: ['linode'], n: 'Linode (Akamai)' },
+  ];
+  for (const entry of map) {
+    if (entry.k.some((k) => low.includes(k))) return entry.n;
+  }
+  return raw;
+}
+
+async function lookupIpDetails(ip) {
+  try {
+    const { data } = await axios.get(
+      `http://ip-api.com/json/${ip}?fields=status,message,query,country,countryCode,regionName,city,isp,proxy,hosting`
+    );
+    if (data.status === 'success') {
+      return {
+        ip: data.query || ip,
+        city: data.city || 'Unknown',
+        region: data.regionName || 'Unknown',
+        country: data.country || 'Unknown',
+        countryCode: data.countryCode || '',
+        isp: normalizeISP(data.isp),
+        vpn: data.proxy || data.hosting || false,
+      };
+    }
+  } catch (err) {
+    console.log(`IP lookup failed for ${ip}: ${err.message}`);
+  }
+  return {
+    ip,
+    city: 'Unknown',
+    region: 'Unknown',
+    country: 'Unknown',
+    countryCode: '',
+    isp: 'Unknown',
+    vpn: false,
+  };
+}
+
+// ----------------- Static -----------------
+app.use(express.static(path.join(__dirname, 'public')));
+
+// ----------------- Routes -----------------
+app.get('/login', (req, res) => {
+  res.sendFile(path.join(__dirname, 'public', 'login.html'));
+});
+
+app.post('/api/login', (req, res) => {
+  const { username } = req.body;
+  if (!username || username.trim().length === 0) {
+    return res.status(400).send('Username is required.');
+  }
+  res.cookie('username', username.trim(), {
+    expires: cookieExpiryAtUTCMidnight(),
+    httpOnly: true,
+    sameSite: 'Lax',
+  });
+  return res.redirect('/');
+});
+
+app.get('/api/verify', (req, res) => {
+  const username = req.cookies.username;
+  if (username) return res.json({ valid: true, username });
+  return res.json({ valid: false });
+});
+
+app.get('/broadcast', (req, res) => {
+  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
+});
+
+app.get('/', (req, res) => {
+  if (!req.cookies.username) return res.redirect('/login');
+  return res.sendFile(path.join(__dirname, 'public', 'client.html'));
+});
+
+// ----------------- Socket.IO -----------------
+let adminSocket = null;
+let clients = new Map();
+let currentQrValue = null;
+let isStreaming = false;
+let isHidden = false;
+
+function getClientList() {
+  return Array.from(clients.entries()).map(([id, client]) => ({
+    id,
+    username: client.username,
+    ip: client.ip,
+    city: client.city,
+    region: client.region,
+    country: client.country,
+    countryFlag: client.countryFlag,
+    isp: client.isp,
+    vpn: client.vpn,
+    ping: client.ping,
+  }));
+}
+
+function updateAdminClientList() {
+  if (adminSocket) adminSocket.emit('client_list', getClientList());
+}
+
+io.on('connection', (socket) => {
+  socket.on('join_guest', async (guestId) => {
+    const ip = socket.handshake.headers['x-forwarded-for']?.split(',')[0] || socket.handshake.address;
+    const details = await lookupIpDetails(ip);
+    clients.set(socket.id, {
+      ping: 0,
+      username: `${guestId} (Not logged in yet)`,
+      ip: details.ip,
+      city: details.city,
+      region: details.region,
+      country: details.country,
+      countryFlag: flagEmoji(details.countryCode),
+      isp: details.isp,
+      vpn: details.vpn,
+    });
+    socket.join('clients');
+    updateAdminClientList();
+    console.log(`Guest joined: ${guestId} (${details.ip})`);
+  });
+
+  socket.on('join', async (role) => {
+    // ---------- ADMIN ----------
+    if (role === 'admin') {
+      if (adminSocket) {
+        socket.emit('error', 'Admin already connected');
+        socket.disconnect();
+        return;
+      }
+      adminSocket = socket;
+      socket.emit('state', { isStreaming, isHidden, currentQrValue });
+      socket.emit('hide_state', isHidden);
+      socket.emit('client_list', getClientList());
+      io.to('clients').emit('admin_present', true);
+      console.log('Admin connected:', socket.id);
+      return;
+    }
+
+    // ---------- CLIENT ----------
+    if (role === 'client') {
+      const cookieHeader = socket.handshake.headers.cookie || '';
+      const parsed = parseCookies(cookieHeader);
+      const username = parsed.username;
+      if (!username) {
+        socket.emit('forbidden', 'Login required. Please refresh.');
+        setTimeout(() => socket.disconnect(true), 50);
+        return;
+      }
+
+      const ip = socket.handshake.headers['x-forwarded-for']?.split(',')[0] || socket.handshake.address;
+      const details = await lookupIpDetails(ip);
+
+      clients.set(socket.id, {
+        ping: 0,
+        username,
+        ip: details.ip,
+        city: details.city,
+        region: details.region,
+        country: details.country,
+        countryFlag: flagEmoji(details.countryCode),
+        isp: details.isp,
+        vpn: details.vpn,
+      });
+
+      socket.join('clients');
+      socket.emit('connected', true);
+      if (isStreaming && !isHidden && currentQrValue) socket.emit('qr_update', currentQrValue);
+      updateAdminClientList();
+      console.log(
+        `Client connected: ${username} (${socket.id}) IP=${details.ip} ISP=${details.isp} Country=${details.country} VPN=${details.vpn}`
+      );
+      return;
+    }
+
+    socket.emit('error', 'Unknown role');
+    socket.disconnect(true);
+  });
+
+  // ------------------ Admin-only socket events ------------------
+  socket.on('start_stream', () => {
+    if (socket !== adminSocket) return;
+    isStreaming = true;
+    io.to('clients').emit('connected', true);
+    if (adminSocket) adminSocket.emit('state', { isStreaming, isHidden, currentQrValue });
+    console.log('Streaming started by admin');
+  });
+
+  socket.on('stop_stream', () => {
+    if (socket !== adminSocket) return;
+    isStreaming = false;
+    currentQrValue = null;
+    io.to('clients').emit('connected', false);
+    io.to('clients').emit('qr_update', null);
+    if (adminSocket) adminSocket.emit('qr_preview', null);
+    if (adminSocket) adminSocket.emit('state', { isStreaming, isHidden, currentQrValue });
+    console.log('Streaming stopped by admin');
+  });
+
+  socket.on('toggle_hide', (hide) => {
+    if (socket !== adminSocket) return;
+    isHidden = !!hide;
+    if (isHidden) io.to('clients').emit('qr_update', null);
+    else if (currentQrValue) io.to('clients').emit('qr_update', currentQrValue);
+    if (adminSocket) adminSocket.emit('hide_state', isHidden);
+    console.log('Hide toggled:', isHidden);
+  });
+
+  socket.on('qr_update', (value) => {
+    if (socket !== adminSocket || !isStreaming) return;
+    if (value && value !== currentQrValue) {
+      currentQrValue = value;
+      if (!isHidden) io.to('clients').emit('qr_update', value);
+      if (adminSocket) adminSocket.emit('qr_preview', value);
+      console.log('QR updated and broadcasted');
+    }
+  });
+
+  socket.on('request_client_list', () => {
+    if (socket !== adminSocket) return;
+    socket.emit('client_list', getClientList());
+  });
+
+  socket.on('pong', (startTime) => {
+    const ping = Date.now() - startTime;
+    if (clients.has(socket.id)) {
+      const c = clients.get(socket.id);
+      clients.set(socket.id, { ...c, ping });
+      updateAdminClientList();
+    } else if (socket === adminSocket) socket.emit('your_ping', ping);
+  });
+
+  socket.on('disconnect', (reason) => {
+    if (socket === adminSocket) {
+      adminSocket = null;
+      isStreaming = false;
+      currentQrValue = null;
+      io.to('clients').emit('connected', false);
+      io.to('clients').emit('admin_present', false);
+      console.log('Admin disconnected.');
+    } else {
+      const c = clients.get(socket.id);
+      const username = c ? c.username : 'Unknown';
+      const ip = c ? c.ip : 'Unknown';
+      clients.delete(socket.id);
+      updateAdminClientList();
+      console.log(`Client disconnected: ${username} (${socket.id}) IP=${ip}, reason=${reason}`);
+    }
+  });
+});
+
+setInterval(() => {
+  io.emit('ping', Date.now());
+}, 5000);
+
+const PORT = process.env.PORT || 5000;
+server.listen(PORT, '0.0.0.0', () => console.log(`Server running on port ${PORT}`));

