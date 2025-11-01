
'use strict';

var express = require('express');
var http = require('http');
var socketIo = require('socket.io');
var path = require('path');
var axios = require('axios');

var app = express();

var cookieParser;
try {
  cookieParser = require('cookie-parser');
  app.use(cookieParser());
} catch (err) {
  console.log('cookie-parser not installed. Run: npm install cookie-parser');
}

app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

var server = http.createServer(app);
var io = new socketIo.Server(server, {
  pingInterval: 10000,
  pingTimeout: 5000,
});

function cookieExpiryAtUTCMidnight() {
  var expiry = new Date();
  expiry.setUTCHours(23, 59, 59, 999);
  return expiry;
}

function parseCookies(cookieHeader) {
  var list = {};
  if (!cookieHeader) return list;
  var cookies = cookieHeader.split(';');
  for (var i = 0; i < cookies.length; i = 1) {
    var parts = cookies[i].split('=');
    var name = parts.shift();
    if (name) {
      name = name.trim();
      var value = decodeURIComponent(parts.join('='));
      list[name] = value;
    }
  }
  return list;
}

function getRequestCookie(req, name) {
  if (!name) return null;
  if (req.cookies && typeof req.cookies[name] !== 'undefined') {
    return req.cookies[name];
  }
  var header = req.headers ? req.headers.cookie : '';
  if (!header) return null;
  var parsed = parseCookies(header);
  return parsed[name] || null;
}

function flagEmoji(code) {
  if (!code || code.length !== 2) return '';
  var upper = code.toUpperCase();
  var first = upper.charCodeAt(0) - 65  0x1f1e6;
  var second = upper.charCodeAt(1) - 65  0x1f1e6;
  return String.fromCodePoint(first, second);
}

function normalizeISP(raw) {
  if (!raw) return 'Unknown';
  var low = raw.toLowerCase();
  var map = [
    { keys: ['ethionet', 'ethiotelecom', 'ethio telecom'], name: 'Ethio Telecom' },
    { keys: ['safaricom', 'vodafone'], name: 'Safaricom Ethiopia PLC' },
    { keys: ['mtn'], name: 'MTN Group' },
    { keys: ['airtel'], name: 'Airtel Africa' },
    { keys: ['aws', 'amazon'], name: 'Amazon Web Services' },
    { keys: ['azure', 'microsoft'], name: 'Microsoft Azure' },
    { keys: ['oracle'], name: 'Oracle Cloud' },
    { keys: ['ovh'], name: 'OVHcloud' },
    { keys: ['hetzner'], name: 'Hetzner Online' },
    { keys: ['cloudflare'], name: 'Cloudflare' },
    { keys: ['starlink'], name: 'Starlink Internet' },
    { keys: ['hostinger'], name: 'Hostinger' },
    { keys: ['contabo'], name: 'Contabo GmbH' },
    { keys: ['linode'], name: 'Linode (Akamai)' },
  ];
  for (var i = 0; i < map.length; i = 1) {
    var entry = map[i];
    for (var j = 0; j < entry.keys.length; j = 1) {
      if (low.indexOf(entry.keys[j]) !== -1) {
        return entry.name;
      }
    }
  }
  return raw;
}

async function lookupIpDetails(ip) {
  if (!ip || ip === 'Unknown') {
    return {
      ip: ip || 'Unknown',
      city: 'Unknown',
      region: 'Unknown',
      country: 'Unknown',
      countryCode: '',
      isp: 'Unknown',
      vpn: false,
    };
  }
  var normalized = normalizeAddress(ip);
  if (isPrivateIp(normalized)) {
    return {
      ip: normalized,
      city: 'Local Network',
      region: 'Local',
      country: 'Local',
      countryCode: '',
      isp: 'Local Network',
      vpn: false,
    };
  }
  try {
    var response = await axios.get(
      'http://ip-api.com/json/' 
        normalized 
        '?fields=status,message,query,country,countryCode,regionName,city,isp,proxy,hosting'
    );
    var data = response.data;
    if (data && data.status === 'success') {
      return {
        ip: data.query || normalized,
        city: data.city || 'Unknown',
        region: data.regionName || 'Unknown',
        country: data.country || 'Unknown',
        countryCode: data.countryCode || '',
        isp: normalizeISP(data.isp),
        vpn: !!(data.proxy || data.hosting),
      };
    }
  } catch (err) {
    console.log('IP lookup failed for '  ip  ': '  err.message);
  }
  return {
    ip: normalized,
    city: 'Unknown',
    region: 'Unknown',
    country: 'Unknown',
    countryCode: '',
    isp: 'Unknown',
    vpn: false,
  };
}

app.get('/login', function (req, res) {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/api/login', function (req, res) {
  var username = req.body ? req.body.username : '';
  if (!username || !username.trim()) {
    return res.status(400).send('Username is required.');
  }
  res.cookie('username', username.trim(), {
    expires: cookieExpiryAtUTCMidnight(),
    httpOnly: true,
    sameSite: 'Lax',
  });
  return res.redirect('/');
});

app.get('/api/verify', function (req, res) {
  var username = getRequestCookie(req, 'username');
  if (username) return res.json({ valid: true, username: username });
  return res.json({ valid: false });
});

app.get('/broadcast', function (req, res) {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/', function (req, res) {
  if (!getRequestCookie(req, 'username')) return res.redirect('/login');
  return res.sendFile(path.join(__dirname, 'public', 'client.html'));
});

var adminSocket = null;
var clients = new Map();
var currentQrValue = null;
var isStreaming = false;
var isHidden = false;

function normalizeAddress(raw) {
  if (!raw) return null;
  var trimmed = String(raw).trim();
  if (trimmed.indexOf('::ffff:') === 0) {
    return trimmed.substring(7);
  }
  if (trimmed === '::1') {
    return '127.0.0.1';
  }
  return trimmed;
}

function safeForwardedAddress(headers) {
  if (!headers) return null;
  var forwarded = headers['x-forwarded-for'];
  if (!forwarded) return null;
  var parts = forwarded.split(',');
  if (!parts.length) return null;
  return normalizeAddress(parts[0]);
}

function isPrivateIp(ip) {
  if (!ip) return false;
  if (ip === '127.0.0.1') return true;
  if (ip.indexOf('10.') === 0) return true;
  if (ip.indexOf('192.168.') === 0) return true;
  if (ip.indexOf('172.') === 0) {
    var second = parseInt(ip.split('.')[1], 10);
    if (!isNaN(second) && second >= 16 && second <= 31) {
      return true;
    }
  }
  if (ip === '::1') return true;
  return false;
}

function getClientList() {
  var list = [];
  clients.forEach(function (client, id) {
    list.push({
      id: id,
      username: client.username,
      ip: client.ip,
      city: client.city,
      region: client.region,
      country: client.country,
      countryFlag: client.countryFlag,
      isp: client.isp,
      vpn: client.vpn,
      ping: client.ping,
    });
  });
  return list;
}

function updateAdminClientList() {
  if (adminSocket) {
    adminSocket.emit('client_list', getClientList());
  }
}

io.on('connection', function (socket) {
  socket.on('join_guest', async function (guestId) {
    var ip =
      safeForwardedAddress(socket.handshake.headers) || normalizeAddress(socket.handshake.address);
    if (!ip) {
      ip = 'Unknown';
    }
    var details = await lookupIpDetails(ip);
    clients.set(socket.id, {
      ping: 0,
      username: guestId  ' (Not logged in yet)',
      ip: details.ip,
      city: details.city,
      region: details.region,
      country: details.country,
      countryFlag: flagEmoji(details.countryCode),
      isp: details.isp,
      vpn: details.vpn,
    });
    socket.join('clients');
    updateAdminClientList();
    console.log('Guest joined: '  guestId  ' ('  details.ip  ')');
  });

  socket.on('join', async function (role) {
    if (role === 'admin') {
      if (adminSocket) {
        socket.emit('error', 'Admin already connected');
        socket.disconnect();
        return;
      }
      adminSocket = socket;
      socket.emit('state', { isStreaming: isStreaming, isHidden: isHidden, currentQrValue: currentQrValue });
      socket.emit('hide_state', isHidden);
      socket.emit('client_list', getClientList());
      io.to('clients').emit('admin_present', true);
      console.log('Admin connected: '  socket.id);
      return;
    }

    if (role === 'client') {
      var cookieHeader = (socket.handshake.headers && socket.handshake.headers.cookie) || '';
      var parsed = parseCookies(cookieHeader);
      var username = parsed.username;
      if (!username) {
        socket.emit('forbidden', 'Login required. Please refresh.');
        setTimeout(function () {
          socket.disconnect(true);
        }, 50);
        return;
      }

      var clientIp =
        safeForwardedAddress(socket.handshake.headers) || normalizeAddress(socket.handshake.address);
      if (!clientIp) {
        clientIp = 'Unknown';
      }
      var info = await lookupIpDetails(clientIp);

      clients.set(socket.id, {
        ping: 0,
        username: username,
        ip: info.ip,
        city: info.city,
        region: info.region,
        country: info.country,
        countryFlag: flagEmoji(info.countryCode),
        isp: info.isp,
        vpn: info.vpn,
      });

      socket.join('clients');
      socket.emit('connected', true);
      if (isStreaming && !isHidden && currentQrValue) {
        socket.emit('qr_update', currentQrValue);
      }
      updateAdminClientList();
      console.log(
        'Client connected: ' 
          username 
          ' (' 
          socket.id 
          ') IP=' 
          info.ip 
          ' ISP=' 
          info.isp 
          ' Country=' 
          info.country 
          ' VPN=' 
          (info.vpn ? 'true' : 'false')
      );
      return;
    }

    socket.emit('error', 'Unknown role');
    socket.disconnect(true);
  });

  socket.on('start_stream', function () {
    if (socket !== adminSocket) return;
    isStreaming = true;
    io.to('clients').emit('connected', true);
    if (adminSocket) {
      adminSocket.emit('state', { isStreaming: isStreaming, isHidden: isHidden, currentQrValue: currentQrValue });
    }
    console.log('Streaming started by admin');
  });

  socket.on('stop_stream', function () {
    if (socket !== adminSocket) return;
    isStreaming = false;
    currentQrValue = null;
    io.to('clients').emit('connected', false);
    io.to('clients').emit('qr_update', null);
    if (adminSocket) {
      adminSocket.emit('qr_preview', null);
      adminSocket.emit('state', { isStreaming: isStreaming, isHidden: isHidden, currentQrValue: currentQrValue });
    }
    console.log('Streaming stopped by admin');
  });

  socket.on('toggle_hide', function (hide) {
    if (socket !== adminSocket) return;
    isHidden = !!hide;
    if (isHidden) {
      io.to('clients').emit('qr_update', null);
    } else if (currentQrValue) {
      io.to('clients').emit('qr_update', currentQrValue);
    }
    if (adminSocket) {
      adminSocket.emit('hide_state', isHidden);
    }
    console.log('Hide toggled: '  isHidden);
  });

  socket.on('qr_update', function (value) {
    if (socket !== adminSocket || !isStreaming) return;
    if (value && value !== currentQrValue) {
      currentQrValue = value;
      if (!isHidden) {
        io.to('clients').emit('qr_update', value);
      }
      if (adminSocket) {
        adminSocket.emit('qr_preview', value);
      }
      console.log('QR updated and broadcasted');
    }
  });

  socket.on('request_client_list', function () {
    if (socket !== adminSocket) return;
    socket.emit('client_list', getClientList());
  });

  socket.on('pong', function (startTime) {
    var ping = Date.now() - startTime;
    if (clients.has(socket.id)) {
      var existing = clients.get(socket.id);
      clients.set(socket.id, {
        ping: ping,
        username: existing.username,
        ip: existing.ip,
        city: existing.city,
        region: existing.region,
        country: existing.country,
        countryFlag: existing.countryFlag,
        isp: existing.isp,
        vpn: existing.vpn,
      });
      updateAdminClientList();
    } else if (socket === adminSocket) {
      socket.emit('your_ping', ping);
    }
  });

  socket.on('disconnect', function (reason) {
    if (socket === adminSocket) {
      adminSocket = null;
      isStreaming = false;
      currentQrValue = null;
      io.to('clients').emit('connected', false);
      io.to('clients').emit('admin_present', false);
      console.log('Admin disconnected.');
    } else {
      var record = clients.get(socket.id);
      var username = record ? record.username : 'Unknown';
      var ip = record ? record.ip : 'Unknown';
      clients.delete(socket.id);
      updateAdminClientList();
      console.log('Client disconnected: ' + username + ' (' + socket.id + ') IP=' + ip + ', reason=' + reason);
    }
  });
});

setInterval(function () {
  io.emit('ping', Date.now());
}, 5000);

var PORT = process.env.PORT || 5000;
server.listen(PORT, '0.0.0.0', function () {
  console.log('Server running on port ' + PORT);
});
