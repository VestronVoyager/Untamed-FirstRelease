/**
 * UnTamed
 * Copyright (C) 2025  vestron.wtf <oss@vestron.wtf>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, version 3 of the License only.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
const fs = require("fs");
const https = require("https");
const http = require("http");
const express = require("express");
const { WebSocketServer } = require("ws");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const selfsigned = require("selfsigned");
const net = require("net")

const app = express();

// Enforce HSTS
app.use((req, res, next) => {
  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  next();
});

const CERT_DIR = path.join(__dirname, "cert");
const KEY_PATH = path.join(CERT_DIR, "key.pem");
const CERT_PATH = path.join(CERT_DIR, "cert.pem");

// normalize remote addresses
function normalizeAddr(addr) {
  if (!addr) return addr;
  const pct = addr.indexOf('%');
  if (pct !== -1) addr = addr.substring(0, pct);
  if (addr.startsWith('::ffff:')) addr = addr.replace('::ffff:', '');
  if (addr === '::1') addr = '127.0.0.1';
  return addr;
}

// gather local addresses
function getLocalAddresses() {
  const nets = os.networkInterfaces();
  const addrs = new Set();
  addrs.add('127.0.0.1');
  addrs.add('::1');
  for (const name of Object.keys(nets)) {
    for (const net of nets[name]) {
      const a = normalizeAddr(net.address);
      if (a) addrs.add(a);
    }
  }
  return addrs;
}

app.get("/host.html", (req, res) => {
  const remoteRaw = req.socket?.remoteAddress;
  const remote = normalizeAddr(remoteRaw);
  const localAddrs = getLocalAddresses();

  if (!remote || !localAddrs.has(remote)) {
    console.warn(`Blocked /host.html access from: ${remoteRaw}`);
    return res.status(403).send("no.");
  }

  res.sendFile(path.join(__dirname, "private", "host.html"));
});
app.use("/host-assets", express.static(path.join(__dirname, "private")));
app.use(express.static(path.join(__dirname, "public")));


// Ensure cert directory exists
if (!fs.existsSync(CERT_DIR)) fs.mkdirSync(CERT_DIR, { recursive: true });

// Generate a self-signed certificate valid for ~6 months (183 days)
function generateSelfSignedCert() {
  const hostname = os.hostname() + ".local";
  const attrs = [{ name: "commonName", value: hostname }];
  // days: 183 ~ 6 months
  const opts = { days: 183, keySize: 2048, algorithm: "sha256" };
  const p = selfsigned.generate(attrs, opts);
  // p.private, p.cert (PEM encoded)
  return { key: p.private, cert: p.cert };
}

// Load existing cert/key or generate new ones if missing
function loadOrCreateCerts() {
  try {
    const keyExists = fs.existsSync(KEY_PATH);
    const certExists = fs.existsSync(CERT_PATH);
    if (keyExists && certExists) {
      const key = fs.readFileSync(KEY_PATH, "utf8");
      const cert = fs.readFileSync(CERT_PATH, "utf8");
      return { key, cert, fromFile: true };
    }
  } catch (e) {
    console.warn("Error reading existing certs, will generate new ones:", e);
  }
  const { key, cert } = generateSelfSignedCert();
  fs.writeFileSync(KEY_PATH, key, { mode: 0o600 });
  fs.writeFileSync(CERT_PATH, cert);
  console.log("Generated initial self-signed certs");
  return { key, cert, fromFile: false };
}

// Create HTTPS server using existing or newly generated certs
const initial = loadOrCreateCerts();
const httpsServer = https.createServer({ key: initial.key, cert: initial.cert }, app);

const wss = new WebSocketServer({ server: httpsServer });

let hostSocket = null;
let clientSocket = null;

// Passcode handling
const PASSCODE_EXPIRY_MS = 5 * 60 * 1000;
let currentPasscode = null; // { code, expiresAt, used }

function generatePasscode() {
  const code = String(100000 + crypto.randomInt(0, 900000));
  currentPasscode = {
    code,
    expiresAt: Date.now() + PASSCODE_EXPIRY_MS,
    used: false
  };
  broadcastPasscode();
  console.log("New passcode generated:", code);
  return currentPasscode;
}

function broadcastPasscode() {
  const payload = JSON.stringify({
    type: "passcodeUpdated",
    code: currentPasscode.code,
    expiresAt: currentPasscode.expiresAt,
    used: currentPasscode.used
  });
  wss.clients.forEach(c => {
    if (c.readyState === c.OPEN) {
      try { c.send(payload); } catch (e) {}
    }
  });
}

// initial and scheduled rotation
generatePasscode();
setInterval(() => {
  generatePasscode();
}, PASSCODE_EXPIRY_MS);

wss.on("connection", (ws) => {
  console.log("WS connected");

  // send current passcode to new peer
  try {
    if (currentPasscode) {
      ws.send(JSON.stringify({
        type: "passcodeUpdated",
        code: currentPasscode.code,
        expiresAt: currentPasscode.expiresAt,
        used: currentPasscode.used
      }));
    }
  } catch (e) {}

  ws.on("message", (msg) => {
    let data;
    try { data = JSON.parse(msg); } catch (e) { console.error("bad json", e); return; }

    // Host registration
    if (data.type === "host") {
      const remoteRaw = ws._socket?.remoteAddress;
      const remote = normalizeAddr(remoteRaw);
      const localAddrs = getLocalAddresses();

      if (!remote || !localAddrs.has(remote)) {
        console.warn("Blocked remote host registration attempt:", remoteRaw);
        ws.close();
        return;
      }

      hostSocket = ws;
      console.log("Registered host");
      if (clientSocket && clientSocket.readyState === clientSocket.OPEN) {
        clientSocket.send(JSON.stringify({ type: "requestOffer" }));
      }
      return;
    }

    // Client registration requires valid passcode
    if (data.type === "client") {
      const provided = (data.passcode || "").toString();
      console.log("Client registration attempt with passcode:", provided);

      // enforce single-client
      if (clientSocket && clientSocket.readyState === clientSocket.OPEN) {
        try { ws.send(JSON.stringify({ type: "streamConflict", reason: "another client active" })); } catch (e) {}
        return;
      }

      // validate passcode
      if (!currentPasscode || provided !== currentPasscode.code) {
        try { ws.send(JSON.stringify({ type: "authFailed", reason: "invalid_passcode" })); } catch (e) {}
        return;
      }

      // accept client and flag passcode used
      clientSocket = ws;
      currentPasscode.used = true;
      broadcastPasscode();

      try { ws.send(JSON.stringify({ type: "clientAccepted" })); } catch (e) {}

      console.log("Registered client (passcode accepted)");
      if (hostSocket && hostSocket.readyState === hostSocket.OPEN) {
        hostSocket.send(JSON.stringify({ type: "requestOffer" }));
      }
      return;
    }

    // Signaling relay
    if (data.type === "offer" && hostSocket && hostSocket.readyState === hostSocket.OPEN) {
      hostSocket.send(JSON.stringify(data));
      return;
    }
    if (data.type === "answer" && clientSocket && clientSocket.readyState === clientSocket.OPEN) {
      clientSocket.send(JSON.stringify(data));
      return;
    }
    if (data.type === "candidate") {
      if (data.to === "host" && hostSocket && hostSocket.readyState === hostSocket.OPEN) {
        hostSocket.send(JSON.stringify(data));
      } else if (data.to === "client" && clientSocket && clientSocket.readyState === clientSocket.OPEN) {
        clientSocket.send(JSON.stringify(data));
      }
      return;
    }

    // forward stuff to 'to'
    if (data.to === "host" && hostSocket && hostSocket.readyState === hostSocket.OPEN) {
      hostSocket.send(JSON.stringify(data));
    } else if (data.to === "client" && clientSocket && clientSocket.readyState === clientSocket.OPEN) {
      clientSocket.send(JSON.stringify(data));
    }
  });

  ws.on("close", () => {
    console.log("WS disconnected");
    if (ws === hostSocket) {
      hostSocket = null;
      if (clientSocket && clientSocket.readyState === clientSocket.OPEN) {
        clientSocket.send(JSON.stringify({ type: "hostDisconnected" }));
      }
    }
    if (ws === clientSocket) {
      clientSocket = null;
      if (hostSocket && hostSocket.readyState === hostSocket.OPEN) {
        hostSocket.send(JSON.stringify({ type: "clientDisconnected" }));
      }
      // regenerate passcode when client leaves
      generatePasscode();
    }
  });
});

// return local hostname
app.get("/hostname", (req, res) => {
  res.send({ hostname: os.hostname() + ".local" });
});

// local-only passcode endpoint
app.get("/passcode", (req, res) => {
  try {
    const remoteRaw = req.socket && req.socket.remoteAddress ? req.socket.remoteAddress : null;
    const remote = normalizeAddr(remoteRaw);
    const localAddrs = getLocalAddresses();

    if (!remote || !localAddrs.has(remote)) {
      console.warn(`Blocked /passcode request from non-local address: ${remoteRaw}`);
      return res.status(403).json({ error: "forbidden" });
    }

    if (!currentPasscode) return res.json({ code: null });
    res.json({
      code: currentPasscode.code,
      expiresAt: currentPasscode.expiresAt,
      used: currentPasscode.used
    });
  } catch (err) {
    console.error("Error handling /passcode:", err);
    res.status(500).json({ error: "internal_server_error" });
  }
});

// Rotate certs: generate, write files, and update running HTTPS server's credentials.
// Note: httpsServer.setSecureContext is available on Node's TLS/HTTPS servers on modern Node versions.
function rotateCertsNow() {
  try {
    const { key, cert } = generateSelfSignedCert();
    fs.writeFileSync(KEY_PATH, key, { mode: 0o600 });
    fs.writeFileSync(CERT_PATH, cert);
    // setSecureContext accepts the same options as tls.createSecureContext
    if (typeof httpsServer.setSecureContext === "function") {
      httpsServer.setSecureContext({ key, cert });
      console.log("Installed new TLS certs into running server");
    } else {
      console.warn("setSecureContext not available on this Node version; a server restart will be required to pick up new certs");
    }
  } catch (e) {
    console.error("Failed to rotate certs:", e);
  }
}

// Compute next occurrence of the 1st of the month at 00:00:00 local time
function next1stAtMidnight() {
  const now = new Date();
  // candidate: 1st of current month at 00:00:00
  let year = now.getFullYear();
  let month = now.getMonth(); // 0-based
  const candidate = new Date(year, month, 1, 0, 0, 0, 0);
  // if candidate is already in the past or is now, pick next month
  if (candidate.getTime() <= now.getTime()) {
    month += 1;
    if (month > 11) {
      month = 0;
      year += 1;
    }
  }
  return new Date(year, month, 1, 0, 0, 0, 0);
}

// monthly rotation
function scheduleMonthlyRotation() {
  const next = next1stAtMidnight();
  const delay = next.getTime() - Date.now();
  console.log(`Next cert rotation scheduled for ${next.toString()} (in ${Math.round(delay/1000)}s)`);
  setTimeout(() => {
    console.log("Running scheduled cert rotation (1st of month)");
    rotateCertsNow();
    // schedule next
    scheduleMonthlyRotation();
  }, delay);
}

// inspect the cert, this only works on node.js, if you are using a different runtime please use that runtimes API
function certExpiresBefore(msFromNow) {
  try {
    if (!fs.existsSync(CERT_PATH)) return true;
    const pem = fs.readFileSync(CERT_PATH, "utf8");
    if (typeof crypto.X509Certificate !== "function") return false;
    const x = new crypto.X509Certificate(pem);
    const validTo = new Date(x.validTo);
    return validTo.getTime() < (Date.now() + msFromNow);
  } catch (e) {
    console.warn("Could not inspect existing cert expiry:", e);
    return true;
  }
}

// If the cert is missing or expiring in less than ~5 months, generate new
const FIVE_MONTHS_MS = 1000 * 60 * 60 * 24 * 30 * 5;
if (certExpiresBefore(FIVE_MONTHS_MS)) {
  console.log("Existing cert missing or expiring soon — rotating now");
  rotateCertsNow();
}

// 1st of every month rotates the cert (hopefully)
scheduleMonthlyRotation();

const HTTPS_PORT = process.env.HTTPS_PORT || 443;
httpsServer.listen(HTTPS_PORT, () => console.log(`HTTPS/WSS running on https://${os.hostname()}.local:${HTTPS_PORT}`));

// HTTP -> HTTPS redirect
const HTTP_PORT = process.env.HTTP_PORT || 80;
http.createServer((req, res) => {
  const hostHeader = req.headers.host ? req.headers.host.replace(/:\d+$/, "") : os.hostname() + ".local";
  const location = `https://${hostHeader}${req.url}`;
  res.writeHead(301, { "Location": location });
  res.end();
}).listen(HTTP_PORT, () => console.log(`HTTP -> HTTPS redirect running on port ${HTTP_PORT}`));

//regen cert if something goes horribly wrong
if (process.stdin && process.stdin.setEncoding) {
  try {
    process.stdin.setEncoding("utf8");
    process.stdin.resume();
    process.stdin.on("data", (chunk) => {
      const cmd = String(chunk || "").trim().toLowerCase();
      if (!cmd) return;
      if (cmd === "regen") {
        console.log("Manual cert regen requested via stdin -> rotating certs now.");
        rotateCertsNow();
        return;
      }
      else if (cmd === "exit") {
         console.log("Manual exit requested!");
         console.log("Exiting...");
         process.exit(0);
      }
      console.log(`Unknown command.`);
    });
  } catch (e) {
    console.warn("Failed to initialize stdin command handler:", e);
  }

  /* ============================================================
   GLOBAL CONTROL SOCKET (Windows + Linux)
   Allows: untamed exit / untamed regen
   ============================================================ */

const CONTROL_PATH = process.platform === "win32"
  ? "\\\\.\\pipe\\untamed-control"
  : "/tmp/untamed-control.sock";

// Clean stale socket on Unix systems
if (process.platform !== "win32") {
  try {
    if (fs.existsSync(CONTROL_PATH)) {
      fs.unlinkSync(CONTROL_PATH);
    }
  } catch (e) {}
}

const controlServer = net.createServer((socket) => {
  socket.setEncoding("utf8");

  socket.on("data", (data) => {
    const cmd = String(data || "").trim().toLowerCase();

    if (cmd === "exit") {
      console.log("Control command: exit");
      socket.end("bye\n");
      process.exit(0);
      return;
    }

    if (cmd === "regen") {
      console.log("Control command: regen");
      rotateCertsNow();
      socket.end("ok\n");
      return;
    }

    socket.end("unknown\n");
  });
});

controlServer.listen(CONTROL_PATH, () => {
  if (process.platform !== "win32") {
    try { fs.chmodSync(CONTROL_PATH, 0o600); } catch {}
  }
  console.log("Control socket listening");
});

}
