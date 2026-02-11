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
const path = require("path");
const os = require("os");
const selfsigned = require("selfsigned");

const CERT_DIR = path.join(__dirname, "cert");
const KEY_PATH = path.join(CERT_DIR, "key.pem");
const CERT_PATH = path.join(CERT_DIR, "cert.pem");
const META_PATH = path.join(CERT_DIR, "meta.json");

// validity in days for ~6 months (give or take)
const VALIDITY_DAYS = 180;

function ensureCertDir() {
  if (!fs.existsSync(CERT_DIR)) fs.mkdirSync(CERT_DIR, { recursive: true });
}

function writeFiles({ key, cert, expiresAt }) {
  ensureCertDir();
  fs.writeFileSync(KEY_PATH, key, { mode: 0o600 });
  fs.writeFileSync(CERT_PATH, cert, { mode: 0o644 });
  fs.writeFileSync(META_PATH, JSON.stringify({ expiresAt }, null, 2));
}

function readMeta() {
  try {
    const raw = fs.readFileSync(META_PATH, "utf8");
    return JSON.parse(raw);
  } catch (e) {
    return null;
  }
}

function readPemFiles() {
  try {
    const key = fs.readFileSync(KEY_PATH, "utf8");
    const cert = fs.readFileSync(CERT_PATH, "utf8");
    return { key, cert };
  } catch (e) {
    return null;
  }
}

function generate(hostnames = []) {
  // properties for the certificate subject alt names
  const attrs = [
    { name: "commonName", value: hostnames[0] || os.hostname() },
  ];

  const opts = {
    days: VALIDITY_DAYS,
    keySize: 2048,
    algorithm: "sha256",
    extensions: [
      {
        name: "subjectAltName",
        altNames: hostnames.map(h => {
          if (/^\d+\.\d+\.\d+\.\d+$/.test(h)) return { type: 7, ip: h }; // IP
          if (h.endsWith(".local")) return { type: 2, value: h }; // DNS
          return { type: 2, value: h };
        })
      }
    ]
  };

  const pems = selfsigned.generate(attrs, opts);
  const expiresAt = Date.now() + VALIDITY_DAYS * 24 * 60 * 60 * 1000;
  writeFiles({ key: pems.private, cert: pems.cert, expiresAt });
  return { key: pems.private, cert: pems.cert, expiresAt };
}

function needRegenSoon(thresholdMs = 24 * 60 * 60 * 1000 * 7) { // default: 7 days
  const meta = readMeta();
  if (!meta || !meta.expiresAt) return true;
  const now = Date.now();
  return (meta.expiresAt - now) < thresholdMs;
}

function ensureCerts(hostname) {
  ensureCertDir();

  // try to read existing pem files and meta
  const pem = readPemFiles();
  const meta = readMeta();

  if (pem && meta && meta.expiresAt && meta.expiresAt > Date.now()) {
    // existing cert is valid
    return { key: pem.key, cert: pem.cert, expiresAt: meta.expiresAt };
  }

  const hostnames = [hostname, os.hostname(), "localhost", "127.0.0.1", "::1"].filter(Boolean);
  return generate(Array.from(new Set(hostnames)));
}

function msUntilNextDayOfMonth(day) {
  const now = new Date();
  const thisMonthTarget = new Date(now.getFullYear(), now.getMonth(), day, 2, 0, 0, 0);

  if (thisMonthTarget.getMonth() !== now.getMonth()) {
    const nextMonth = new Date(now.getFullYear(), now.getMonth() + 1, day, 2, 0, 0, 0);
    return nextMonth - now;
  }

  if (thisMonthTarget > now) return thisMonthTarget - now;

  const next = new Date(now.getFullYear(), now.getMonth() + 1, day, 2, 0, 0, 0);
  if (next.getDate() !== day) {
    let m = now.getMonth() + 2;
    let y = now.getFullYear();
    while (true) {
      const candidate = new Date(y, m - 1, day, 2, 0, 0, 0);
      if (candidate.getDate() === day) return candidate - now;
      m++;
      if (m > 12) { m = 1; y++; }
    }
  }
  return next - now;
}

function scheduleRotation(server, dayOfMonth = 28, onRotateCallback) {
  // 7day expiry
  if (needRegenSoon()) {
    const hn = os.hostname() + ".local";
    const newCert = ensureCerts(hn);
    // attempt to reload into running server
    try {
      if (server && typeof server.setSecureContext === "function") {
        server.setSecureContext({ key: newCert.key, cert: newCert.cert });
        if (typeof onRotateCallback === "function") onRotateCallback(newCert);
      }
    } catch (e) {
      console.warn("Failed to set initial secure context:", e);
    }
  }

  // schedule function
  function scheduleNext() {
    const ms = msUntilNextDayOfMonth(dayOfMonth);
    console.log(`Next cert rotation scheduled in ${(ms / 1000 / 60 / 60).toFixed(2)} hours`);
    setTimeout(async () => {
      try {
        const hn = os.hostname() + ".local";
        const newCert = ensureCerts(hn); 
        const rotated = generate([hn, os.hostname(), "localhost", "127.0.0.1", "::1"]);
        try {
          if (server && typeof server.setSecureContext === "function") {
            server.setSecureContext({ key: rotated.key, cert: rotated.cert });
            console.log("TLS context rotated with new self-signed certificate");
            if (typeof onRotateCallback === "function") onRotateCallback(rotated);
          } else {
            console.log("No server.setSecureContext available; cert files were written but server was not reloaded in-memory");
          }
        } catch (e) {
          console.error("Failed to set secure context on server:", e);
        }
      } catch (err) {
        console.error("Error during cert rotation:", err);
      } finally {
        scheduleNext();
      }
    }, ms);
  }

  scheduleNext();
}

module.exports = {
  ensureCerts,
  scheduleRotation,
  KEY_PATH,
  CERT_PATH,
  META_PATH,
};