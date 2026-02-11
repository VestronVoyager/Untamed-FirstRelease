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
const shareBtn = document.getElementById("shareBtn");
const localVideo = document.getElementById("localVideo");
const bg = document.getElementById("bg");
const reloadNotice = document.getElementById("reloadNotice");
const passcodeInput = document.getElementById("passcodeInput");

(function populateCodeFromUrl() {
  try {
    const usp = new URLSearchParams(window.location.search || window.location.hash || "");
    let code = usp.get("code");
    if (!code) {
      const combined = (window.location.search || "") + (window.location.hash || "");
      const m = combined.match(/(?:\?|&|#|=)?code=([^&#]*)/i);
      if (m && m[1]) code = decodeURIComponent(m[1]);
    }
    if (code) {
      passcodeInput.value = String(code);
      passcodeInput.dispatchEvent(new Event("input", { bubbles: true }));
    }
  } catch (e) {}
})();

const wsProtocol = location.protocol === "https:" ? "wss" : "ws";
const ws = new WebSocket(`${wsProtocol}://${location.host}`);

let pc = null;
let localStream = null;
let streamingActive = false;
let reloadTimer = null;

const MAX_RELOAD_ATTEMPTS = 3;
const RELOAD_KEY = "screen_stream_reload_attempts";
const RELOAD_DELAY_MS = 800;

function readReloadAttempts() {
  try {
    const v = sessionStorage.getItem(RELOAD_KEY);
    return v ? parseInt(v, 10) || 0 : 0;
  } catch {
    return 0;
  }
}

function writeReloadAttempts(n) {
  try {
    sessionStorage.setItem(RELOAD_KEY, String(n));
  } catch {}
}

function resetReloadAttempts() {
  writeReloadAttempts(0);
}

function scheduleReload(reason) {
  if (!streamingActive) return;

  const attempts = readReloadAttempts();
  if (attempts >= MAX_RELOAD_ATTEMPTS) {
    reloadNotice.style.display = "block";
    return;
  }

  if (reloadTimer) return;

  writeReloadAttempts(attempts + 1);

  reloadTimer = setTimeout(() => {
    if (!streamingActive) {
      clearReloadTimer();
      return;
    }
    window.location.reload();
  }, RELOAD_DELAY_MS);
}

function clearReloadTimer() {
  if (reloadTimer) {
    clearTimeout(reloadTimer);
    reloadTimer = null;
  }
}

function createClientPC() {
  const _pc = new RTCPeerConnection();

  _pc.onicecandidate = (ev) => {
    if (ev.candidate) {
      ws.send(JSON.stringify({ type: "candidate", to: "host", candidate: ev.candidate }));
    }
  };

  _pc.onconnectionstatechange = () => {
    if (_pc.connectionState === "failed" || _pc.connectionState === "disconnected") {
      scheduleReload("pc.connectionState");
    }
  };

  _pc.oniceconnectionstatechange = () => {
    if (["failed", "disconnected", "closed"].includes(_pc.iceConnectionState)) {
      scheduleReload("pc.iceConnectionState");
    }
  };

  _pc.onerror = () => {
    scheduleReload("pc.onerror");
  };

  return _pc;
}

async function sendOfferToHost() {
  if (!localStream) return;

  if (pc) {
    try { pc.close(); } catch {}
  }

  pc = createClientPC();
  localStream.getTracks().forEach(t => pc.addTrack(t, localStream));

  const offer = await pc.createOffer();
  await pc.setLocalDescription(offer);

  ws.send(JSON.stringify({ type: "offer", to: "host", offer }));

  localVideo.srcObject = localStream;
  localVideo.style.display = "block";
}

ws.onmessage = async (evt) => {
  let data;
  try { data = JSON.parse(evt.data); } catch { return; }

  if (data.type === "authFailed") {
    alert("Passcode rejected by server");
    return;
  }

  if (data.type === "clientAccepted") {
    await startCaptureAndOfferAfterAuth();
    return;
  }

  if (data.type === "answer") {
    if (!pc) pc = createClientPC();
    await pc.setRemoteDescription(data.answer);
    return;
  }

  if (data.type === "candidate" && data.candidate && pc) {
    try {
      await pc.addIceCandidate(new RTCIceCandidate(data.candidate));
    } catch {}
    return;
  }

  if (data.type === "requestOffer") {
    sendOfferToHost();
    return;
  }

  if (data.type === "hostDisconnected") {
    scheduleReload("hostDisconnected");
  }

  if (data.type === "streamConflict") {
    alert("Host already has an active stream.");
  }
};

ws.onerror = () => {
  if (streamingActive) scheduleReload("ws.onerror");
};

ws.onclose = () => {
  if (streamingActive) scheduleReload("ws.onclose");
};

async function startCaptureAndOfferAfterAuth() {
  try {
    localStream = await navigator.mediaDevices.getDisplayMedia({ video: true, audio: true });
    resetReloadAttempts();
    reloadNotice.style.display = "none";
    streamingActive = true;

    localStream.getTracks().forEach(track => {
      track.onended = () => scheduleReload("track.onended");
    });

    localVideo.srcObject = localStream;
    localVideo.style.display = "block";
    localVideo.muted = true;

    await sendOfferToHost();
  } catch {
    alert("Failed to start streaming. Make sure you allowed screen sharing and are on HTTPS.");
  }
}

shareBtn.onclick = () => {
  const passcode = (passcodeInput.value || "").trim();
  if (!/^\d{6}$/.test(passcode)) {
    alert("Please enter the 6-digit passcode.");
    passcodeInput.focus();
    return;
  }

  try {
    ws.send(JSON.stringify({ type: "client", passcode }));
  } catch {
    alert("Unable to contact server.");
  }
};

const RANGE_X = 8;
const RANGE_Y = 6;

function setBgPositionFromPointer(clientX, clientY) {
  const { innerWidth: w, innerHeight: h } = window;
  const nx = (clientX / w - 0.5) * 2;
  const ny = (clientY / h - 0.5) * 2;
  const px = 50 + nx * RANGE_X;
  const py = 50 + ny * RANGE_Y;
  bg.style.objectPosition = `${px}% ${py}%`;
}

window.addEventListener("mousemove", ev => {
  setBgPositionFromPointer(ev.clientX, ev.clientY);
}, { passive: true });

window.addEventListener("touchmove", ev => {
  if (ev.touches && ev.touches[0]) {
    setBgPositionFromPointer(ev.touches[0].clientX, ev.touches[0].clientY);
  }
}, { passive: true });

window.addEventListener("mouseleave", () => {
  bg.style.objectPosition = "50% 50%";
});

window.addEventListener("resize", () => {
  bg.style.objectPosition = "50% 50%";
});

window.addEventListener("beforeunload", () => {
  streamingActive = false;
  clearReloadTimer();
  try {
    if (localStream) localStream.getTracks().forEach(t => t.stop());
    if (pc) pc.close();
  } catch {}
});
