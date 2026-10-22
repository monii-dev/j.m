"use strict";

// Note: The visitor's device clock supplies the time. Korea uses UTC+09:00
// without daylight-saving time. Static hosting cannot enforce a trusted clock.
const KST_OFFSET_MS = 9 * 60 * 60 * 1000;
const DAY_MS = 24 * 60 * 60 * 1000;
const VERIFY_PREFIX = new TextEncoder().encode("daily-plan-verifier-v1\0");
const KEY_PREFIX = new TextEncoder().encode("daily-plan-key-v1\0");
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", {fatal: true});
const config = window.DAILY_PLAN;
const elements = {
  loginForm: document.getElementById("login-form"),
  loginView: document.getElementById("login-view"),
  messageView: document.getElementById("message-view"),
  password: document.getElementById("password"),
  unlockButton: document.getElementById("unlock-button"),
  status: document.getElementById("login-status"),
  text: document.getElementById("message-text"),
  label: document.getElementById("today-label"),
  countdown: document.getElementById("countdown"),
  lockButton: document.getElementById("lock-button"),
  toggle: document.getElementById("toggle-visibility"),
};
let aesKey = null;
let currentDate = "";
let renderRequest = 0;
let midnightTimeout;

function todayKst() {
  return new Date(Date.now() + KST_OFFSET_MS).toISOString().slice(0, 10);
}

function nextKstMidnightMs() {
  return (Math.floor((Date.now() + KST_OFFSET_MS) / DAY_MS) + 1) * DAY_MS - KST_OFFSET_MS;
}

function formattedDay(dateKey) {
  const date = new Date(`${dateKey}T00:00:00+09:00`);
  return new Intl.DateTimeFormat("ko-KR", {
    timeZone: "Asia/Seoul", year: "numeric", month: "long", day: "numeric", weekday: "long",
  }).format(date);
}

function fromBase64(s) {
  const binary = atob(s);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

function concat(a, b) {
  const output = new Uint8Array(a.length + b.length);
  output.set(a);
  output.set(b, a.length);
  return output;
}

async function sha256(data) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}

function sameBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

async function unlock(password) {
  // Identical to build.py: SHA256(password) -> salted PBKDF2-SHA256 ->
  // domain-separated SHA256 verifier and AES-256 key.
  const firstHash = await sha256(encoder.encode(password));
  const kdfSource = await crypto.subtle.importKey("raw", firstHash, "PBKDF2", false, ["deriveBits"]);
  const stretched = new Uint8Array(await crypto.subtle.deriveBits({
    name: "PBKDF2", hash: "SHA-256", salt: fromBase64(config.salt), iterations: config.iterations,
  }, kdfSource, 256));
  const verifier = await sha256(concat(VERIFY_PREFIX, stretched));
  if (!sameBytes(verifier, fromBase64(config.verifier))) return null;
  const keyBytes = await sha256(concat(KEY_PREFIX, stretched));
  return crypto.subtle.importKey("raw", keyBytes, {name: "AES-GCM"}, false, ["decrypt"]);
}

function displayStatus(message, success = false) {
  elements.status.textContent = message;
  elements.status.classList.toggle("ok", success);
}

async function renderToday() {
  const id = ++renderRequest;
  const date = todayKst();
  elements.text.textContent = "";
  if (!aesKey) return;
  const entry = config.entries?.[date];
  if (!entry) {
    elements.text.textContent = "오늘 날짜의 문구가 아직 등록되지 않았어요.";
    return;
  }
  elements.text.textContent = "오늘의 문구를 열고 있어요…";
  try {
    const plaintext = await crypto.subtle.decrypt({
      name: "AES-GCM", iv: fromBase64(entry.iv),
      additionalData: encoder.encode(`dayplan:v1:${date}`), tagLength: 128,
    }, aesKey, fromBase64(entry.data));
    const item = JSON.parse(decoder.decode(plaintext));
    if (id !== renderRequest || date !== todayKst() || !aesKey) return;
    if (item.date !== date || typeof item.text !== "string") throw new Error("invalid message");
    elements.text.textContent = item.text; // Never interpret decrypted text as HTML.
  } catch (_) {
    if (id !== renderRequest) return;
    elements.text.textContent = "이 날짜의 문구를 복호화하지 못했어요. 관리자에게 문의해 주세요.";
  }
}

function checkDay() {
  const date = todayKst();
  if (date !== currentDate) {
    currentDate = date;
    elements.label.textContent = formattedDay(date);
    if (aesKey) renderToday();
  }
  const remaining = Math.max(0, nextKstMidnightMs() - Date.now());
  const hours = String(Math.floor(remaining / 3_600_000)).padStart(2, "0");
  const minutes = String(Math.floor((remaining % 3_600_000) / 60_000)).padStart(2, "0");
  const seconds = String(Math.floor((remaining % 60_000) / 1_000)).padStart(2, "0");
  elements.countdown.textContent = `${hours}:${minutes}:${seconds}`;
}

function scheduleMidnight() {
  clearTimeout(midnightTimeout);
  const delay = Math.max(10, nextKstMidnightMs() - Date.now() + 20);
  midnightTimeout = setTimeout(() => {
    checkDay();
    scheduleMidnight();
  }, delay);
}

function lock() {
  renderRequest++;
  aesKey = null;
  elements.text.textContent = "";
  elements.password.value = "";
  elements.messageView.hidden = true;
  elements.loginView.hidden = false;
  elements.unlockButton.disabled = false;
  displayStatus("");
  elements.password.focus();
}

elements.loginForm.addEventListener("submit", async event => {
  event.preventDefault();
  if (!config || config.version !== 1 || !config.entries || !Number.isInteger(config.iterations)) {
    displayStatus("설정되지 않은 사이트입니다. 관리자에게 암호화 파일 생성을 요청하세요.");
    return;
  }
  if (!crypto?.subtle) {
    displayStatus("HTTPS 환경에서 접속해야 암호화를 사용할 수 있어요.");
    return;
  }
  const password = elements.password.value;
  elements.password.value = "";
  elements.unlockButton.disabled = true;
  displayStatus("비밀번호를 확인하고 있어요…", true);
  try {
    const key = await unlock(password);
    if (!key) {
      displayStatus("비밀번호가 올바르지 않습니다.");
      return;
    }
    aesKey = key; // Key kept in memory only; never persisted to localStorage.
    elements.loginView.hidden = true;
    elements.messageView.hidden = false;
    await renderToday();
  } catch (_) {
    displayStatus("복호화할 수 없습니다. 파일 또는 브라우저 설정을 확인하세요.");
  } finally {
    elements.unlockButton.disabled = false;
  }
});

elements.lockButton.addEventListener("click", lock);
elements.toggle.addEventListener("click", () => {
  const reveal = elements.password.type === "password";
  elements.password.type = reveal ? "text" : "password";
  elements.toggle.textContent = reveal ? "숨김" : "보기";
  elements.toggle.setAttribute("aria-label", reveal ? "비밀번호 숨기기" : "비밀번호 표시");
});

checkDay();
scheduleMidnight();
setInterval(checkDay, 1000); // Catch clock adjustments and resumed tabs.
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) { checkDay(); scheduleMidnight(); }
});
window.addEventListener("focus", checkDay);
window.addEventListener("pageshow", checkDay);
if (!config) displayStatus("아직 암호화 문구가 없습니다. 먼저 Python 빌더를 실행해 주세요.");
