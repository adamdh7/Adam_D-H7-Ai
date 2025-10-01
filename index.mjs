// index.mjs
import express from 'express';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import { promises as fs } from 'fs';
import crypto from 'crypto';

dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

/* ---------------------------
   Config
   --------------------------- */
const PORT = Number(process.env.PORT) || 3000;
const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY;
const OPENROUTER_ENDPOINT = process.env.OPENROUTER_ENDPOINT || 'https://openrouter.ai/api/v1/chat/completions';
const OPENROUTER_MODEL = process.env.OPENROUTER_MODEL || 'gpt-5';

// keep last 7 messages as most important
const HISTORY_TAIL = 7;

const DEFAULT_MAX_TOKENS = Number(process.env.DEFAULT_MAX_TOKENS) || 150;
const DEFAULT_TIMEOUT_MS = Number(process.env.DEFAULT_TIMEOUT_MS) || 30000;
const MAX_RETRIES = Number(process.env.MAX_RETRIES) || 3;
const DEFAULT_USER_NAME = process.env.DEFAULT_USER_NAME || "User";

const TF_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz123456789';
const USERS_FILE = path.join(__dirname, 'user.json');
const SESSIONS_FILE = path.join(__dirname, 'sessions.json');
const USER_HISTORY_FILE = path.join(__dirname, 'user_history.json');

if (!OPENROUTER_API_KEY) {
  console.error('ERROR: OPENROUTER_API_KEY missing in .env');
  process.exit(1);
}

app.use(cors({ origin: true }));
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

/* ---------------------------
   JSON helpers
   --------------------------- */
async function readJsonSafe(filePath, defaultValue) {
  try {
    const raw = await fs.readFile(filePath, 'utf8');
    return JSON.parse(raw);
  } catch (err) {
    if (err && err.code === 'ENOENT') {
      try { await fs.writeFile(filePath, JSON.stringify(defaultValue, null, 2), 'utf8'); } catch (e) {}
      return defaultValue;
    }
    throw err;
  }
}
async function writeJsonSafe(filePath, obj) {
  const tmp = filePath + '.tmp';
  const data = JSON.stringify(obj, null, 2);
  await fs.writeFile(tmp, data, 'utf8');
  await fs.rename(tmp, filePath);
}

/* ---------------------------
   TFID generator
   --------------------------- */
function generateTFIDRaw(len = 7) {
  const bytes = crypto.randomBytes(len);
  let id = '';
  for (let i = 0; i < len; i++) id += TF_CHARS[bytes[i] % TF_CHARS.length];
  return id;
}
async function ensureUniqueTFID() {
  const data = await readJsonSafe(USERS_FILE, { users: [] });
  const exist = new Set((data.users || []).map(u => u.tfid));
  for (let i = 0; i < 20000; i++) {
    const candidate = 'TF-' + generateTFIDRaw(7);
    if (!exist.has(candidate)) return candidate;
  }
  return 'TF-' + crypto.randomUUID().slice(0,7).toUpperCase();
}

/* ---------------------------
   Simple marker helpers (server-side only)
   --------------------------- */
const MARKER = '***Terminé***';
function ensureMarkerBefore(text) {
  const t = text == null ? '' : String(text).trim();
  if (!t) return MARKER;
  if (t.includes(MARKER)) return t;
  return `${MARKER}\n\n${t}`;
}
function extractVisibleFromWrapped(wrapped) {
  if (!wrapped || typeof wrapped !== 'string') return '';
  const idx = wrapped.lastIndexOf(MARKER);
  if (idx === -1) return wrapped.trim();
  return wrapped.slice(idx + MARKER.length).trim();
}

/* ---------------------------
   Extract assistant text from provider response (NO sanitization)
   --------------------------- */
function extractAssistantText(payloadJson) {
  if (!payloadJson) return null;
  try {
    if (Array.isArray(payloadJson.choices) && payloadJson.choices.length) {
      const c = payloadJson.choices[0];
      const content = c?.message?.content ?? c?.text ?? '';
      if (typeof content === 'string' && content.trim()) {
        return content.trim();
      }
    }
    for (const k of ['response','output','result','text']) {
      if (typeof payloadJson[k] === 'string' && payloadJson[k].trim()) {
        return payloadJson[k].trim();
      }
    }
  } catch (e) {}
  return null;
}

/* ---------------------------
   fetch wrapper with timeout
   --------------------------- */
async function fetchWithTimeout(url, options = {}, timeoutMs = DEFAULT_TIMEOUT_MS) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const r = await fetch(url, { ...options, signal: controller.signal });
    const txt = await r.text();
    let parsed = null;
    try { parsed = JSON.parse(txt); } catch (e) {}
    return { ok: r.ok, status: r.status, text: txt, json: parsed };
  } catch (err) {
    return { ok: false, fetchError: err, status: 502, text: String(err) };
  } finally {
    clearTimeout(id);
  }
}

/* ---------------------------
   Init files
   --------------------------- */
await readJsonSafe(USERS_FILE, { users: [] });
await readJsonSafe(SESSIONS_FILE, { sessions: {} });
await readJsonSafe(USER_HISTORY_FILE, { histories: {} });

/* ---------------------------
   System prompt (minimal, no forcing)
   --------------------------- */
function makeSystemPrompt(tfid, sessionId, userName = null) {
  const display = userName || DEFAULT_USER_NAME || tfid;
  const identity = "You are Adam_D'H7 everyone's friend created by D'H7 | Tergene.";
  const lines = [
    identity,
    `Session: ${sessionId}`,
    'Respond naturally to the user message.'
  ];
  return { role: 'system', content: lines.join(' ') };
}

/* ---------------------------
   Endpoints: user/session/history
   --------------------------- */
app.post('/user', async (req, res) => {
  try {
    const { name, tfid } = req.body || {};
    const data = await readJsonSafe(USERS_FILE, { users: [] });
    if (tfid) {
      const found = (data.users || []).find(u => u.tfid === tfid);
      if (found) return res.json(found);
      return res.status(404).json({ error: 'tfid_not_found' });
    }
    const newTF = await ensureUniqueTFID();
    const user = { tfid: newTF, name: name || DEFAULT_USER_NAME, createdAt: new Date().toISOString() };
    data.users = data.users || [];
    data.users.push(user);
    await writeJsonSafe(USERS_FILE, data);
    const hist = await readJsonSafe(USER_HISTORY_FILE, { histories: {} });
    hist.histories = hist.histories || {};
    hist.histories[newTF] = hist.histories[newTF] || [];
    await writeJsonSafe(USER_HISTORY_FILE, hist);
    return res.json(user);
  } catch (err) {
    console.error('/user error', err);
    return res.status(500).json({ error: 'server_error', details: String(err?.message || err) });
  }
});

app.post('/session', async (req, res) => {
  try {
    const { tfid } = req.body || {};
    if (!tfid) return res.status(400).json({ error: 'tfid_required' });
    const usersObj = await readJsonSafe(USERS_FILE, { users: [] });
    const found = (usersObj.users || []).find(u => u.tfid === tfid);
    if (!found) return res.status(404).json({ error: 'user_not_found' });
    const sessionsData = await readJsonSafe(SESSIONS_FILE, { sessions: {} });
    sessionsData.sessions = sessionsData.sessions || {};
    const sessionId = crypto.randomUUID();
    const session = { sessionId, tfid, createdAt: new Date().toISOString(), messages: [] };
    sessionsData.sessions[sessionId] = session;
    await writeJsonSafe(SESSIONS_FILE, sessionsData);
    res.json({ sessionId, createdAt: session.createdAt });
  } catch (err) {
    console.error('/session error', err);
    res.status(500).json({ error: 'server_error', details: String(err?.message || err) });
  }
});

app.get('/history/:tfid/:n?', async (req, res) => {
  try {
    const tfid = req.params.tfid;
    const n = Math.max(1, Math.min(1000, Number(req.params.n || 100)));
    const hist = await readJsonSafe(USER_HISTORY_FILE, { histories: {} });
    const arr = (hist.histories && hist.histories[tfid]) ? hist.histories[tfid] : [];
    res.json(arr.slice(-n));
  } catch (err) {
    res.status(500).json({ error: String(err?.message || err) });
  }
});

/* ---------------------------
   /message endpoint (minimal behaviour)
   --------------------------- */
app.post('/message', async (req, res) => {
  try {
    const { tfid, sessionId } = req.body || {};
    let text = req.body?.text;
    if (!tfid || !sessionId || typeof text !== 'string' || !text.trim()) {
      return res.status(400).json({ error: 'tfid_session_text_required' });
    }
    const clean = String(text).trim();

    // verify user & session
    const users = await readJsonSafe(USERS_FILE, { users: [] });
    const user = (users.users || []).find(u => u.tfid === tfid);
    if (!user) return res.status(404).json({ error: 'user_not_found' });
    const sessionsData = await readJsonSafe(SESSIONS_FILE, { sessions: {} });
    sessionsData.sessions = sessionsData.sessions || {};
    const session = sessionsData.sessions[sessionId];
    if (!session) return res.status(404).json({ error: 'session_not_found' });
    if (session.tfid !== tfid) return res.status(403).json({ error: 'session_belongs_to_other_user' });

    // append user message to session + history
    session.messages = session.messages || [];
    session.messages.push({ role: 'user', content: clean, ts: Date.now() });
    const hist = await readJsonSafe(USER_HISTORY_FILE, { histories: {} });
    hist.histories = hist.histories || {};
    hist.histories[tfid] = hist.histories[tfid] || [];
    hist.histories[tfid].push({ role: 'user', content: clean, sessionId, ts: Date.now() });
    await writeJsonSafe(SESSIONS_FILE, sessionsData);
    await writeJsonSafe(USER_HISTORY_FILE, hist);

    // Build messages: minimal system prompt + last HISTORY_TAIL messages + final user message
    const systemMsg = makeSystemPrompt(tfid, sessionId, user.name || DEFAULT_USER_NAME);
    const tail = (session.messages || []).slice(-HISTORY_TAIL).map(m => ({ role: m.role, content: m.content || '' }));
    // Ensure last user message is last entry
    const messagesForProvider = [systemMsg, ...tail, { role: 'user', content: clean }];

    // call provider (simple retry)
    let attempt = 0;
    let lastResp = null;
    let assistantText = null;
    while (attempt < MAX_RETRIES) {
      attempt++;
      const payload = {
        model: OPENROUTER_MODEL,
        messages: messagesForProvider,
        max_tokens: DEFAULT_MAX_TOKENS,
        temperature: 0.2
      };
      lastResp = await fetchWithTimeout(OPENROUTER_ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + OPENROUTER_API_KEY },
        body: JSON.stringify(payload)
      }, DEFAULT_TIMEOUT_MS);

      if (!lastResp.ok) {
        continue;
      }
      assistantText = extractAssistantText(lastResp.json);
      if (assistantText) break;
    }

    if (!assistantText) {
      assistantText = "Désolé, je n'ai pas pu obtenir de réponse. Peux-tu reformuler ?";
    }

    // store assistant message (server adds marker for storage only)
    const wrapped = ensureMarkerBefore(assistantText);
    session.messages.push({ role: 'assistant', content: wrapped, ts: Date.now() });
    hist.histories[tfid].push({ role: 'assistant', content: wrapped, sessionId, ts: Date.now() });
    await writeJsonSafe(SESSIONS_FILE, sessionsData);
    await writeJsonSafe(USER_HISTORY_FILE, hist);

    const visible = extractVisibleFromWrapped(wrapped);
    return res.json({ assistant: visible });

  } catch (err) {
    console.error('/message error', err);
    return res.status(500).json({ error: 'server_error', details: String(err?.message || err) });
  }
});

/* ---------------------------
   health
   --------------------------- */
app.get('/health', (req, res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT} (HISTORY_TAIL=${HISTORY_TAIL})`);
});
