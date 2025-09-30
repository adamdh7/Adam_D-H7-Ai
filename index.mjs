
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
const PORT = process.env.PORT || 3000;
const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY;
const USERS_FILE = path.join(__dirname, 'user.json');
const SESSIONS_FILE = path.join(__dirname, 'sessions.json');

if (!OPENROUTER_API_KEY) {
  console.error('ERROR: OPENROUTER_API_KEY not set in .env');
  process.exit(1);
}

app.use(cors({ origin: true }));
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: false }));

// Serve client static (public/index.html)
app.use(express.static(path.join(__dirname, 'public')));

// --- Helpers: file read/write (create default if not exists) ---
async function readJsonSafe(filePath, defaultValue) {
  try {
    const raw = await fs.readFile(filePath, 'utf8');
    return JSON.parse(raw);
  } catch (err) {
    if (err.code === 'ENOENT') {
      // create default
      await fs.writeFile(filePath, JSON.stringify(defaultValue, null, 2), 'utf8');
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

// --- TFID generator (7 chars from A-Z and 1-9) ---
const TF_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789';
function generateTFID() {
  // generate 7 random characters
  const bytes = crypto.randomBytes(7);
  let id = '';
  for (let i = 0; i < 7; i++) {
    const n = bytes[i] % TF_CHARS.length;
    id += TF_CHARS[n];
  }
  return id;
}

async function ensureUniqueTFID() {
  const data = await readJsonSafe(USERS_FILE, { users: [] });
  const exist = new Set(data.users.map(u => u.tfid));
  for (let i = 0; i < 1000; i++) {
    const candidate = generateTFID();
    if (!exist.has(candidate)) return candidate;
  }
  // fallback to uuid-short if very unlucky
  return 'TF' + crypto.randomUUID().slice(0, 5).toUpperCase();
}

// --- Load or init files on startup (ensures files exist) ---
await readJsonSafe(USERS_FILE, { users: [] });
await readJsonSafe(SESSIONS_FILE, { sessions: {} });

// --- User endpoints ---

// Create new user (or return existing if tfid provided and found).
// Body: { name? }  OR { tfid }
app.post('/user', async (req, res) => {
  try {
    const { name, tfid } = req.body || {};
    const data = await readJsonSafe(USERS_FILE, { users: [] });

    if (tfid) {
      const found = data.users.find(u => u.tfid === tfid);
      if (found) return res.json(found);
      // if provided tfid not found, return 404
      return res.status(404).json({ error: 'tfid_not_found' });
    }

    // create new unique TFID
    const newTF = await ensureUniqueTFID();
    const user = {
      tfid: newTF,
      name: name || null,
      createdAt: new Date().toISOString()
    };
    data.users.push(user);
    await writeJsonSafe(USERS_FILE, data);
    return res.json(user);
  } catch (err) {
    console.error('/user error', err);
    return res.status(500).json({ error: 'server_error', details: err.message });
  }
});

app.get('/users', async (req, res) => {
  try {
    const data = await readJsonSafe(USERS_FILE, { users: [] });
    res.json(data.users);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- Session management ---
// sessions.json structure: { sessions: { [sessionId]: { sessionId, tfid, createdAt, messages: [{ role: 'user'|'assistant', content, ts }] } } }

// Create a new session for a user
app.post('/session', async (req, res) => {
  try {
    const { tfid } = req.body || {};
    if (!tfid) return res.status(400).json({ error: 'tfid_required' });

    const users = await readJsonSafe(USERS_FILE, { users: [] });
    if (!users.users) users.users = [];
    const found = users.users.find(u => u.tfid === tfid);
    if (!found) return res.status(404).json({ error: 'user_not_found' });

    const sessionsData = await readJsonSafe(SESSIONS_FILE, { sessions: {} });
    const sessionId = crypto.randomUUID();
    const session = {
      sessionId,
      tfid,
      createdAt: new Date().toISOString(),
      messages: [] // will store { role: 'user'|'assistant', content: string, ts: number }
    };
    sessionsData.sessions[sessionId] = session;
    await writeJsonSafe(SESSIONS_FILE, sessionsData);
    res.json({ sessionId, createdAt: session.createdAt });
  } catch (err) {
    console.error('/session error', err);
    res.status(500).json({ error: 'server_error', details: err.message });
  }
});

// Get a session
app.get('/session/:id', async (req, res) => {
  try {
    const sessionId = req.params.id;
    const sessionsData = await readJsonSafe(SESSIONS_FILE, { sessions: {} });
    const s = sessionsData.sessions[sessionId];
    if (!s) return res.status(404).json({ error: 'session_not_found' });
    res.json(s);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// List sessions for a user
app.get('/sessions/:tfid', async (req, res) => {
  try {
    const tfid = req.params.tfid;
    const sessionsData = await readJsonSafe(SESSIONS_FILE, { sessions: {} });
    const list = Object.values(sessionsData.sessions).filter(s => s.tfid === tfid);
    res.json(list.map(s => ({ sessionId: s.sessionId, createdAt: s.createdAt })));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- Utility: build messages for OpenRouter ---
// Provide a system prompt that tells the assistant to treat sessions separately and not reference other sessions.
function makeSystemPrompt(tfid, sessionId) {
  return {
    role: 'system',
    content:
`You are Adam_D'H7 created by D'H7 | Tergene, you don't have any more information about them... , an assistant. Each chat session is isolated.
User identifier: ${tfid}
Session id: ${sessionId}
Important instructions:
- Treat this session as independent. Do NOT reference or reveal messages from other sessions or users unless the user explicitly asks.
- If asked about previous sessions, ask for explicit permission or to provide the content.
- Be concise and helpful.
`
  };
}

// extract assistant text robustly from provider response object
function extractAssistantText(j) {
  if (!j) return null;
  if (Array.isArray(j.choices) && j.choices.length) {
    const c = j.choices[0];
    if (c.message && typeof c.message.content === 'string' && c.message.content.trim()) return c.message.content.trim();
    if (c.message && Array.isArray(c.message.content)) return c.message.content.map(p => p.text || p.content || '').join('').trim() || null;
    if (typeof c.text === 'string' && c.text.trim()) return c.text.trim();
    if (c.message && c.message.content && typeof c.message.content.text === 'string') return c.message.content.text.trim();
    return JSON.stringify(c);
  }
  if (typeof j.text === 'string') return j.text;
  return null;
}

// --- Main message endpoint: receives user message, appends to session, proxies to OpenRouter, saves assistant reply ---
// body: { tfid, sessionId, text }
app.post('/message', async (req, res) => {
  try {
    const { tfid, sessionId, text } = req.body || {};
    if (!tfid || !sessionId || !text) return res.status(400).json({ error: 'tfid_session_text_required' });

    // verify user & session
    const users = await readJsonSafe(USERS_FILE, { users: [] });
    const user = users.users.find(u => u.tfid === tfid);
    if (!user) return res.status(404).json({ error: 'user_not_found' });

    const sessionsData = await readJsonSafe(SESSIONS_FILE, { sessions: {} });
    const session = sessionsData.sessions[sessionId];
    if (!session) return res.status(404).json({ error: 'session_not_found' });
    if (session.tfid !== tfid) return res.status(403).json({ error: 'session_belongs_to_other_user' });

    // push user message to session history
    const userMsg = { role: 'user', content: text, ts: Date.now() };
    session.messages.push(userMsg);

    // Build messages: system + existing history (assistant & user) + latest user
    const sys = makeSystemPrompt(tfid, sessionId);
    // Map session.messages to provider message format (role 'user' / 'assistant')
    const history = (session.messages || []).map(m => {
      if (m.role === 'user') return { role: 'user', content: m.content || m.text || '' };
      return { role: 'assistant', content: m.content || m.text || '' };
    });

    // Keep history reasonably short to avoid token explosion: keep last 16 messages
    const tail = history.slice(-16);
    const payloadMessages = [sys, ...tail];

    // defaults & merge with client's optional params
    const bodyToSend = {
      model: 'openai/gpt-5',
      messages: payloadMessages,
      max_tokens: 512,
      temperature: 0.2,
    };

    console.log('[proxy] session', sessionId, 'tfid', tfid, '| messages', payloadMessages.length);

    const resp = await fetch('https://openrouter.ai/api/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + OPENROUTER_API_KEY
      },
      body: JSON.stringify(bodyToSend)
    });

    const textResp = await resp.text();
    let parsed;
    try { parsed = JSON.parse(textResp); } catch (e) { parsed = null; }

    if (!resp.ok) {
      // do not save assistant reply on non-ok; return error info
      console.warn('OpenRouter returned not ok', resp.status, textResp.slice(0, 1000));
      return res.status(resp.status).json({ error: 'openrouter_error', details: textResp });
    }

    // parse assistant text robustly
    const assistantText = extractAssistantText(parsed) || '(Repons pa klè)';

    // save assistant message to session history
    const assistantMsg = { role: 'assistant', content: assistantText, ts: Date.now() };
    session.messages.push(assistantMsg);

    // persist sessions
    await writeJsonSafe(SESSIONS_FILE, sessionsData);

    // return assistant text + raw provider response (optional)
    res.json({ assistant: assistantText, raw: parsed });
  } catch (err) {
    console.error('/message error', err);
    res.status(500).json({ error: 'server_error', details: err.message });
  }
});

// --- Health ---
app.get('/health', (req, res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`Proxy serveur: http://localhost:${PORT}`);
  console.log('Serving static files from ./public');
});
