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
const PORT = process.env.PORT || 3000;
const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY || '';
const USERS_FILE = path.join(__dirname, 'user.json');
const SESSIONS_FILE = path.join(__dirname, 'sessions.json');

const DEFAULT_MAX_TOKENS = Number(process.env.DEFAULT_MAX_TOKENS) || 512;
const DEFAULT_TEMPERATURE = Number(process.env.DEFAULT_TEMPERATURE) || 0.2;
const HISTORY_MESSAGE_LIMIT = Number(process.env.HISTORY_MESSAGE_LIMIT) || 16;

if (!OPENROUTER_API_KEY) {
  console.error('ERROR: OPENROUTER_API_KEY not set in .env (OPENROUTER_API_KEY). Exiting.');
  process.exit(1);
}

app.use(cors({ origin: true }));
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

// helpers
async function readJsonSafe(filePath, defaultValue) {
  try {
    const raw = await fs.readFile(filePath, 'utf8');
    return JSON.parse(raw);
  } catch (err) {
    if (err.code === 'ENOENT') {
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

// TFID gen
const TF_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789';
function generateTFID() {
  const bytes = crypto.randomBytes(7);
  let id = '';
  for (let i = 0; i < 7; i++) {
    id += TF_CHARS[bytes[i] % TF_CHARS.length];
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
  return 'TF' + crypto.randomUUID().slice(0, 5).toUpperCase();
}

// ensure files exist
await readJsonSafe(USERS_FILE, { users: [] });
await readJsonSafe(SESSIONS_FILE, { sessions: {} });

// user/session endpoints (same as before)
app.post('/user', async (req, res) => {
  try {
    const { name, tfid } = req.body || {};
    const data = await readJsonSafe(USERS_FILE, { users: [] });
    if (tfid) {
      const found = data.users.find(u => u.tfid === tfid);
      if (found) return res.json(found);
      return res.status(404).json({ error: 'tfid_not_found' });
    }
    const newTF = await ensureUniqueTFID();
    const user = { tfid: newTF, name: name || null, createdAt: new Date().toISOString() };
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

app.post('/session', async (req, res) => {
  try {
    const { tfid } = req.body || {};
    if (!tfid) return res.status(400).json({ error: 'tfid_required' });
    const users = await readJsonSafe(USERS_FILE, { users: [] });
    const found = users.users.find(u => u.tfid === tfid);
    if (!found) return res.status(404).json({ error: 'user_not_found' });
    const sessionsData = await readJsonSafe(SESSIONS_FILE, { sessions: {} });
    const sessionId = crypto.randomUUID();
    const session = { sessionId, tfid, createdAt: new Date().toISOString(), messages: [] };
    sessionsData.sessions[sessionId] = session;
    await writeJsonSafe(SESSIONS_FILE, sessionsData);
    res.json({ sessionId, createdAt: session.createdAt });
  } catch (err) {
    console.error('/session error', err);
    res.status(500).json({ error: 'server_error', details: err.message });
  }
});

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

// system prompt
function makeSystemPrompt(tfid, sessionId) {
  return {
    role: 'system',
    content:
`You are TF-Chat (Adam_D'H7). Each chat session is isolated.
User identifier: ${tfid}
Session id: ${sessionId}
Important instructions:
- Treat this session as independent. Do NOT reference or reveal messages from other sessions or users unless the user explicitly asks.
- If asked about previous sessions, ask for explicit permission or for the user to provide the content.
- Be concise and helpful.
`
  };
}

// Robust extractor: recursively collect text from any nested structure
function collectStrings(value) {
  if (value == null) return '';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (Array.isArray(value)) return value.map(v => collectStrings(v)).join('');
  if (typeof value === 'object') {
    let out = '';
    for (const k of Object.keys(value)) {
      out += collectStrings(value[k]);
    }
    return out;
  }
  return '';
}

function extractAssistantText(j) {
  if (!j) return null;

  // choices-based responses (typical)
  if (Array.isArray(j.choices) && j.choices.length) {
    const c = j.choices[0];

    // 1) direct message.content string
    if (c.message && typeof c.message.content === 'string' && c.message.content.trim()) {
      return c.message.content.trim();
    }

    // 2) message.content may be object/array -> collect strings
    if (c.message && c.message.content) {
      const s = collectStrings(c.message.content).trim();
      if (s) return s;
    }

    // 3) some responses use c.text
    if (typeof c.text === 'string' && c.text.trim()) return c.text.trim();

    // 4) some providers put pieces in different keys (e.g., content.parts)
    if (c.message && c.message.content && typeof c.message.content === 'object') {
      const s2 = collectStrings(c.message.content).trim();
      if (s2) return s2;
    }

    // 5) delta streaming objects sometimes appear - attempt to collect
    if (c.delta) {
      const s3 = collectStrings(c.delta).trim();
      if (s3) return s3;
    }

    // fallback: stringify choice (trim length)
    try {
      return JSON.stringify(c).slice(0, 2000);
    } catch (e) {
      return null;
    }
  }

  // older format: top-level text
  if (typeof j.text === 'string' && j.text.trim()) return j.text.trim();

  // try to collect any strings in the top-level response
  const fallback = collectStrings(j).trim();
  if (fallback) return fallback;

  return null;
}

// main endpoint
app.post('/message', async (req, res) => {
  try {
    const { tfid, sessionId, text } = req.body || {};
    if (!tfid || !sessionId || !text) return res.status(400).json({ error: 'tfid_session_text_required' });

    const users = await readJsonSafe(USERS_FILE, { users: [] });
    const user = users.users.find(u => u.tfid === tfid);
    if (!user) return res.status(404).json({ error: 'user_not_found' });

    const sessionsData = await readJsonSafe(SESSIONS_FILE, { sessions: {} });
    const session = sessionsData.sessions[sessionId];
    if (!session) return res.status(404).json({ error: 'session_not_found' });
    if (session.tfid !== tfid) return res.status(403).json({ error: 'session_belongs_to_other_user' });

    // append user message
    const userMsg = { role: 'user', content: text, ts: Date.now() };
    session.messages.push(userMsg);

    // build payload
    const sys = makeSystemPrompt(tfid, sessionId);
    const history = (session.messages || []).map(m => {
      if (m.role === 'user') return { role: 'user', content: m.content || m.text || '' };
      return { role: 'assistant', content: m.content || m.text || '' };
    });
    const tail = history.slice(-HISTORY_MESSAGE_LIMIT);
    const payloadMessages = [sys, ...tail];

    const bodyToSend = {
      model: 'openai/gpt-5',
      messages: payloadMessages,
      max_tokens: DEFAULT_MAX_TOKENS,
      temperature: DEFAULT_TEMPERATURE
    };

    console.log('[proxy] session', sessionId, 'tfid', tfid, '| messages', payloadMessages.length);

    const resp = await fetch('https://openrouter.ai/api/v1/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + OPENROUTER_API_KEY },
      body: JSON.stringify(bodyToSend)
    });

    const textResp = await resp.text();
    let parsed = null;
    try { parsed = JSON.parse(textResp); } catch (e) { parsed = null; }

    if (!resp.ok) {
      console.warn('OpenRouter returned not ok', resp.status, textResp.slice(0, 1000));
      return res.status(resp.status).json({ error: 'openrouter_error', details: textResp });
    }

    // robust extraction
    const assistantText = extractAssistantText(parsed) || '(Repons pa klè)';

    // if we still didn't get anything meaningful, log some debug for developers
    if (assistantText === '(Repons pa klè)') {
      console.warn('extractAssistantText failed to find text. Parsed response keys:', Object.keys(parsed || {}));
      try {
        // write a short debug snippet to console (not to disk) to help debugging
        console.warn('Parsed snippet:', JSON.stringify(parsed).slice(0, 2000));
      } catch (e) { /* ignore */ }
    }

    const assistantMsg = { role: 'assistant', content: assistantText, ts: Date.now() };
    session.messages.push(assistantMsg);

    await writeJsonSafe(SESSIONS_FILE, sessionsData);

    res.json({ assistant: assistantText, raw: parsed });
  } catch (err) {
    console.error('/message error', err);
    res.status(500).json({ error: 'server_error', details: err.message });
  }
});

// compatibility proxy if you need it
app.post('/openrouter', async (req, res) => {
  try {
    const bodyToSend = {
      model: req.body.model || 'openai/gpt-5',
      messages: req.body.messages || [],
      max_tokens: typeof req.body.max_tokens === 'number' ? req.body.max_tokens : DEFAULT_MAX_TOKENS,
      temperature: typeof req.body.temperature === 'number' ? req.body.temperature : DEFAULT_TEMPERATURE
    };

    const resp = await fetch('https://openrouter.ai/api/v1/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + OPENROUTER_API_KEY },
      body: JSON.stringify(bodyToSend)
    });

    const text = await resp.text();
    try {
      const j = JSON.parse(text);
      res.status(resp.status).json(j);
    } catch (e) {
      res.status(resp.status).type('text').send(text);
    }
  } catch (err) {
    console.error('/openrouter proxy error', err);
    res.status(500).json({ error: 'proxy_failed', details: String(err) });
  }
});

// diag & health
app.get('/diag', async (req, res) => {
  try {
    const r = await fetch('https://openrouter.ai/');
    const snippet = await r.text().catch(() => '');
    res.json({ ok: !!r, status: r.status, snippet: snippet.slice(0, 400) });
  } catch (err) {
    res.status(500).json({ ok: false, error: String(err) });
  }
});

app.get('/health', (req, res) => res.json({ ok: true }));

process.on('unhandledRejection', (r) => console.error('unhandledRejection', r));
process.on('uncaughtException', (err) => {
  console.error('uncaughtException', err);
  process.exit(1);
});

app.listen(PORT, () => {
  console.log(`Proxy serveur: http://localhost:${PORT}`);
  console.log('Serving static files from ./public');
});
