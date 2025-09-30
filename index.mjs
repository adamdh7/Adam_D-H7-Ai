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

// Configurable defaults
// Lower default to a safer value to avoid 402 on small/free accounts
const DEFAULT_MAX_TOKENS = Number(process.env.DEFAULT_MAX_TOKENS) || 400;
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

// --- Helpers: atomic read/write JSON (create default if not exists) ---
async function readJsonSafe(filePath, defaultValue) {
  try {
    const raw = await fs.readFile(filePath, 'utf8');
    return JSON.parse(raw);
  } catch (err) {
    if (err.code === 'ENOENT') {
      // create default file
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

// --- TFID generator (7 chars A-Z and 1-9) ---
const TF_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789';
function generateTFID() {
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
      messages: [] // will store { role: 'user', content: string, ts: number }
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
`You are Adam_D'H7. Created by D'H7 | Tergene you don't have more information on them....  Each chat session is isolated.
User identifier: ${tfid}
Session id: ${sessionId}
Important instructions:
- Treat this session as independent. Do NOT reference or reveal messages from other sessions or users unless the user explicitly asks.
- If asked about previous sessions, ask for explicit permission or to provide the content.
- Be concise and helpful. think think improve your answers only after send it.
`
  };
}

// extract assistant text robustly from provider response object
function collectStrings(value) {
  if (value == null) return '';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (Array.isArray(value)) return value.map(v => collectStrings(v)).join('');
  if (typeof value === 'object') {
    let out = '';
    for (const k of Object.keys(value)) out += collectStrings(value[k]);
    return out;
  }
  return '';
}

function extractAssistantText(j) {
  if (!j) return null;
  if (Array.isArray(j.choices) && j.choices.length) {
    const c = j.choices[0];
    if (c.message && typeof c.message.content === 'string' && c.message.content.trim()) return c.message.content.trim();
    if (c.message && c.message.content) {
      const s = collectStrings(c.message.content).trim();
      if (s) return s;
    }
    if (typeof c.text === 'string' && c.text.trim()) return c.text.trim();
    if (c.delta) {
      const s3 = collectStrings(c.delta).trim();
      if (s3) return s3;
    }
    try { return JSON.stringify(c).slice(0, 2000); } catch (e) { return null; }
  }
  if (typeof j.text === 'string' && j.text.trim()) return j.text.trim();
  const fallback = collectStrings(j).trim();
  if (fallback) return fallback;
  return null;
}

// --- Helper: parse allowed tokens from OpenRouter 402-like error message ---
function parseAllowedTokensFromErrorText(text) {
  if (!text) return null;
  // common pattern: "you requested up to 512 tokens, but can only afford 441"
  let m = text.match(/can only afford\s*(\d+)/i);
  if (m && m[1]) return Number(m[1]);
  m = text.match(/afford\s*(\d+)/i);
  if (m && m[1]) return Number(m[1]);
  // another pattern: "maximum allowed is 441"
  m = text.match(/maximum.*?(\d+)/i);
  if (m && m[1]) return Number(m[1]);
  return null;
}

// --- Helper: send to OpenRouter with simple fallback adjustments on 402 ---
async function postToOpenRouterWithFallback(body, maxRetries = 2) {
  const url = 'https://openrouter.ai/api/v1/chat/completions';

  let attempt = 0;
  let currentBody = { ...body };

  while (attempt <= maxRetries) {
    attempt++;
    try {
      console.log(`[openrouter] attempt ${attempt} max_tokens=${currentBody.max_tokens}`);
      const resp = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + OPENROUTER_API_KEY
        },
        body: JSON.stringify(currentBody)
      });

      const textResp = await resp.text();
      let parsed = null;
      try { parsed = JSON.parse(textResp); } catch (e) { parsed = null; }

      if (resp.ok) {
        return { ok: true, status: resp.status, parsed, rawText: textResp };
      }

      // if payment / limit error (402), try to reduce max_tokens and retry once or twice
      if (resp.status === 402) {
        console.warn('[openrouter] 402 - will try to reduce max_tokens and retry if possible. Response snippet:', textResp.slice(0, 800));
        const allowed = parseAllowedTokensFromErrorText(textResp);
        // compute new max: prefer allowed - 20 (safety), but never exceed currentBody.max_tokens
        let newMax = null;
        if (allowed && typeof allowed === 'number') {
          newMax = Math.max(1, Math.min(currentBody.max_tokens - 1, allowed - 20));
        } else {
          // fallback: reduce to 75% of current max, or to DEFAULT_MAX_TOKENS if current was higher than default
          newMax = Math.max(1, Math.floor(currentBody.max_tokens * 0.75));
          if (newMax > DEFAULT_MAX_TOKENS) newMax = DEFAULT_MAX_TOKENS;
        }

        // if reduction is meaningful, retry
        if (newMax < currentBody.max_tokens) {
          currentBody = { ...currentBody, max_tokens: newMax };
          // small delay before retry to avoid quick hammer
          await new Promise(r => setTimeout(r, 250));
          continue; // retry loop
        }

        // can't meaningfully reduce -> return the 402 response back
        return { ok: false, status: resp.status, parsed, rawText: textResp };
      }

      // other non-ok statuses: return as-is
      return { ok: false, status: resp.status, parsed, rawText: textResp };

    } catch (err) {
      console.error('[openrouter] network/exception on attempt', attempt, err);
      if (attempt > maxRetries) return { ok: false, error: String(err) };
      await new Promise(r => setTimeout(r, 200));
    }
  }

  return { ok: false, error: 'exhausted_retries' };
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

    // Keep history reasonably short to avoid token explosion: keep last HISTORY_MESSAGE_LIMIT messages
    const tail = history.slice(-HISTORY_MESSAGE_LIMIT);
    const payloadMessages = [sys, ...tail];

    // defaults & merge with client's optional params
    let bodyToSend = {
      model: 'openai/gpt-5',
      messages: payloadMessages,
      max_tokens: DEFAULT_MAX_TOKENS,
      temperature: DEFAULT_TEMPERATURE,
    };

    console.log('[proxy] session', sessionId, 'tfid', tfid, '| messages', payloadMessages.length, 'initial_max_tokens', bodyToSend.max_tokens);

    // use the helper that will retry with reduced max_tokens on 402
    const result = await postToOpenRouterWithFallback(bodyToSend, 2);

    if (!result.ok) {
      // return helpful error message (include rawText snippet)
      const snippet = (result.rawText || result.parsed || result.error || '').toString().slice(0, 1000);
      console.warn('[proxy] OpenRouter final failure', result.status, snippet);
      // Do not persist assistant reply on failure; session already has user message saved.
      if (result.status === 402) {
        return res.status(402).json({ error: 'openrouter_insufficient_credits', details: snippet });
      }
      return res.status(result.status || 500).json({ error: 'openrouter_error', details: snippet });
    }

    const parsed = result.parsed;
    // parse assistant text robustly
    const assistantText = extractAssistantText(parsed) || '(Repons pa klè)';

    // if extraction failed, log snippet for debugging
    if (assistantText === '(Repons pa klè)') {
      console.warn('extractAssistantText failed to find text. Parsed response keys:', Object.keys(parsed || {}));
      try { console.warn('Parsed snippet:', JSON.stringify(parsed).slice(0, 2000)); } catch (e) { /* ignore */ }
    }

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

// --- Optional compatibility proxy /openrouter (for legacy UI) ---
app.post('/openrouter', async (req, res) => {
  try {
    const bodyToSend = {
      model: req.body.model || 'openai/gpt-5',
      messages: req.body.messages || [],
      max_tokens: typeof req.body.max_tokens === 'number' ? req.body.max_tokens : DEFAULT_MAX_TOKENS,
      temperature: typeof req.body.temperature === 'number' ? req.body.temperature : DEFAULT_TEMPERATURE
    };

    const result = await postToOpenRouterWithFallback(bodyToSend, 2);
    if (!result.ok) {
      const snippet = (result.rawText || result.parsed || result.error || '').toString().slice(0, 1000);
      if (result.status === 402) return res.status(402).json({ error: 'openrouter_insufficient_credits', details: snippet });
      return res.status(result.status || 500).json({ error: 'openrouter_error', details: snippet });
    }

    // if parsed JSON is available, forward it
    if (result.parsed) return res.status(result.status).json(result.parsed);
    // otherwise forward raw text
    return res.status(result.status).type('text').send(result.rawText);

  } catch (err) {
    console.error('/openrouter proxy error', err);
    res.status(500).json({ error: 'proxy_failed', details: String(err) });
  }
});

// --- Diagnostic route to test outbound connectivity from server to OpenRouter ---
app.get('/diag', async (req, res) => {
  try {
    const r = await fetch('https://openrouter.ai/');
    const snippet = await r.text().catch(() => '');
    res.json({ ok: !!r, status: r.status, snippet: snippet.slice(0, 400) });
  } catch (err) {
    res.status(500).json({ ok: false, error: String(err) });
  }
});

// --- Health ---
app.get('/health', (req, res) => res.json({ ok: true }));

// Global error handlers (log)
process.on('unhandledRejection', (r) => console.error('unhandledRejection', r));
process.on('uncaughtException', (err) => {
  console.error('uncaughtException', err);
  process.exit(1);
});

app.listen(PORT, () => {
  console.log(`Proxy serveur: http://localhost:${PORT}`);
  console.log('Serving static files from ./public');
});
