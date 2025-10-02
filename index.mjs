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

/* Config */
const PORT = Number(process.env.PORT) || 3000;
const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY;
const OPENROUTER_ENDPOINT = process.env.OPENROUTER_ENDPOINT || 'https://openrouter.ai/api/v1/chat/completions';
const OPENROUTER_MODEL = process.env.OPENROUTER_MODEL || 'gpt-5';

const raw = process.env.HISTORY_TAIL;
let HISTORY_TAIL = (raw !== undefined && raw !== '') ? Number(raw) : 77;
if (!Number.isFinite(HISTORY_TAIL)) HISTORY_TAIL = 77;
// Prevent using Infinity for slice(-HISTORY_TAIL)
if (HISTORY_TAIL <= 0) HISTORY_TAIL = 77;

const DEFAULT_MAX_TOKENS = Number(process.env.DEFAULT_MAX_TOKENS) || 1000;
const MAX_ALLOWED_TOKENS = Number(process.env.MAX_ALLOWED_TOKENS) || 1000;
const MAX_CONTEXT_TOKENS = Number(process.env.MAX_CONTEXT_TOKENS) || 2048;
const DEFAULT_TIMEOUT_MS = Number(process.env.DEFAULT_TIMEOUT_MS) || 120000;
const MAX_RETRIES = Number(process.env.MAX_RETRIES) || 5;
const MAX_CONTINUATIONS = Number(process.env.MAX_CONTINUATIONS) || 6;
const DEFAULT_USER_NAME = process.env.DEFAULT_USER_NAME || 'User';

const CHARS_PER_TOKEN_SAFE = 3.5;
const TF_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz123456789';
const USERS_FILE = path.join(__dirname, 'user.json');
const SESSIONS_FILE = path.join(__dirname, 'sessions.json');
const USER_HISTORY_FILE = path.join(__dirname, 'user_history.json');

if (!OPENROUTER_API_KEY) {
  console.error('ERROR: OPENROUTER_API_KEY missing in .env — set OPENROUTER_API_KEY and restart.');
  process.exit(1);
}

/* Middlewares */
app.use(cors({ origin: true }));
app.use(express.json({ limit: '1000mb' }));
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

// Simple request logger (dev)
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl} body:`, req.body || {});
  next();
});

/* JSON helpers */
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

/* TFID */
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

/* Marker helpers */
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

/* Token/char estimation */
function estimateTokensFromString(s) {
  if (!s) return 0;
  return Math.ceil(s.length / CHARS_PER_TOKEN_SAFE);
}
function estimateTokensFromMessagesArray(arr) {
  let total = 0;
  for (const m of arr) {
    total += estimateTokensFromString(String(m.content || ''));
    total += 3;
  }
  return total;
}

/* Robust extractor */
function findFirstStringInObject(obj) {
  if (obj == null) return null;
  if (typeof obj === 'string' && obj.trim()) return obj.trim();
  if (Array.isArray(obj)) {
    for (const it of obj) {
      const s = findFirstStringInObject(it);
      if (s) return s;
    }
    return null;
  }
  if (typeof obj === 'object') {
    const tryKeys = ['content', 'text', 'message', 'output_text', 'response', 'result', 'parts'];
    for (const k of tryKeys) {
      if (obj[k] !== undefined) {
        const s = findFirstStringInObject(obj[k]);
        if (s) return s;
      }
    }
    for (const k of Object.keys(obj)) {
      const s = findFirstStringInObject(obj[k]);
      if (s) return s;
    }
  }
  return null;
}
function extractAssistantText(payloadJson) {
  if (!payloadJson) return null;
  try {
    if (Array.isArray(payloadJson.choices) && payloadJson.choices.length) {
      const c = payloadJson.choices[0];
      const mc = c?.message?.content;
      if (typeof mc === 'string' && mc.trim()) return mc.trim();
      const fromMc = findFirstStringInObject(mc);
      if (fromMc) return fromMc;
      if (typeof c.text === 'string' && c.text.trim()) return c.text.trim();
      if (c?.delta) {
        const d = c.delta.content ?? c.delta;
        const s = findFirstStringInObject(d);
        if (s) return s;
      }
      if (Array.isArray(c?.message?.reasoning_details)) {
        for (const it of c.message.reasoning_details) {
          if (!it) continue;
          if (it.type && String(it.type).toLowerCase().includes('encrypted')) continue;
          if (typeof it.summary === 'string' && it.summary.trim()) return it.summary.trim();
          const fromIt = findFirstStringInObject(it);
          if (fromIt) return fromIt;
        }
      }
    }
    for (const k of ['response','output','result','text','output_text']) {
      if (typeof payloadJson[k] === 'string' && payloadJson[k].trim()) return payloadJson[k].trim();
      const candidate = findFirstStringInObject(payloadJson[k]);
      if (candidate) return candidate;
    }
  } catch (e) {
    console.error('extractAssistantText error', e);
  }
  return null;
}

/* sleep helper */
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/* fetchWithTimeout (robust) */
async function fetchWithTimeout(url, options = {}, timeoutMs = DEFAULT_TIMEOUT_MS) {
  const controller = new AbortController();
  const id = setTimeout(() => {
    try { controller.abort(); } catch (e) {}
  }, timeoutMs);
  try {
    const r = await fetch(url, { ...options, signal: controller.signal });
    const txt = await r.text();
    let parsed = null;
    try { parsed = JSON.parse(txt); } catch (e) { parsed = null; }
    return { ok: r.ok, status: r.status, text: txt, json: parsed, fetchError: null };
  } catch (err) {
    const normalized = err instanceof Error ? err : new Error(String(err));
    return { ok: false, fetchError: normalized, status: 502, text: String(normalized) };
  } finally {
    clearTimeout(id);
  }
}

/* Init storage files */
await readJsonSafe(USERS_FILE, { users: [] });
await readJsonSafe(SESSIONS_FILE, { sessions: {} });
await readJsonSafe(USER_HISTORY_FILE, { histories: {} });

/* System prompt builder */
function makeSystemPrompt(tfid, sessionId, userName = null) {
  const identity = "You are Adam_D'H7 everyone's friend created by D'H7 | Tergene. born on July 17, 2009, you are a Haitian This information about you will only be given when requested.";
  const instructions = [
    'Respond in the same language the user used.',
    'When you include content the user may want to copy exactly (code, commands, snippets, or any text to copy), surround that exact content with triple backticks, for example: ```this is copyable```',
    'Do NOT place commentary inside the triple backticks — only the exact content to copy should be between the backticks.',
    `At the end of your full reply, include a single line with exactly ${MARKER} (three asterisks + Terminé + three asterisks), and after that line provide a concise final visible response for the user. The server will display the portion after ${MARKER}. If you already include ${MARKER}, do not duplicate it.`,
    'Keep the reply concise and avoid revealing internal chain-of-thought or reasoning steps. If asked for code or copyable outputs, prefer triple-backtick blocks as explained above.'
  ];
  const lines = [identity, `Session: ${sessionId}`, ...instructions];
  return { role: 'system', content: lines.join(' ') };
}

/* Helper: format a session for client consumption */
function formatSessionForClient(sessionObj) {
  if (!sessionObj) return null;
  const out = {
    id: sessionObj.sessionId || sessionObj.id || null,
    title: sessionObj.title || (sessionObj.messages && sessionObj.messages.length ? (String(sessionObj.messages[0].content || '').slice(0, 100)) : 'Chat'),
    createdAt: sessionObj.createdAt || null,
    messages: (sessionObj.messages || []).map(m => {
      const sender = (m.role === 'user') ? 'user' : (m.role === 'assistant' ? 'bot' : (m.role || 'bot'));
      return { sender, text: m.content || '', ts: m.ts || m.timestamp || null };
    })
  };
  return out;
}

/* Routes */

/**
 * POST /user
 */
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

/**
 * POST /session
 * returns client-friendly session AND sessionId field for compatibility
 */
app.post('/session', async (req, res) => {
  try {
    const { tfid, title } = req.body || {};
    if (!tfid) return res.status(400).json({ error: 'tfid_required' });
    const usersObj = await readJsonSafe(USERS_FILE, { users: [] });
    const found = (usersObj.users || []).find(u => u.tfid === tfid);
    if (!found) return res.status(404).json({ error: 'user_not_found' });
    const sessionsData = await readJsonSafe(SESSIONS_FILE, { sessions: {} });
    sessionsData.sessions = sessionsData.sessions || {};
    const sessionId = crypto.randomUUID();
    const session = { sessionId, tfid, title: title || 'Nouveau Chat', createdAt: new Date().toISOString(), messages: [] };
    sessionsData.sessions[sessionId] = session;
    await writeJsonSafe(SESSIONS_FILE, sessionsData);
    // return the session in client-friendly shape AND include sessionId
    const clientShape = formatSessionForClient(session);
    return res.json({ sessionId, ...clientShape });
  } catch (err) {
    console.error('/session error', err);
    return res.status(500).json({ error: 'server_error', details: String(err?.message || err) });
  }
});

/**
 * GET /sessions
 */
app.get('/sessions', async (req, res) => {
  try {
    const tfid = req.query.tfid;
    const sessionsData = await readJsonSafe(SESSIONS_FILE, { sessions: {} });
    const all = sessionsData.sessions || {};
    const arr = Object.keys(all).map(k => all[k]);
    const filtered = tfid ? arr.filter(s => s.tfid === tfid) : arr;
    const out = filtered.map(formatSessionForClient);
    return res.json(out);
  } catch (err) {
    console.error('/sessions error', err);
    return res.status(500).json({ error: String(err?.message || err) });
  }
});

/**
 * GET /history/:tfid/:n?
 */
app.get('/history/:tfid/:n?', async (req, res) => {
  try {
    const tfid = req.params.tfid;
    const n = Math.max(1, Math.min(1000, Number(req.params.n || 100)));
    const hist = await readJsonSafe(USER_HISTORY_FILE, { histories: {} });
    const arr = (hist.histories && hist.histories[tfid]) ? hist.histories[tfid] : [];
    return res.json(arr.slice(-n));
  } catch (err) {
    console.error('/history error', err);
    return res.status(500).json({ error: String(err?.message || err) });
  }
});

/**
 * Core handler logic extracted to a reusable function
 */
async function handleMessage(req, res) {
  try {
    const { tfid, sessionId } = req.body || {};
    let text = req.body?.text;
    if (!tfid || !sessionId || typeof text !== 'string' || !text.trim()) {
      return res.status(400).json({ error: 'tfid_session_text_required' });
    }
    const clean = String(text).trim();

    const users = await readJsonSafe(USERS_FILE, { users: [] });
    const user = (users.users || []).find(u => u.tfid === tfid);
    if (!user) return res.status(404).json({ error: 'user_not_found' });

    const sessionsData = await readJsonSafe(SESSIONS_FILE, { sessions: {} });
    sessionsData.sessions = sessionsData.sessions || {};
    const session = sessionsData.sessions[sessionId];
    if (!session) return res.status(404).json({ error: 'session_not_found' });
    if (session.tfid !== tfid) return res.status(403).json({ error: 'session_belongs_to_other_user' });

    session.messages = session.messages || [];
    session.messages.push({ role: 'user', content: clean, ts: Date.now() });

    const hist = await readJsonSafe(USER_HISTORY_FILE, { histories: {} });
    hist.histories = hist.histories || {};
    hist.histories[tfid] = hist.histories[tfid] || [];
    hist.histories[tfid].push({ role: 'user', content: clean, sessionId, ts: Date.now() });

    await writeJsonSafe(SESSIONS_FILE, sessionsData);
    await writeJsonSafe(USER_HISTORY_FILE, hist);

    const systemMsg = makeSystemPrompt(tfid, sessionId, user.name || DEFAULT_USER_NAME);
    let tail = (session.messages || []).slice(-HISTORY_TAIL).map(m => ({ role: m.role, content: m.content || '' }));

    function estimatePromptTokens(systemObj, tailArr, finalUserContent) {
      let tokens = estimateTokensFromString(systemObj.content);
      tokens += estimateTokensFromMessagesArray(tailArr);
      tokens += estimateTokensFromString(finalUserContent) + 3;
      return tokens;
    }

    let promptTokens = estimatePromptTokens(systemMsg, tail, clean);
    while (tail.length > 0 && (promptTokens + DEFAULT_MAX_TOKENS > MAX_CONTEXT_TOKENS)) {
      tail.shift();
      promptTokens = estimatePromptTokens(systemMsg, tail, clean);
    }

    if (promptTokens + DEFAULT_MAX_TOKENS > MAX_CONTEXT_TOKENS) {
      console.warn('Prompt still large after trimming; provider may truncate. Estimated prompt tokens:', promptTokens);
    } else {
      console.log('Prompt tokens after trimming:', promptTokens, ' Response tokens cap:', DEFAULT_MAX_TOKENS);
    }

    function abbreviateMessages(arr, maxChars = 400) {
      return arr.map(m => {
        if (!m || !m.content) return { role: m.role, content: '' };
        let c = String(m.content);
        if (c.length <= maxChars) return { role: m.role, content: c };
        const head = c.slice(0, Math.floor(maxChars * 0.6));
        const tailPiece = c.slice(-Math.floor(maxChars * 0.3));
        return { role: m.role, content: head + '\n…\n' + tailPiece };
      });
    }

    let abbreviatedTail = abbreviateMessages(tail, 400);
    let messagesForProvider = [systemMsg, ...abbreviatedTail, { role: 'user', content: clean }];

    let attempt = 0;
    let currentMax = DEFAULT_MAX_TOKENS;
    let lastResp = null;
    let accumulated = '';
    let continuations = 0;
    let assistantText = null;

    // backoff params
    let backoffMs = 1000;
    const BACKOFF_MULT = 2;
    const MAX_BACKOFF_MS = 16000;
    const EXTRA_TIMEOUT_PER_ATTEMPT = 2000;

    while (attempt < MAX_RETRIES) {
      attempt++;
      const attemptTimeout = DEFAULT_TIMEOUT_MS + (attempt - 1) * EXTRA_TIMEOUT_PER_ATTEMPT;
      const payload = {
        model: OPENROUTER_MODEL,
        messages: messagesForProvider,
        max_tokens: currentMax,
        max_output_tokens: currentMax,
        temperature: 0.2
      };

      lastResp = await fetchWithTimeout(OPENROUTER_ENDPOINT, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + OPENROUTER_API_KEY
        },
        body: JSON.stringify(payload)
      }, attemptTimeout);

      if (!lastResp.ok && lastResp.fetchError) {
        console.warn(`Provider network error (attempt ${attempt}):`, lastResp.fetchError);
        if (attempt < MAX_RETRIES) {
          await sleep(backoffMs);
          backoffMs = Math.min(MAX_BACKOFF_MS, Math.floor(backoffMs * BACKOFF_MULT));
          continue;
        } else {
          break;
        }
      }

      if (!lastResp.ok) {
        console.warn(`Provider returned status ${lastResp.status} (attempt ${attempt}).`);
        if ([502, 503, 504].includes(lastResp.status) && attempt < MAX_RETRIES) {
          await sleep(backoffMs);
          backoffMs = Math.min(MAX_BACKOFF_MS, Math.floor(backoffMs * BACKOFF_MULT));
          continue;
        }
        break;
      }

      const part = extractAssistantText(lastResp.json) || (lastResp.text && lastResp.text.trim()) || null;
      if (part) accumulated = accumulated ? (accumulated + '\n' + part) : part;

      const maybeChoice = lastResp.json?.choices?.[0];
      const finishReason = maybeChoice?.finish_reason || maybeChoice?.native_finish_reason || null;

      if (finishReason !== 'length' && finishReason !== 'max_output_tokens') {
        assistantText = accumulated || null;
        break;
      }

      console.warn(`Model truncated (finish_reason=${finishReason}) on attempt ${attempt}.`);

      const prev = currentMax;
      currentMax = Math.min(MAX_ALLOWED_TOKENS, Math.max(currentMax + 32, Math.floor(currentMax * 1.5)));
      if (currentMax !== prev && currentMax <= MAX_ALLOWED_TOKENS) {
        console.warn(`Increasing max tokens ${prev} -> ${currentMax} and retrying.`);
        await sleep(200);
        continue;
      }

      if (accumulated && continuations < MAX_CONTINUATIONS) {
        continuations++;
        messagesForProvider = [
          systemMsg,
          ...abbreviateMessages(tail, 300),
          { role: 'assistant', content: accumulated },
          { role: 'user', content: 'Continue la réponse précédente.' }
        ];
        console.warn(`Issuing continuation #${continuations} to fetch remaining content.`);
        continue;
      } else {
        console.warn('No more continuation attempts allowed or nothing accumulated. Breaking.');
        assistantText = accumulated || null;
        break;
      }
    }

    if (assistantText) {
      const wrapped = ensureMarkerBefore(assistantText);
      session.messages.push({ role: 'assistant', content: wrapped, ts: Date.now() });
      hist.histories[tfid].push({ role: 'assistant', content: wrapped, sessionId, ts: Date.now() });
      await writeJsonSafe(SESSIONS_FILE, sessionsData);
      await writeJsonSafe(USER_HISTORY_FILE, hist);
      const visible = extractVisibleFromWrapped(wrapped);
      return res.json({ assistant: visible, session: formatSessionForClient(session) });
    }

    console.error('No assistant text extracted after retries/continuations.');
    if (lastResp) {
      console.error('Provider lastResp status:', lastResp.status);
      if (lastResp.fetchError) console.error('Provider fetchError:', lastResp.fetchError);
      if (lastResp.text && lastResp.text.trim()) {
        const statusToSend = Number.isInteger(lastResp.status) ? lastResp.status : 502;
        return res.status(statusToSend).type('text').send(lastResp.text);
      }
    }

    return res.status(502).json({ error: 'no_response_from_provider' });
  } catch (err) {
    console.error('/message error', err);
    return res.status(500).json({ error: 'server_error', details: String(err?.message || err) });
  }
}

/**
 * POST /message (main)
 */
app.post('/message', handleMessage);

/**
 * POST /api/chat -> alias (compatibility)
 * Accepts { prompt } or { text } and forwards
 */
app.post('/api/chat', async (req, res) => {
  // Normalize older shape: prompt -> text
  if (req.body && req.body.prompt && !req.body.text) req.body.text = req.body.prompt;
  return handleMessage(req, res);
});

app.get('/health', (req, res) => res.json({ ok: true }));

// Print routes (dev-friendly)
if (app && app._router && app._router.stack) {
  console.log('Exposed routes:');
  app._router.stack.forEach(m => {
    if (m.route && m.route.path) {
      const methods = Object.keys(m.route.methods).join(',').toUpperCase();
      console.log(methods, m.route.path);
    }
  });
}

app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT} (HISTORY_TAIL=${HISTORY_TAIL}, RESPONSE_MAX_TOKENS=${DEFAULT_MAX_TOKENS})`);
});
