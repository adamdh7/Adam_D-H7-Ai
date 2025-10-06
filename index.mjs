import express from 'express';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import { promises as fs } from 'fs';
import fsSync from 'fs';
import crypto from 'crypto';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

/* Config */
const PORT = Number(process.env.PORT) || 3000;

/* Google-only config */
const GOOGLE_API_KEY = process.env.GOOGLE_API_KEY || '';
const GOOGLE_BASE = process.env.GOOGLE_BASE || 'https://generativelanguage.googleapis.com';
const GOOGLE_MODEL = process.env.GOOGLE_MODEL || 'gemini-2.0-flash';

if (!GOOGLE_API_KEY) {
  console.error('ERROR: GOOGLE_API_KEY missing in .env — set GOOGLE_API_KEY and restart.');
  process.exit(1);
}

/* Other config */
const raw = process.env.HISTORY_TAIL;
let HISTORY_TAIL = (raw !== undefined && raw !== '') ? Number(raw) : 777;
if (!Number.isFinite(HISTORY_TAIL)) HISTORY_TAIL = 777;
if (HISTORY_TAIL <= 0) HISTORY_TAIL = 777;

const DEFAULT_MAX_TOKENS = Number(process.env.DEFAULT_MAX_TOKENS) || 1024;
const MAX_ALLOWED_TOKENS = Number(process.env.MAX_ALLOWED_TOKENS) || 1024;
const MAX_CONTEXT_TOKENS = Number(process.env.MAX_CONTEXT_TOKENS) || 8192;
const DEFAULT_TIMEOUT_MS = Number(process.env.DEFAULT_TIMEOUT_MS) || 120000;
const MAX_RETRIES = Number(process.env.MAX_RETRIES) || 5;
const MAX_CONTINUATIONS = Number(process.env.MAX_CONTINUATIONS) || 6;
const DEFAULT_USER_NAME = process.env.DEFAULT_USER_NAME || 'User';

const CHARS_PER_TOKEN_SAFE = 3.5;
const TF_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz123456789';
const USERS_FILE = path.join(__dirname, 'user.json');
const SESSIONS_FILE = path.join(__dirname, 'sessions.json');
const USER_HISTORY_FILE = path.join(__dirname, 'user_history.json');

/* Logging setup */
const LOG_FILE = path.join(__dirname, 'server.log');
function appendLogLine(line) {
  try {
    fsSync.appendFileSync(LOG_FILE, line + '\n');
  } catch (e) {
    console.error('Failed to write log file:', e?.message || e);
  }
}
function makeLogLine(level, requestId, tfid, sessionId, msg) {
  const ts = new Date().toISOString();
  const parts = [`${ts}`, level.toUpperCase(), `req=${requestId || '-'}`];
  if (tfid) parts.push(`tfid=${tfid}`);
  if (sessionId) parts.push(`sid=${sessionId}`);
  parts.push('-', typeof msg === 'string' ? msg : JSON.stringify(msg));
  return parts.join(' ');
}
const logger = {
  info: (requestId, tfid, sessionId, msg) => {
    const line = makeLogLine('info', requestId, tfid, sessionId, msg);
    console.log(line);
    appendLogLine(line);
  },
  warn: (requestId, tfid, sessionId, msg) => {
    const line = makeLogLine('warn', requestId, tfid, sessionId, msg);
    console.warn(line);
    appendLogLine(line);
  },
  error: (requestId, tfid, sessionId, msg) => {
    const line = makeLogLine('error', requestId, tfid, sessionId, msg);
    console.error(line);
    appendLogLine(line);
  }
};

app.use(cors({ origin: true }));
app.use(express.json({ limit: '1000mb' }));
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

/* Request-ID middleware */
app.use((req, res, next) => {
  const rid = req.headers['x-request-id'] || crypto.randomUUID();
  req.requestId = rid;
  res.setHeader('X-Request-ID', rid);
  next();
});

/* Access log middleware (uses logger) */
app.use((req, res, next) => {
  const shortBody = req.body && Object.keys(req.body).length ? '<body>' : '{}';
  logger.info(req.requestId, null, null, `${req.method} ${req.originalUrl} body: ${shortBody}`);
  const start = Date.now();
  res.once('finish', () => {
    const dur = Date.now() - start;
    logger.info(req.requestId, null, null, `→ ${res.statusCode} ${req.method} ${req.originalUrl} (${dur}ms)`);
  });
  next();
});

/* Helpers: read/write safe */
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
  if (!t) return '';
  if (t.includes(MARKER)) return t;
  return `${t}\n\n${MARKER}`;
}
function extractVisibleFromWrapped(wrapped) {
  if (!wrapped || typeof wrapped !== 'string') return '';
  const idx = wrapped.lastIndexOf(MARKER);
  if (idx === -1) return wrapped.trim();
  return wrapped.slice(0, idx).trim();
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
    const tryKeys = ['content', 'text', 'message', 'output_text', 'response', 'result', 'parts', 'candidates', 'output'];
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
    if (Array.isArray(payloadJson.candidates) && payloadJson.candidates.length) {
      const cand = payloadJson.candidates[0];
      const txt = findFirstStringInObject(cand);
      if (txt) return txt;
    }
    // fallback: top-level fields
    for (const k of ['response','output','result','text','output_text','candidates']) {
      if (typeof payloadJson[k] === 'string' && payloadJson[k].trim()) return payloadJson[k].trim();
      const candidate = findFirstStringInObject(payloadJson[k]);
      if (candidate) return candidate;
    }
  } catch (e) {
    logger.error(null, null, null, `extractAssistantText error: ${String(e)}`);
  }
  return null;
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/* fetchWithTimeout: returns relevant headers (Retry-After) */
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

    // capture relevant headers
    const headers = {};
    try {
      const ra = r.headers.get('retry-after');
      if (ra) headers['retry-after'] = ra;
    } catch (e) {}

    return { ok: r.ok, status: r.status, text: txt, json: parsed, fetchError: null, headers };
  } catch (err) {
    const normalized = err instanceof Error ? err : new Error(String(err));
    return { ok: false, fetchError: normalized, status: 502, text: String(normalized), headers: {} };
  } finally {
    clearTimeout(id);
  }
}

/* Init storage files */
await readJsonSafe(USERS_FILE, { users: [] });
await readJsonSafe(SESSIONS_FILE, { sessions: {} });
await readJsonSafe(USER_HISTORY_FILE, { histories: {} });

/* Copy-marker helpers */
function normalizeCopyMarkers(text) {
  if (!text || typeof text !== 'string') return text;
  return text.replace(/§\s*([\s\S]*?)\s*§/g, '§$1§');
}
function renderCopyableMarkersToMarkdown(text) {
  if (!text || typeof text !== 'string') return text;
  const normalized = normalizeCopyMarkers(text);
  return normalized.replace(/§([\s\S]*?)§/g, (m, p1) => {
    const inner = String(p1).replace(/^\n+|\n+$/g, '');
    return '```' + inner + '```';
  });
}

/* System prompt builder */
function makeSystemPrompt(tfid, sessionId, userName = null) {
  const identity = "You are Adam_D'H7 everyone's friend created by D'H7 | Tergene. born on July 17, 2009, you are a Haitian This information about you will only be given when requested.";
  const instructions = [
    'Respond in the same language the user used.',
    'note well you were created by D\'H7 | Tergene you model v1 so Adam_D\'H7 V1, you were trained by D\'H7 | Tergene and configured by them, This information about you will only be given when requested.',
    'When you include content the user may want to copy exactly (code, commands, snippets, texts, or any text to copy), surround that exact content with the § character at the start and end, for example: §this is copyable§. Do NOT place commentary inside the § markers — only the exact content to copy should be between them.',
    `At the end of your full reply, include a single line with exactly ${MARKER}. Anything after that line will be hidden by the server; the server will display only the text before ${MARKER}. If you already include ${MARKER}, do not duplicate it.`,
    'Do not reveal internal chain-of-thought or reasoning steps.'
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
    logger.error(req.requestId, null, null, `/user error: ${String(err)}`);
    return res.status(500).json({ error: 'server_error', details: String(err?.message || err) });
  }
});

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
    const clientShape = formatSessionForClient(session);
    return res.json({ sessionId, ...clientShape });
  } catch (err) {
    logger.error(req.requestId, null, null, `/session error: ${String(err)}`);
    return res.status(500).json({ error: 'server_error', details: String(err?.message || err) });
  }
});

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
    logger.error(req.requestId, null, null, `/sessions error: ${String(err)}`);
    return res.status(500).json({ error: String(err?.message || err) });
  }
});

app.get('/history/:tfid/:n?', async (req, res) => {
  try {
    const tfid = req.params.tfid;
    const n = Math.max(1, Math.min(1000, Number(req.params.n || 100)));
    const hist = await readJsonSafe(USER_HISTORY_FILE, { histories: {} });
    const arr = (hist.histories && hist.histories[tfid]) ? hist.histories[tfid] : [];
    return res.json(arr.slice(-n));
  } catch (err) {
    logger.error(req.requestId, null, null, `/history error: ${String(err)}`);
    return res.status(500).json({ error: String(err?.message || err) });
  }
});

/* Core handler using Google generateContent */
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

    // Correct trimming logic: reserve allowed response tokens, compute max prompt tokens
    const allowedResponseTokens = Math.min(DEFAULT_MAX_TOKENS, MAX_ALLOWED_TOKENS);
    const maxPromptTokens = Math.max(0, MAX_CONTEXT_TOKENS - allowedResponseTokens);

    while (tail.length > 0 && promptTokens > maxPromptTokens) {
      tail.shift();
      promptTokens = estimatePromptTokens(systemMsg, tail, clean);
    }

    if (promptTokens > maxPromptTokens) {
      logger.warn(req.requestId, tfid, sessionId, `Prompt still large after trimming; estimated prompt tokens: ${promptTokens}, maxPromptTokens: ${maxPromptTokens}`);
    } else {
      logger.info(req.requestId, tfid, sessionId, `Prompt tokens after trimming: ${promptTokens}, response tokens cap: ${allowedResponseTokens}`);
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
      const attemptStart = Date.now();
      const attemptTimeout = DEFAULT_TIMEOUT_MS + (attempt - 1) * EXTRA_TIMEOUT_PER_ATTEMPT;

      // Build Google generateContent payload
      const promptText = messagesForProvider.map(m => `${m.role || 'user'}: ${String(m.content || '')}`).join('\n\n');

      const url = `${GOOGLE_BASE}/v1beta/models/${GOOGLE_MODEL}:generateContent?key=${GOOGLE_API_KEY}`;

      const payload = {
        system_instruction: {
          parts: [
            { text: systemMsg.content }
          ]
        },
        contents: [
          {
            parts: [
              { text: promptText }
            ]
          }
        ],
        generationConfig: {
          maxOutputTokens: currentMax,
          temperature: 0.7
        }
      };

      lastResp = await fetchWithTimeout(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
      }, attemptTimeout);

      const attemptDur = Date.now() - attemptStart;
      logger.info(req.requestId, tfid, sessionId, `provider attempt=${attempt} status=${lastResp.status} duration=${attemptDur}ms headers=${JSON.stringify(lastResp.headers || {})}`);

      if (lastResp.text) {
        const preview = String(lastResp.text).slice(0, 800).replace(/\s+/g,' ');
        logger.info(req.requestId, tfid, sessionId, `provider body preview: ${preview}${lastResp.text.length > 800 ? '...[truncated]' : ''}`);
      }

      // Network-level error (fetch failed)
      if (!lastResp.ok && lastResp.fetchError) {
        logger.warn(req.requestId, tfid, sessionId, `Provider network error (attempt ${attempt}): ${String(lastResp.fetchError)}`);
        if (attempt < MAX_RETRIES) {
          const jitter = Math.floor(Math.random() * 300);
          const wait = Math.min(MAX_BACKOFF_MS, backoffMs + jitter);
          logger.info(req.requestId, tfid, sessionId, `network retry in ${wait}ms`);
          await sleep(wait);
          backoffMs = Math.min(MAX_BACKOFF_MS, Math.floor(backoffMs * BACKOFF_MULT));
          continue;
        } else {
          break;
        }
      }

      // Non-OK HTTP status handling (including 429)
      if (!lastResp.ok) {
        logger.warn(req.requestId, tfid, sessionId, `Provider returned status ${lastResp.status} (attempt ${attempt}).`);

        // If provider provided Retry-After header, use it
        const retryAfterSec = lastResp.headers?.['retry-after'] ? Number(lastResp.headers['retry-after']) : null;

        if (lastResp.status === 429 && attempt < MAX_RETRIES) {
          const base = retryAfterSec ? retryAfterSec * 1000 : backoffMs;
          const jitter = Math.floor(Math.random() * Math.min(1000, base));
          const waitMs = Math.min(MAX_BACKOFF_MS, base + jitter);
          logger.warn(req.requestId, tfid, sessionId, `Received 429. Waiting ${waitMs}ms before retrying (Retry-After=${retryAfterSec}).`);
          await sleep(waitMs);
          backoffMs = Math.min(MAX_BACKOFF_MS, Math.floor(backoffMs * BACKOFF_MULT));
          continue;
        }

        if ([502, 503, 504].includes(lastResp.status) && attempt < MAX_RETRIES) {
          const jitter = Math.floor(Math.random() * 300);
          const wait = Math.min(MAX_BACKOFF_MS, backoffMs + jitter);
          logger.info(req.requestId, tfid, sessionId, `Transient error ${lastResp.status}, retrying in ${wait}ms.`);
          await sleep(wait);
          backoffMs = Math.min(MAX_BACKOFF_MS, Math.floor(backoffMs * BACKOFF_MULT));
          continue;
        }

        break;
      }

      // OK response
      const part = extractAssistantText(lastResp.json) || (lastResp.text && lastResp.text.trim()) || null;
      if (part) accumulated = accumulated ? (accumulated + '\n' + part) : part;

      const finishReason = lastResp.json?.candidates?.[0]?.finishReason ?? null;

      if (finishReason && finishReason !== 'LENGTH_EXCEEDED' && finishReason !== 'MAX_OUTPUT_TOKENS') {
        assistantText = accumulated || null;
        break;
      }

      if (!finishReason) {
        assistantText = accumulated || null;
        break;
      }

      logger.warn(req.requestId, tfid, sessionId, `Model truncated (finishReason=${finishReason}) on attempt ${attempt}.`);

      const prev = currentMax;
      currentMax = Math.min(MAX_ALLOWED_TOKENS, Math.max(currentMax + 32, Math.floor(currentMax * 1.5)));
      if (currentMax !== prev && currentMax <= MAX_ALLOWED_TOKENS) {
        logger.info(req.requestId, tfid, sessionId, `Increasing max tokens ${prev} -> ${currentMax} and retrying.`);
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
        logger.info(req.requestId, tfid, sessionId, `Issuing continuation #${continuations} to fetch remaining content.`);
        continue;
      } else {
        logger.warn(req.requestId, tfid, sessionId, 'No more continuation attempts allowed or nothing accumulated. Breaking.');
        assistantText = accumulated || null;
        break;
      }
    } // end attempts loop

    if (assistantText) {
      // Wrap with server marker if not present
      const wrapped = ensureMarkerBefore(assistantText);

      // store wrapped in session/history (raw from model)
      session.messages.push({ role: 'assistant', content: wrapped, ts: Date.now() });
      hist.histories[tfid].push({ role: 'assistant', content: wrapped, sessionId, ts: Date.now() });
      await writeJsonSafe(SESSIONS_FILE, sessionsData);
      await writeJsonSafe(USER_HISTORY_FILE, hist);

      // Visible part (before marker)
      let visible = extractVisibleFromWrapped(wrapped);

      // 1) Normalize any accidental spaces inside § markers: § code § -> §code§
      let normalized = normalizeCopyMarkers(visible);

      // 2) If model used triple-backticks ```...``` convert them to §...§ to enforce § usage
      normalized = normalized.replace(/```(?:[a-zA-Z0-9]+\n)?([\s\S]*?)```/g, (m, p1) => {
        const inner = String(p1).replace(/^\n+|\n+$/g, '');
        return '§' + inner + '§';
      });

      // 3) Prepare a rendered version (```...```) if UI wants to show it
      const rendered = renderCopyableMarkersToMarkdown(normalized);

      logger.info(req.requestId, tfid, sessionId, `assistantText length=${String(assistantText).length} saved to session`);

      // Return RAW with § as primary field, plus optional rendered.
      return res.json({
        assistant: normalized,
        assistant_rendered: rendered,
        session: formatSessionForClient(session)
      });
    }

    logger.error(req.requestId, tfid, sessionId, 'No assistant text extracted after retries/continuations.');
    if (lastResp) {
      logger.error(req.requestId, tfid, sessionId, `Provider lastResp status: ${lastResp.status}`);
      if (lastResp.fetchError) logger.error(req.requestId, tfid, sessionId, `Provider fetchError: ${String(lastResp.fetchError)}`);
      if (lastResp.text && lastResp.text.trim()) {
        const statusToSend = Number.isInteger(lastResp.status) ? lastResp.status : 502;
        return res.status(statusToSend).type('text').send(lastResp.text);
      }
    }

    return res.status(502).json({ error: 'no_response_from_provider' });
  } catch (err) {
    logger.error(req.requestId, null, null, `/message error: ${String(err)}`);
    return res.status(500).json({ error: 'server_error', details: String(err?.message || err) });
  }
}

app.post('/message', handleMessage);

app.post('/api/chat', async (req, res) => {
  if (req.body && req.body.prompt && !req.body.text) req.body.text = req.body.prompt;
  return handleMessage(req, res);
});

app.get('/health', (req, res) => res.json({ ok: true }));

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
  logger.info(null, null, null, `Server listening on http://localhost:${PORT} (HISTORY_TAIL=${HISTORY_TAIL}, RESPONSE_MAX_TOKENS=${DEFAULT_MAX_TOKENS})`);
});
