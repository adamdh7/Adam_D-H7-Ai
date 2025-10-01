// index.mjs
import express from 'express';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import { promises as fs } from 'fs';
import crypto from 'crypto';

dotenv.config();

// ensure fetch exists (Node 18+ has global fetch). If not, try node-fetch dynamically.
if (typeof globalThis.fetch !== 'function') {
  try {
    const nf = await import('node-fetch');
    globalThis.fetch = nf.default;
  } catch (e) {
    console.error('Global fetch not available and node-fetch could not be imported. Use Node 18+ or install node-fetch.');
    throw e;
  }
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const OPENROUTER_API_KEY = (process.env.OPENROUTER_API_KEY || '').trim();
const MASTER_KEY_HEX = (process.env.MASTER_KEY || '').trim(); // optional: 64 hex chars
const MODEL = process.env.MODEL || 'openai/gpt-5';
const SYSTEM_PROMPT = (process.env.SYSTEM_PROMPT && process.env.SYSTEM_PROMPT.trim()) ||
  "You are Adam_D'H7. Created by D'H7 | Tergene. Be concise. Do NOT reveal internal chain-of-thought.";

const USERS_FILE = path.join(__dirname, 'user.json');
const SESSIONS_FILE = path.join(__dirname, 'sessions.json');

// Configurable defaults
const DEFAULT_MAX_TOKENS = Number(process.env.DEFAULT_MAX_TOKENS) || 170;
const DEFAULT_TEMPERATURE = Number(process.env.DEFAULT_TEMPERATURE) || 0.2;
const HISTORY_MESSAGE_LIMIT = Number(process.env.HISTORY_MESSAGE_LIMIT) || 16;
const DEV_DEBUG = process.env.DEV_DEBUG === '1';

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

// --- Encryption helpers (AES-256-GCM) ---
function hasMasterKey() {
  return !!MASTER_KEY_HEX && MASTER_KEY_HEX.length === 64;
}
function getMasterKeyBuffer() {
  if (!hasMasterKey()) throw new Error("MASTER_KEY missing or invalid (must be 32 bytes hex = 64 hex chars).");
  return Buffer.from(MASTER_KEY_HEX, 'hex');
}
function encryptText(plaintext) {
  const key = getMasterKeyBuffer();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${iv.toString('base64')}:${tag.toString('base64')}:${ciphertext.toString('base64')}`;
}
function decryptText(payload) {
  const key = getMasterKeyBuffer();
  const parts = payload.split(':');
  if (parts.length !== 3) throw new Error('Invalid encrypted payload');
  const iv = Buffer.from(parts[0], 'base64');
  const tag = Buffer.from(parts[1], 'base64');
  const ciphertext = Buffer.from(parts[2], 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return plain.toString('utf8');
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
  return 'TF' + crypto.randomUUID().slice(0, 5).toUpperCase();
}

// --- Init files ---
await readJsonSafe(USERS_FILE, { users: [] });
await readJsonSafe(SESSIONS_FILE, { sessions: {} });

// --- Utility: system prompt builder per session
function makeSystemPrompt(tfid, sessionId) {
  return {
    role: 'system',
    content:
`You are Adam_D'H7. Created by D'H7 | Tergene. Each chat session is isolated.
User identifier: ${tfid}
Session id: ${sessionId}
Important instructions:
- Treat this session as independent. Do NOT reference or reveal messages from other sessions or users unless the user explicitly asks.
- If asked about previous sessions, ask for explicit permission or to provide the content.
- Be concise`
  };
}

// --- Robust extractor for provider responses ---
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

// --- Sanitize parsed provider objects before exposing them ---
function deepSanitize(obj) {
  if (obj == null || typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(v => deepSanitize(v));
  const copy = {};
  for (const k of Object.keys(obj)) {
    const lower = String(k).toLowerCase();
    // Keys we do NOT want to expose to UI
    if (['logprobs', 'reasoning', 'reasoning_details', 'internal', 'debug', 'trace', 'metadata', 'safety', 'plugins'].includes(lower)) {
      continue;
    }
    try {
      copy[k] = deepSanitize(obj[k]);
    } catch {
      // skip problematic entries
    }
  }
  return copy;
}
function safeSnippetFromParsed(parsed, maxChars = 800) {
  try {
    const sanitized = deepSanitize(parsed);
    const s = JSON.stringify(sanitized);
    if (s.length <= maxChars) return s;
    return s.slice(0, maxChars) + '... (truncated)';
  } catch (e) {
    return '(unable to create snippet)';
  }
}

// --- Parse allowed tokens from OpenRouter 402 error message ---
function parseAllowedTokensFromErrorText(text) {
  if (!text) return null;
  let m = text.match(/can only afford\s*(\d+)/i);
  if (m && m[1]) return Number(m[1]);
  m = text.match(/afford\s*(\d+)/i);
  if (m && m[1]) return Number(m[1]);
  m = text.match(/maximum.*?(\d+)/i);
  if (m && m[1]) return Number(m[1]);
  return null;
}

// --- Post to OpenRouter with fallback adjustments on 402 (accepts apiKey param) ---
async function postToOpenRouterWithFallback(body, apiKey = OPENROUTER_API_KEY, maxRetries = 2) {
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
          'Authorization': 'Bearer ' + apiKey
        },
        body: JSON.stringify(currentBody)
      });

      const textResp = await resp.text();
      let parsed = null;
      try { parsed = JSON.parse(textResp); } catch (e) { parsed = null; }

      if (resp.ok) {
        return { ok: true, status: resp.status, parsed, rawText: textResp };
      }

      if (resp.status === 402) {
        console.warn('[openrouter] 402 - will try to reduce max_tokens and retry if possible. Snippet:', textResp.slice(0,800));
        const allowed = parseAllowedTokensFromErrorText(textResp);
        let newMax = null;
        if (allowed && typeof allowed === 'number') {
          newMax = Math.max(1, Math.min(currentBody.max_tokens - 1, allowed - 20));
        } else {
          newMax = Math.max(1, Math.floor(currentBody.max_tokens * 0.75));
          if (newMax > DEFAULT_MAX_TOKENS) newMax = DEFAULT_MAX_TOKENS;
        }
        if (newMax < currentBody.max_tokens) {
          currentBody = { ...currentBody, max_tokens: newMax };
          await new Promise(r => setTimeout(r, 250));
          continue;
        }
        return { ok: false, status: resp.status, parsed, rawText: textResp };
      }

      return { ok: false, status: resp.status, parsed, rawText: textResp };

    } catch (err) {
      console.error('[openrouter] network/exception on attempt', attempt, err);
      if (attempt > maxRetries) return { ok: false, error: String(err) };
      await new Promise(r => setTimeout(r, 200));
    }
  }

  return { ok: false, error: 'exhausted_retries' };
}

// --- Deliberate & refine pipeline (uses postToOpenRouterWithFallback with user's or global key) ---
async function deliberateAndRefine(baseMessagesForApi, apiKeyToUse, userText) {
  try {
    const historyLen = (baseMessagesForApi.map(m => m.content || '').join(' ') || '').length;
    const contentLen = (userText || '').length + historyLen;
    let passes = 1 + Math.floor(contentLen / 800);
    passes = Math.max(1, Math.min(passes, 2)); // keep passes 1..2 for cost control

    const draftMessages = [
      ...baseMessagesForApi,
      { role: 'system', content: `You are Adam_D'H7. Deliberation mode: produce a clear draft answer to the user's request. DO NOT reveal internal chain-of-thought. Output ONLY the draft answer.` },
      { role: 'user', content: userText || 'Please respond.' }
    ];

    const draftResult = await postToOpenRouterWithFallback({
      model: MODEL,
      messages: draftMessages,
      max_tokens: DEFAULT_MAX_TOKENS,
      temperature: DEFAULT_TEMPERATURE
    }, apiKeyToUse, 1);

    if (!draftResult.ok) {
      // fallback early
      return null;
    }
    let draft = extractAssistantText(draftResult.parsed) || '';

    for (let pass = 2; pass <= passes; pass++) {
      const refineMessages = [
        ...baseMessagesForApi,
        { role: 'system', content: `You are Adam_D'H7. Deliberation pass ${pass}/${passes}: Critique and improve the previous draft briefly and produce an improved final answer. DO NOT output internal critique or chain-of-thought.` },
        { role: 'assistant', content: draft },
        { role: 'user', content: userText || 'Refine the draft and produce the final improved answer.' }
      ];

      const refineResult = await postToOpenRouterWithFallback({
        model: MODEL,
        messages: refineMessages,
        max_tokens: DEFAULT_MAX_TOKENS,
        temperature: DEFAULT_TEMPERATURE
      }, apiKeyToUse, 1);

      if (!refineResult.ok) break;
      const refined = extractAssistantText(refineResult.parsed);
      if (refined && refined.trim().length > 0) draft = refined;
    }

    return draft;
  } catch (e) {
    console.error('deliberateAndRefine error:', e);
    return null;
  }
}

// ----------------- API Endpoints -----------------

// Create new user (or return existing if tfid provided).
// Body: { name? }  OR { tfid }
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
    const user = {
      tfid: newTF,
      name: name || null,
      createdAt: new Date().toISOString(),
      encryptedApiKey: null,
      profile: {}
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

// Set (save) a user's API key (encrypted) — requires MASTER_KEY to be set on the server.
// Body: { tfid, apikey }
app.post('/user/apikey', async (req, res) => {
  try {
    const { tfid, apikey } = req.body || {};
    if (!tfid || !apikey) return res.status(400).json({ error: 'tfid_and_apikey_required' });

    if (!hasMasterKey()) return res.status(400).json({ error: 'server_missing_master_key' });

    const data = await readJsonSafe(USERS_FILE, { users: [] });
    const found = data.users.find(u => u.tfid === tfid);
    if (!found) return res.status(404).json({ error: 'user_not_found' });

    try {
      found.encryptedApiKey = encryptText(apikey);
      await writeJsonSafe(USERS_FILE, data);
      return res.json({ ok: true });
    } catch (e) {
      console.error('encrypt save error', e);
      return res.status(500).json({ error: 'encrypt_failed', details: String(e) });
    }
  } catch (err) {
    console.error('/user/apikey error', err);
    res.status(500).json({ error: 'server_error', details: err.message });
  }
});

// Delete user's saved API key
app.delete('/user/apikey', async (req, res) => {
  try {
    const { tfid } = req.body || req.query || {};
    if (!tfid) return res.status(400).json({ error: 'tfid_required' });

    const data = await readJsonSafe(USERS_FILE, { users: [] });
    const found = data.users.find(u => u.tfid === tfid);
    if (!found) return res.status(404).json({ error: 'user_not_found' });

    found.encryptedApiKey = null;
    await writeJsonSafe(USERS_FILE, data);
    return res.json({ ok: true });
  } catch (err) {
    console.error('/user/apikey delete error', err);
    res.status(500).json({ error: 'server_error', details: err.message });
  }
});

// --- Session management ---
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
      messages: []
    };
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

// --- Main message endpoint: receives user message, appends to session, proxies to OpenRouter, saves assistant reply ---
// body: { tfid, sessionId, text }
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

    // push user message to session history
    const userMsg = { role: 'user', content: text, ts: Date.now() };
    session.messages.push(userMsg);

    // Build messages: system + existing history (assistant & user) + latest user
    const sys = makeSystemPrompt(tfid, sessionId);
    const history = (session.messages || []).map(m => {
      if (m.role === 'user') return { role: 'user', content: m.content || m.text || '' };
      return { role: 'assistant', content: m.content || m.text || '' };
    });

    const tail = history.slice(-HISTORY_MESSAGE_LIMIT);
    const payloadMessages = [sys, ...tail];

    // Determine API key to use (user encrypted key if present & MASTER_KEY available, else global)
    let apiKeyToUse = OPENROUTER_API_KEY;
    if (user.encryptedApiKey) {
      if (hasMasterKey()) {
        try {
          apiKeyToUse = decryptText(user.encryptedApiKey);
        } catch (e) {
          console.error('decrypt error for user key, falling back to global key', e);
          apiKeyToUse = OPENROUTER_API_KEY;
        }
      } else {
        apiKeyToUse = OPENROUTER_API_KEY;
      }
    }

    // Deliberate & refine pipeline (tries small passes)
    const baseForApi = payloadMessages;
    let finalAnswer = await deliberateAndRefine(baseForApi, apiKeyToUse, text);
    let parsedForDebug = null;
    let finishReason = null;

    // Fallback single call if no answer from pipeline
    if (!finalAnswer || !finalAnswer.trim()) {
      const result = await postToOpenRouterWithFallback({
        model: MODEL,
        messages: baseForApi,
        max_tokens: DEFAULT_MAX_TOKENS,
        temperature: DEFAULT_TEMPERATURE
      }, apiKeyToUse, 2);

      if (!result.ok) {
        const snippet = (result.rawText || result.parsed || result.error || '').toString().slice(0, 1000);
        console.warn('[proxy] OpenRouter final failure', result.status, snippet);
        // Do not persist assistant reply on failure; session already has user message saved.
        await writeJsonSafe(SESSIONS_FILE, sessionsData);
        if (result.status === 402) {
          return res.status(402).json({ error: 'openrouter_insufficient_credits', details: snippet });
        }
        return res.status(result.status || 500).json({ error: 'openrouter_error', details: snippet });
      }

      parsedForDebug = result.parsed;
      finalAnswer = extractAssistantText(result.parsed) || "(Repons pa klè)";
      // capture finish reason if present
      try {
        const c = (result.parsed.choices && result.parsed.choices[0]) || null;
        finishReason = c && (c.finish_reason || c.native_finish_reason || null);
      } catch {}
    } else {
      // If the deliberate/refine pipeline returned text, we won't have parsed object.
      // leave parsedForDebug null.
    }

    // If the model likely truncated output due to max tokens, append user-friendly note
    if (finishReason === 'max_output_tokens' || finishReason === 'length') {
      finalAnswer = `${finalAnswer}\n\n(Nòt: repons la te long epi li te koupe. Si ou vle repons pi long, ogmante DEFAULT_MAX_TOKENS oswa retire kèk mesaj nan istwa.)`;
    }

    // Only save non-empty assistant messages
    if (finalAnswer && finalAnswer.trim()) {
      const assistantMsg = { role: 'assistant', content: finalAnswer, ts: Date.now() };
      session.messages.push(assistantMsg);
      await writeJsonSafe(SESSIONS_FILE, sessionsData);
    } else {
      // persist the session (user message already there)
      await writeJsonSafe(SESSIONS_FILE, sessionsData);
      console.warn('Not saving empty assistant response for session', sessionId);
    }

    // Prepare response to client: never include full raw parsed provider JSON
    const resp = { assistant: finalAnswer };
    if (DEV_DEBUG && parsedForDebug) {
      resp.debug = safeSnippetFromParsed(parsedForDebug, 800);
    } else if (DEV_DEBUG && !parsedForDebug) {
      resp.debug = '(no parsed provider object available for this response)';
    }
    return res.json(resp);

  } catch (err) {
    console.error('/message error', err);
    res.status(500).json({ error: 'server_error', details: err.message });
  }
});

// Optional compatibility proxy /openrouter (for legacy UI) — uses global key
// This endpoint returns a SANITIZED parsed provider object (no 'reasoning' or internal debug fields)
app.post('/openrouter', async (req, res) => {
  try {
    const bodyToSend = {
      model: req.body.model || MODEL,
      messages: req.body.messages || [],
      max_tokens: typeof req.body.max_tokens === 'number' ? req.body.max_tokens : DEFAULT_MAX_TOKENS,
      temperature: typeof req.body.temperature === 'number' ? req.body.temperature : DEFAULT_TEMPERATURE
    };

    const result = await postToOpenRouterWithFallback(bodyToSend, OPENROUTER_API_KEY, 2);
    if (!result.ok) {
      const snippet = (result.rawText || result.parsed || result.error || '').toString().slice(0, 1000);
      if (result.status === 402) return res.status(402).json({ error: 'openrouter_insufficient_credits', details: snippet });
      return res.status(result.status || 500).json({ error: 'openrouter_error', details: snippet });
    }

    if (result.parsed) {
      const safe = deepSanitize(result.parsed);
      // If DEV_DEBUG, include tiny snippet of original raw (truncated) — careful to not expose internal fields
      if (DEV_DEBUG) {
        return res.status(result.status).json({ sanitized: safe, debug_snippet: safeSnippetFromParsed(result.parsed, 1000) });
      }
      return res.status(result.status).json(safe);
    }

    return res.status(result.status).type('text').send('(no parsed response)');
  } catch (err) {
    console.error('/openrouter proxy error', err);
    res.status(500).json({ error: 'proxy_failed', details: String(err) });
  }
});

// Diagnostic route to test outbound connectivity to OpenRouter
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
