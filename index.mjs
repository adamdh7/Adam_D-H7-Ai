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

let HISTORY_TAIL = (raw !== undefined && raw !== '') ? Number(raw) : 7;

if (!Number.isFinite(HISTORY_TAIL)) {
  HISTORY_TAIL = 7;
}

// si itilizatè mete 0 oswa negatif => entèprete kòm "pran tout"
if (HISTORY_TAIL <= 0) {
  HISTORY_TAIL = Infinity;
}

const DEFAULT_MAX_TOKENS = Number(process.env.DEFAULT_MAX_TOKENS) || 1000;
const MAX_ALLOWED_TOKENS = Number(process.env.MAX_ALLOWED_TOKENS) || 1000;
const MAX_CONTEXT_TOKENS = Number(process.env.MAX_CONTEXT_TOKENS) || 2048;

// Increased default timeout to reduce AbortError on slow networks
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

app.use(cors({ origin: true }));
app.use(express.json({ limit: '1000mb' }));
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

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

/* ---------- Similarité / fallback search helpers (NEW) ---------- */

function tokenizeWords(s) {
  if (!s) return [];
  return String(s).toLowerCase()
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '') // remove diacritics
    .split(/\s+/)
    .map(w => w.replace(/[^\p{L}\p{N}]/gu, ''))
    .filter(Boolean);
}

// Dice coefficient (word-level)
function diceCoefficientWords(a, b) {
  const A = tokenizeWords(a);
  const B = tokenizeWords(b);
  if (!A.length && !B.length) return 0;
  const setA = new Set(A);
  const setB = new Set(B);
  let inter = 0;
  for (const t of setA) if (setB.has(t)) inter++;
  return (2 * inter) / (setA.size + setB.size) || 0;
}

// Longest common substring length (char-level) — normalized
function longestCommonSubstringLen(a, b) {
  if (!a || !b) return 0;
  const A = String(a);
  const B = String(b);
  const m = A.length, n = B.length;
  let max = 0;
  const dp = new Uint16Array(n + 1);
  for (let i = 1; i <= m; i++) {
    let prev = 0;
    for (let j = 1; j <= n; j++) {
      const tmp = dp[j];
      if (A[i - 1] === B[j - 1]) {
        dp[j] = prev + 1;
        if (dp[j] > max) max = dp[j];
      } else {
        dp[j] = 0;
      }
      prev = tmp;
    }
  }
  return max;
}

function combinedSimilarity(a, b) {
  const dice = diceCoefficientWords(a, b);
  const lcs = longestCommonSubstringLen(a, b);
  const avgLen = (String(a).length + String(b).length) / 2 || 1;
  const lcsNorm = lcs / avgLen; // between 0..1
  // combine both signals, give word overlap more weight
  return Math.max(dice, (dice * 0.7 + lcsNorm * 0.3));
}

/**
 * Recherche la meilleure réponse passée (dans user_history.json) correspondant à `query`.
 * Renvoie { score, userContent, assistantContent, tfid, sessionId } ou null si rien.
 */
async function findBestPastReply(query) {
  const all = await readJsonSafe(USER_HISTORY_FILE, { histories: {} });
  let best = null;
  const histories = all.histories || {};
  for (const [histTfid, arr] of Object.entries(histories)) {
    if (!Array.isArray(arr)) continue;
    for (let i = 0; i < arr.length; i++) {
      const rec = arr[i];
      if (!rec || rec.role !== 'user' || !rec.content) continue;
      const score = combinedSimilarity(query, rec.content);
      // chercher la prochaine réponse assistant dans le même sessionId après i
      for (let j = i + 1; j < arr.length; j++) {
        const next = arr[j];
        if (!next) continue;
        // si sessionId diffère, on arrête de chercher plus loin pour cet indice
        if (rec.sessionId && next.sessionId && rec.sessionId !== next.sessionId) break;
        if (next.role === 'assistant' && next.content) {
          if (!best || score > best.score) {
            best = {
              score,
              userContent: rec.content,
              assistantContent: next.content,
              tfid: histTfid,
              sessionId: rec.sessionId || null,
              idxUser: i,
              idxAssistant: j
            };
          }
          break; // on garde uniquement la réponse immédiate suivante
        }
      }
    }
  }
  return best;
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

/* System prompt */
function makeSystemPrompt(tfid, sessionId, userName = null) {
  const identity = "You are Adam_D'H7 everyone's friend created by D'H7 | Tergene. born on July 17, 2009, you are a Haitian ";
  const lines = [identity, `Session: ${sessionId}`, 'responds to the user\'s language '];
  return { role: 'system', content: lines.join(' ') };
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
    return res.json({ sessionId, createdAt: session.createdAt });
  } catch (err) {
    console.error('/session error', err);
    return res.status(500).json({ error: 'server_error', details: String(err?.message || err) });
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
    console.error('/history error', err);
    return res.status(500).json({ error: String(err?.message || err) });
  }
});

app.post('/message', async (req, res) => {
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

    // backoff parameters
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
      return res.json({ assistant: visible });
    }

    // === BEGIN: remplacement du bloc d'erreur par logique de fallback historique (NEW) ===
    console.error('No assistant text extracted after retries/continuations.');

    if (lastResp) {
      console.error('Provider lastResp status:', lastResp.status);
      if (lastResp.fetchError) console.error('Provider fetchError:', lastResp.fetchError);
      if (lastResp.text && lastResp.text.trim()) {
        // si le provider renvoie du texte brut, on le renvoie (comme avant)
        const statusToSend = Number.isInteger(lastResp.status) ? lastResp.status : 502;
        return res.status(statusToSend).type('text').send(lastResp.text);
      }
    }

    // --- Nouvelle logique : fallback sur historique local ---
    try {
      const best = await findBestPastReply(clean);
      if (best && best.assistantContent) {
        console.log('Fallback: found best past reply with score', best.score.toFixed(3), 'from tfid', best.tfid);

        // utiliser la réponse trouvée (on garde telle quelle si elle contient le marqueur, sinon on l'enveloppe)
        const assistantRaw = String(best.assistantContent || '').trim();
        const wrapped = ensureMarkerBefore(assistantRaw);

        // enregistrer dans la session courante et dans user_history du tfid actuel
        session.messages.push({ role: 'assistant', content: wrapped, ts: Date.now() });
        hist.histories[tfid].push({ role: 'assistant', content: wrapped, sessionId, ts: Date.now(), fallback_from: best.tfid });

        await writeJsonSafe(SESSIONS_FILE, sessionsData);
        await writeJsonSafe(USER_HISTORY_FILE, hist);

        const visible = extractVisibleFromWrapped(wrapped);
        return res.json({ assistant: visible, fallback: true, fallbackScore: best.score });
      } else {
        console.warn('Fallback search found no suitable past reply.');
        return res.status(502).json({ error: 'no_response_from_provider', fallback: false });
      }
    } catch (e) {
      console.error('Error during fallback search:', e);
      return res.status(502).json({ error: 'no_response_from_provider', fallback: false, details: String(e?.message || e) });
    }
    // === END: fallback historique ===

  } catch (err) {
    console.error('/message error', err);
    return res.status(500).json({ error: 'server_error', details: String(err?.message || err) });
  }
});

app.get('/health', (req, res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT} (HISTORY_TAIL=${HISTORY_TAIL}, RESPONSE_MAX_TOKENS=${DEFAULT_MAX_TOKENS})`);
});
