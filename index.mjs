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
   Configuration & constantes
   --------------------------- */
const PORT = Number(process.env.PORT) || 3000;
const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY;
const OPENROUTER_ENDPOINT = process.env.OPENROUTER_ENDPOINT || 'https://openrouter.ai/api/v1/chat/completions';
const OPENROUTER_MODEL = process.env.OPENROUTER_MODEL || 'gpt-5';
const HISTORY_TAIL = Number(process.env.HISTORY_TAIL) || 27;

const DEFAULT_MAX_TOKENS = Number(process.env.DEFAULT_MAX_TOKENS) || 100;
const DEFAULT_TIMEOUT_MS = Number(process.env.DEFAULT_TIMEOUT_MS) || 30000;
const MAX_RETRIES = Number(process.env.MAX_RETRIES) || 3;
const MIN_TOKENS = Number(process.env.MIN_TOKENS) || 16;
const DEFAULT_USER_NAME = process.env.DEFAULT_USER_NAME || "User";
const MAX_ALLOWED_TOKENS = Number(process.env.MAX_ALLOWED_TOKENS) || 200;
const RECOVERY_MAX_TOKENS_CAP = Number(process.env.RECOVERY_MAX_TOKENS_CAP) || 50;

// Toggle marker behavior via .env (string "true" enables it).
// For correct "***Terminé***" handling default is true.
const ENABLE_MARKER = process.env.ENABLE_MARKER ? process.env.ENABLE_MARKER === 'true' : true;

// Reflection pauses (ms) — default 2s each as requested
const THINK_PROMPT_MS = Number(process.env.THINK_PROMPT_MS) || 2000;   // lire prompt pendant 2s
const THINK_MESSAGES_MS = Number(process.env.THINK_MESSAGES_MS) || 2000; // lire messages pendant 2s

const TF_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz123456789';
const USERS_FILE = path.join(__dirname, 'user.json');
const SESSIONS_FILE = path.join(__dirname, 'sessions.json');
const USER_HISTORY_FILE = path.join(__dirname, 'user_history.json');
const PHRASE_BANK_FILE = path.join(__dirname, 'phrasebank.json');

if (!OPENROUTER_API_KEY) {
  console.error('ERROR: OPENROUTER_API_KEY missing in .env');
  process.exit(1);
}

app.use(cors({ origin: true }));
app.use(express.json({ limit: '70mb' }));
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

/* ---------------------------
   Helpers: fichiers JSON safe
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
   Sleep helper
   --------------------------- */
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
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
   MARKER helpers (internal)
   --------------------------- */
// Marker is INTERNAL only. It marks end of internal reasoning and start of visible reply.
const MARKER = '***Terminé***';

// Put MARKER immediately before visible reply for storage; server will strip it before sending to front.
function ensureMarkerBefore(text) {
  // Always trim
  const t = text == null ? '' : String(text).trim();
  if (!ENABLE_MARKER) {
    return t;
  }
  if (!t) return MARKER;
  if (t.includes(MARKER)) return t;
  return `${MARKER}\n\n${t}`;
}

// VERY ROBUST extraction: return strictly text AFTER last marker (no marker)
// Avoid returning fragments like "Term" or "Terminé" or stray stars.
function extractVisibleFromWrapped(wrappedText) {
  if (!wrappedText || typeof wrappedText !== 'string') return '';
  const raw = wrappedText;
  let lastIdx = raw.lastIndexOf(MARKER);
  let markerLen = MARKER.length;
  let matchedText = null;

  if (lastIdx === -1) {
    const fuzzy = /(\*{0,}\s*Term(?:in?é|ine)?\s*\*{0,})/ig;
    let m;
    let lastMatch = null;
    while ((m = fuzzy.exec(raw)) !== null) {
      lastMatch = { index: m.index, text: m[0] };
    }
    if (lastMatch) {
      lastIdx = lastMatch.index;
      markerLen = lastMatch.text.length;
      matchedText = lastMatch.text;
    }
  } else {
    matchedText = MARKER;
  }

  if (lastIdx === -1) {
    return raw.trim();
  }

  let after = raw.slice(lastIdx + markerLen);
  after = after.replace(/^[\s\*—–\-\._"'`:]*/u, '');
  after = after.replace(/^(?:Term(?:in?é|ine)?)/i, '');
  return after.trim();
}

/* ---------------------------
   Phrase bank (secure)
   --------------------------- */
let phraseBank = { phrases: {}, updatedAt: null };

const RE_EMAIL = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i;
const RE_URL = /https?:\/\/|www\.[\S]+/i;
const RE_PHONE = /(?:\+?\d{1,3}[-.\s]?)*\(?\d{2,4}\)?[-.\s]?\d{2,4}[-.\s]?\d{2,4}/;
const RE_DIGIT_SEQ = /\d{3,}/;
const MAX_PHRASE_LEN = 160;
const MIN_PHRASE_LEN = 6;

function isSafePhraseCandidate(txt) {
  if (!txt || typeof txt !== 'string') return false;
  const t = txt.trim();
  if (t.length < MIN_PHRASE_LEN || t.length > MAX_PHRASE_LEN) return false;
  if (RE_EMAIL.test(t)) return false;
  if (RE_URL.test(t)) return false;
  if (RE_PHONE.test(t)) return false;
  if (RE_DIGIT_SEQ.test(t)) return false;
  if (/\b(ssn|social security|passport|card number|password|mot de passe)\b/i.test(t)) return false;
  if (/\S{40,}/.test(t)) return false;
  return true;
}

function splitIntoCandidates(text) {
  if (!text) return [];
  const parts = text.split(/[.?!\n\r]+/).map(p => p.trim()).filter(Boolean);
  const candidates = [];
  for (const p of parts) {
    if (p.length > MAX_PHRASE_LEN) {
      const sub = p.split(/[,;:]+/).map(s => s.trim()).filter(Boolean);
      for (const s of sub) if (s.length >= MIN_PHRASE_LEN && s.length <= MAX_PHRASE_LEN) candidates.push(s);
    } else {
      candidates.push(p);
    }
  }
  return candidates;
}

async function loadPhraseBank() {
  try {
    const pb = await readJsonSafe(PHRASE_BANK_FILE, { phrases: {}, updatedAt: null });
    phraseBank = pb;
  } catch (e) {
    phraseBank = { phrases: {}, updatedAt: null };
  }
}

async function updatePhraseBankWithAssistantContent(rawContent) {
  if (!rawContent || typeof rawContent !== 'string') return;
  const candidates = splitIntoCandidates(rawContent);
  let changed = false;
  for (let c of candidates) {
    c = c.replace(/\s{2,}/g, ' ').trim();
    if (!isSafePhraseCandidate(c)) continue;
    const normalized = c.replace(/\s+([,;:.!?])/g, '$1').trim();
    phraseBank.phrases[normalized] = (phraseBank.phrases[normalized] || 0) + 1;
    changed = true;
  }
  if (changed) {
    phraseBank.updatedAt = new Date().toISOString();
    try { await writeJsonSafe(PHRASE_BANK_FILE, phraseBank); } catch(e) {}
  }
}

async function buildPhraseBankFromHistory() {
  try {
    const hist = await readJsonSafe(USER_HISTORY_FILE, { histories: {} });
    const allHist = hist.histories || {};
    for (const tfid of Object.keys(allHist)) {
      const arr = allHist[tfid] || [];
      for (const e of arr) {
        if (e && e.role === 'assistant' && typeof e.content === 'string') {
          const visible = extractVisibleFromWrapped(e.content);
          await updatePhraseBankWithAssistantContent(visible);
        }
      }
    }
  } catch (e) {}
}

function findBestBankPhrase(userInput) {
  const words = (userInput || '').toLowerCase().match(/\b[\p{L}0-9'-]+\b/gu) || [];
  if (!words.length) return getMostFrequentPhrase();
  let best = null;
  let bestScore = 0;
  for (const [phrase, count] of Object.entries(phraseBank.phrases || {})) {
    const pWords = (phrase || '').toLowerCase().match(/\b[\p{L}0-9'-]+\b/gu) || [];
    let overlap = 0;
    const pSet = new Set(pWords);
    for (const w of words) if (pSet.has(w)) overlap++;
    const score = overlap * 2 + Math.log(1 + count);
    if (score > bestScore && overlap > 0) {
      bestScore = score;
      best = phrase;
    }
  }
  if (best) return best;
  return getMostFrequentPhrase();
}

function getMostFrequentPhrase() {
  const entries = Object.entries(phraseBank.phrases || {});
  if (!entries.length) return null;
  entries.sort((a,b) => b[1] - a[1]);
  return entries[0][0];
}

/* ---------------------------
   Sanitizer & extraction from provider
   --------------------------- */
function sanitizeAssistantText(raw) {
  if (!raw || typeof raw !== 'string') return null;

  // 1) Keep code blocks intact by placeholdering
  const codeBlocks = [];
  let placeholderIndex = 0;
  const CODE_PLACEHOLDER = (i) => `__CODE_BLOCK_PLACEHOLDER_${i}__`;
  let temp = raw.replace(/```[\s\S]*?```/g, (m) => {
    const idx = placeholderIndex++;
    codeBlocks[idx] = m;
    return CODE_PLACEHOLDER(idx);
  });

  // 2) Split lines and normalize
  const lines = temp.split(/\r?\n/).map(l => l.replace(/\t/g,' ').trim());

  // Patterns considered meta/internal/reasoning
  const metaLinePatterns = [
    /^\s*Generating\b/i,
    /^\s*Creation\b/i,
    /^\s*Creating\b/i,
    /^\s*Plan[:\-]/i,
    /^\s*Step\s*\d+/i,
    /^\s*Steps?\b/i,
    /^\s*\[?Generating/i,
    /^\s*\(Draft[:\s]/i,
    /^\s*Note[:\-]/i,
    /^\s*Commande[:\-]/i,
    /^\s*Command[:\-]/i,
    /^\s*System[:\-]/i,
    /^\s*\**\s*Considering\b/i,
    /^\s*\**\s*Responding\b/i,
    /^\s*\**\s*Responding in\b/i,
    /^\s*\**\s*Considering user\b/i,
    /^\s*\**\s*I\s+(think|believe|see|will|should)\b/i,
    /^\s*\**\s*The user's?\s+/i,
    /^\s*\**\s*(Because|Since|Therefore)\b/i,
    /^\s*\**\s*Thoughts?\b/i,
    /^\s*\**\s*Reasoning\b/i,
    /^\s*\**\s*Analysis\b/i,
    /^\s*\**\s*Conclusion\b/i,
    /^\s*\**\s*Respond in\b/i,
    /^\s*<\/?[^>]+>/i, // html tags
    /^\s*\*{1,}.*\*{1,}\s*$/ // lines enclosed fully in asterisks (like **Considering user language**)
  ];

  // Also short parenthetical meta like "(thinking...)" already partly covered
  const shortThinking = /^[\(\[]\s*(thinking|processing|loading|one moment|please wait|en train|m'ap panse|mwen panse|je réfléchis|estoy pensando|espera un momento)[\)\]]\.?$/i;

  // Keep only lines that are not meta, but we'll also remove leading meta blocks
  const rawKept = [];
  for (let ln of lines) {
    if (!ln) continue;
    if (shortThinking.test(ln)) continue;

    // if line matches any meta pattern -> mark as meta
    let isMeta = false;
    for (const p of metaLinePatterns) {
      if (p.test(ln)) { isMeta = true; break; }
    }
    if (isMeta) {
      rawKept.push({ meta: true, text: ln });
    } else {
      // remove superficial prefixes like "Assistant:" or "System:"
      const cleaned = ln.replace(/^(Assistant|System|AI|Bot|Response)[:\-\s]+/i, '').trim();
      rawKept.push({ meta: false, text: cleaned });
    }
  }

  if (!rawKept.length) return null;

  // Remove leading meta-only block: many models print reasoning first then final reply.
  let firstNonMetaIndex = 0;
  while (firstNonMetaIndex < rawKept.length && rawKept[firstNonMetaIndex].meta) firstNonMetaIndex++;
  let kept = rawKept.slice(firstNonMetaIndex).map(o => o.text);

  // If everything was meta, fallback to removing meta flags and keep last few lines
  if (!kept.length) {
    // choose last non-empty lines (but strip meta markers)
    const lastTexts = rawKept.slice(-4).map(o => o.text);
    kept = lastTexts.filter(Boolean);
  }

  // Join, normalize whitespace
  let out = kept.join('\n').replace(/\s{2,}/g, ' ').trim();

  // Restore code blocks placeholders
  for (let i = 0; i < codeBlocks.length; i++) {
    const ph = CODE_PLACEHOLDER(i);
    out = out.replace(ph, codeBlocks[i] || ph);
  }

  // Final safety: don't return empty string
  return out === '' ? null : out;
}

function extractAssistantText(payloadJson) {
  if (!payloadJson) return null;
  const safe = (s) => (typeof s === 'string' && s.trim() ? s.trim() : null);

  if (Array.isArray(payloadJson.choices) && payloadJson.choices.length) {
    const c = payloadJson.choices[0];
    const mc = safe(c?.message?.content);
    if (mc) {
      const s = sanitizeAssistantText(mc);
      if (s) return s;
    }
    const ct = safe(c.text);
    if (ct) {
      const s = sanitizeAssistantText(ct);
      if (s) return s;
    }
    const d = safe(c?.delta?.content);
    if (d) {
      const s = sanitizeAssistantText(d);
      if (s) return s;
    }
    if (Array.isArray(c?.message?.reasoning_details)) {
      for (const it of c.message.reasoning_details) {
        if (!it) continue;
        if (it.type && String(it.type).toLowerCase().includes('encrypted')) continue;
        if (typeof it.summary === 'string' && it.summary.trim()) {
          const s = sanitizeAssistantText(it.summary);
          if (s) return s;
        }
      }
    }
  }

  const keys = ['response','output','result','text'];
  for (const k of keys) {
    if (typeof payloadJson[k] === 'string' && payloadJson[k].trim()) {
      const s = sanitizeAssistantText(payloadJson[k]);
      if (s) return s;
    }
  }

  try {
    const raw = JSON.stringify(payloadJson || {});
    const m = raw.match(/"content"\\s*:\\s*"([^"]{10,2000})"/i);
    if (m) {
      const candidate = m[1].replace(/\\n/g,' ').replace(/\\"/g,'"');
      const s = sanitizeAssistantText(candidate);
      if (s) return s;
    }
  } catch(e) {}

  return null;
}

/* ---------------------------
   Fetch wrapper
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
   History append (also updates phrase bank)
   --------------------------- */
async function appendUserHistory(tfid, entry) {
  const hist = await readJsonSafe(USER_HISTORY_FILE, { histories: {} });
  hist.histories = hist.histories || {};
  hist.histories[tfid] = hist.histories[tfid] || [];
  hist.histories[tfid].push(entry);
  const CAP = 10000;
  if (hist.histories[tfid].length > CAP) {
    hist.histories[tfid] = hist.histories[tfid].slice(-CAP);
  }
  await writeJsonSafe(USER_HISTORY_FILE, hist);

  try {
    if (entry && entry.role === 'assistant' && typeof entry.content === 'string') {
      const visible = extractVisibleFromWrapped(entry.content);
      await updatePhraseBankWithAssistantContent(visible);
    }
  } catch (e) {}
}

/* ---------------------------
   Init files & phrasebank
   --------------------------- */
await readJsonSafe(USERS_FILE, { users: [] });
await readJsonSafe(SESSIONS_FILE, { sessions: {} });
await readJsonSafe(USER_HISTORY_FILE, { histories: {} });
await loadPhraseBank();
await buildPhraseBankFromHistory();

/* ---------------------------
   Endpoints: user, session, history
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
    return res.status(500).json({ error: 'server_error', details: err.message });
  }
});

app.get('/users', async (req, res) => {
  try { const data = await readJsonSafe(USERS_FILE, { users: [] }); res.json(data.users || []); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/session', async (req, res) => {
  try {
    const { tfid } = req.body || {};
    if (!tfid) return res.status(400).json({ error: 'tfid_required' });
    const users = await readJsonSafe(USERS_FILE, { users: [] });
    const found = (users.users || []).find(u => u.tfid === tfid);
    if (!found) return res.status(404).json({ error: 'user_not_found' });
    const sessionsData = await readJsonSafe(SESSIONS_FILE, { sessions: {} });
    sessionsData.sessions = sessionsData.sessions || {};
    const sessionId = crypto.randomUUID();
    const session = { sessionId, tfid, createdAt: new Date().toISOString(), messages: [] };
    sessionsData.sessions[sessionId] = session;
    await writeJsonSafe(SESSIONS_FILE, sessionsData);
    res.json({ sessionId, createdAt: session.createdAt });
  } catch (err) { console.error('/session error', err); res.status(500).json({ error: 'server_error', details: err.message }); }
});

app.get('/session/:id', async (req,res) => {
  try { const sessionsData = await readJsonSafe(SESSIONS_FILE, { sessions: {} }); const s = (sessionsData.sessions || {})[req.params.id]; if (!s) return res.status(404).json({ error: 'session_not_found' }); res.json(s); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/sessions/:tfid', async (req,res) => {
  try { const sessionsData = await readJsonSafe(SESSIONS_FILE, { sessions: {} }); const list = Object.values(sessionsData.sessions || {}).filter(s => s.tfid === req.params.tfid); res.json(list.map(s => ({ sessionId: s.sessionId, createdAt: s.createdAt }))); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/history/:tfid/:n?', async (req, res) => {
  try {
    const tfid = req.params.tfid;
    const n = Math.max(1, Math.min(1000, Number(req.params.n || 100)));
    const hist = await readJsonSafe(USER_HISTORY_FILE, { histories: {} });
    const arr = (hist.histories && hist.histories[tfid]) ? hist.histories[tfid] : [];
    res.json(arr.slice(-n));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* ---------------------------
   Main /message endpoint
   --------------------------- */
app.post('/message', async (req, res) => {
  try {
    const { tfid, sessionId } = req.body || {};
    let text = req.body?.text;
    if (!tfid || !sessionId || typeof text !== 'string' || !text.trim()) {
      return res.status(400).json({ error: 'tfid_session_text_required' });
    }

    // clean text
    let clean = String(text || '').trim().replace(/\s+/g,' ');
    if (!clean) return res.status(400).json({ error: 'empty_message' });

    // verify user & session
    const users = await readJsonSafe(USERS_FILE, { users: [] });
    const user = (users.users || []).find(u => u.tfid === tfid);
    if (!user) return res.status(404).json({ error: 'user_not_found' });
    const sessionsData = await readJsonSafe(SESSIONS_FILE, { sessions: {} });
    sessionsData.sessions = sessionsData.sessions || {};
    const session = sessionsData.sessions[sessionId];
    if (!session) return res.status(404).json({ error: 'session_not_found' });
    if (session.tfid !== tfid) return res.status(403).json({ error: 'session_belongs_to_other_user' });

    // Append user message to session + history (we still record it)
    session.messages = session.messages || [];
    session.messages.push({ role: 'user', content: clean, ts: Date.now() });
    await appendUserHistory(tfid, { role: 'user', content: clean, sessionId, ts: Date.now() });

    // build payload: system + compact context + ensure last user message is final (priority)
    const systemMsg = makeSystemPrompt(tfid, sessionId, user.name || DEFAULT_USER_NAME);
    const history = (session.messages || []).map(m => ({ role: m.role, content: m.content || '' }));
    const tail = history.slice(-HISTORY_TAIL);

    // Build a plain-text context summary (background only). Limit length.
    let contextLines = [];
    for (const m of tail) {
      contextLines.push(`${m.role.toUpperCase()}: ${String(m.content || '').replace(/\s+/g,' ').trim()}`);
    }
    let contextText = contextLines.join('\n').trim();
    if (contextText.length > 4000) contextText = contextText.slice(-4000);

    const contextSystemMsg = {
      role: 'system',
      content: `CONTEXT (background — use only to clarify). Treat the most recent user message as the highest priority:\n${contextText}`
    };

    // Add an explicit system instruction to prioritize final user message; instruct model not to output the literal marker.
    const prioritySystemMsg = {
      role: 'system',
      content: [
        'IMPORTANT: Prioritize the final USER message below when producing your answer.',
        'Do NOT output internal chain-of-thought or planning as visible text.',
        `Do NOT include the literal marker string ${MARKER} in your response; the server handles any internal markings.`,
        'When you finish internal reflection, put the marker EXACTLY on its own line before the visible reply: ' + MARKER
      ].join(' ')
    };

    // Final payload: system instructions, background context, then the user's current message LAST
    const payloadMessages = [systemMsg, contextSystemMsg, prioritySystemMsg, { role: 'user', content: clean }];

    // ---------- LECTURE / RÉFLEXION ----------
    // 1) lire prompt pendant THINK_PROMPT_MS (pause to simulate "reading the prompt")
    if (THINK_PROMPT_MS > 0) {
      await sleep(THINK_PROMPT_MS);
    }

    // 2) lire messages pendant THINK_MESSAGES_MS (pause to simulate "reading messages")
    if (THINK_MESSAGES_MS > 0) {
      await sleep(THINK_MESSAGES_MS);
    }
    // ---------- fin réflexion ----------

    // provider call loop
    let attempt = 0;
    let currentMax = DEFAULT_MAX_TOKENS;
    let lastResp = null;
    let extracted = null;

    while (attempt < MAX_RETRIES) {
      attempt++;
      const payload = {
        model: OPENROUTER_MODEL,
        messages: payloadMessages,
        max_tokens: currentMax,
        max_output_tokens: currentMax,
        temperature: 0.2
      };

      lastResp = await fetchWithTimeout(OPENROUTER_ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type':'application/json', 'Authorization': 'Bearer ' + OPENROUTER_API_KEY },
        body: JSON.stringify(payload)
      }, DEFAULT_TIMEOUT_MS);

      if (!lastResp.ok && lastResp.fetchError) {
        console.warn('Network error contacting provider:', String(lastResp.fetchError));
        continue; // retry
      }

      if (!lastResp.ok) {
        if (lastResp.status === 402) {
          let affordable = null;
          const j = lastResp.json;
          if (j && j.error) {
            if (j.error.metadata && typeof j.error.metadata.affordable_tokens === 'number') affordable = j.error.metadata.affordable_tokens;
            else if (typeof j.error.message === 'string') {
              const m = j.error.message.match(/(\d{2,4})\s*tokens?/i);
              if (m) affordable = parseInt(m[1], 10);
            }
          }
          if (!affordable || Number.isNaN(affordable)) affordable = Math.max(MIN_TOKENS, Math.floor(currentMax * 0.6));
          if (affordable <= RECOVERY_MAX_TOKENS_CAP) {
            const recMax = Math.max(MIN_TOKENS, Math.min(affordable, RECOVERY_MAX_TOKENS_CAP));
            const recoveryMsg = { role: 'user', content: `Brief summary: give a direct short answer (1 sentence) to the previous request: "${clean}".` };
            const shortPayload = { model: OPENROUTER_MODEL, messages: [systemMsg, contextSystemMsg, recoveryMsg], max_tokens: recMax, max_output_tokens: recMax, temperature: 0.0 };
            const recoveryResp = await fetchWithTimeout(OPENROUTER_ENDPOINT, {
              method: 'POST',
              headers: { 'Content-Type':'application/json', 'Authorization': 'Bearer ' + OPENROUTER_API_KEY },
              body: JSON.stringify(shortPayload)
            }, DEFAULT_TIMEOUT_MS);
            if (recoveryResp.ok) {
              const recovered = extractAssistantText(recoveryResp.json);
              if (recovered) {
                // Wrap for storage
                const wrapped = ensureMarkerBefore(recovered);
                const visible = extractVisibleFromWrapped(wrapped);
                session.messages.push({ role: 'assistant', content: wrapped, ts: Date.now() });
                await writeJsonSafe(SESSIONS_FILE, sessionsData);
                await appendUserHistory(tfid, { role: 'assistant', content: wrapped, sessionId, ts: Date.now() });
                return res.json({ assistant: visible });
              }
            }
          }
        }
        continue;
      }

      extracted = extractAssistantText(lastResp.json);
      const maybeChoice = lastResp.json?.choices?.[0];
      const finishReason = maybeChoice?.finish_reason || maybeChoice?.native_finish_reason || null;
      if (extracted) break;

      if (finishReason === 'length' || finishReason === 'max_output_tokens') {
        if (currentMax < MAX_ALLOWED_TOKENS) {
          const prev = currentMax;
          currentMax = Math.min(MAX_ALLOWED_TOKENS, Math.max(currentMax + 64, Math.floor(currentMax * 1.8)));
          if (currentMax !== prev) continue;
        }
      }
    } // end loop

    let assistantText = extracted || null;
    if (!assistantText && lastResp && lastResp.ok) assistantText = extractAssistantText(lastResp.json);

    if (!assistantText) {
      const bankReply = localFallbackUsingBank(clean);
      const wrapped = ensureMarkerBefore(bankReply);
      const visible = extractVisibleFromWrapped(wrapped);
      session.messages.push({ role: 'assistant', content: wrapped, ts: Date.now() });
      await writeJsonSafe(SESSIONS_FILE, sessionsData);
      await appendUserHistory(tfid, { role: 'assistant', content: wrapped, sessionId, ts: Date.now() });
      return res.json({ assistant: visible });
    }

    // Wrap for storage (this will add marker before visible content when ENABLE_MARKER=true)
    const wrapped = ensureMarkerBefore(assistantText);
    const visible = extractVisibleFromWrapped(wrapped);
    session.messages.push({ role: 'assistant', content: wrapped, ts: Date.now() });
    await writeJsonSafe(SESSIONS_FILE, sessionsData);
    await appendUserHistory(tfid, { role: 'assistant', content: wrapped, sessionId, ts: Date.now() });

    return res.json({ assistant: visible });

  } catch (err) {
    console.error('/message error', err);
    const fallback = localFallbackUsingBank(req.body?.text || '');
    const wrapped = ensureMarkerBefore(fallback);
    const visible = extractVisibleFromWrapped(wrapped);
    return res.status(500).json({ assistant: visible, error: 'server_error', details: String(err?.message || err) });
  }
});

/* ---------------------------
   Health
   --------------------------- */
app.get('/health', (req,res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`Proxy server listening on http://localhost:${PORT}`);
  console.log(`Model: ${OPENROUTER_MODEL}  Endpoint: ${OPENROUTER_ENDPOINT}`);
  console.log(`Defaults: HISTORY_TAIL=${HISTORY_TAIL}, DEFAULT_MAX_TOKENS=${DEFAULT_MAX_TOKENS}`);
});

/* ---------------------------
   System prompt maker
   --------------------------- */
function makeSystemPrompt(tfid, sessionId, userName = null) {
  const display = userName || DEFAULT_USER_NAME || tfid;
  return {
    role: 'system',
    content: [
      `You are Adam_D'H7, a helpful assistant created by D'H7 | Tergene for ${display}. Session: ${sessionId}.`,
      'GUIDELINES:',
      '- Reply naturally in the user\'s language (French / Haitian Creole as appropriate).',
      '- PRIORITIZE the most recent USER message: treat earlier history only as context/background.',
      '- DO NOT output internal chain-of-thought, private planning, or reasoning details as visible text.',
      `- WHEN YOU HAVE A FINAL VISIBLE REPLY: place the marker EXACTLY on its own line IMMEDIATELY BEFORE the visible reply: ${MARKER}`,
      `  Example (must be the same string, on its own line):`,
      `  ${MARKER}`,
      `  Bonjour ! Comment puis-je vous aider ?`,
      `  When you send a message that you think the user might need a copy of, add `````` in the beginning and end',
      '- Do NOT include meta lines like "Considering user language" or "Responding in French" in visible output.',
      '- If you must think, keep it internal and do not print it. Then place the marker and the visible reply.',
      '- When user requests code, return code only (in a code block) unless the user asks for explanation.'
    ].join(' ')
  };
}

/* ---------------------------
   Local fallback logic
   --------------------------- */
function localFallback(userInput) {
  if (!userInput || typeof userInput !== 'string') return "Salut ! Comment puis-je t'aider ?";
  const lc = userInput.toLowerCase();
  if (/\b(salut|bonjour|hey|coucou)\b/.test(lc)) {
    return "Salut ! Comment puis-je t'aider aujourd'hui ?";
  }
  if (/\b(nom|comment t'?appelle|t'?appelle)\b/.test(lc)) {
    return "Je m'appelle Adam_D'H7. En quoi puis-je t'aider ?";
  }
  if (/\b(cod|coder|programm|javascript|node|react|python)\b/.test(lc)) {
    return "Oui, je sais coder — dis-moi le langage ou la tâche (ex: Node.js, React, Python) et je t'aiderai.";
  }
  const short = userInput.length > 200 ? userInput.slice(0, 200) + '…' : userInput;
  return `Je peux t'aider avec: "${short}". Peux-tu préciser ce que tu veux exactement ?`;
}

function localFallbackUsingBank(userInput) {
  const best = findBestBankPhrase(userInput);
  if (best) return best;
  return localFallback(userInput);
  }
