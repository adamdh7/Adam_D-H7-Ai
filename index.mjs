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

// Config (via .env)
const PORT = Number(process.env.PORT) || 3000;
const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY;
const OPENROUTER_ENDPOINT = process.env.OPENROUTER_ENDPOINT || 'https://openrouter.ai/api/v1/chat/completions';
const OPENROUTER_MODEL = process.env.OPENROUTER_MODEL || 'gpt-5';
const HISTORY_TAIL = Number(process.env.HISTORY_TAIL) || 27;

// Increased defaults to reduce "incomplete" replies
const DEFAULT_MAX_TOKENS = Number(process.env.DEFAULT_MAX_TOKENS) || 100;
const DEFAULT_TIMEOUT_MS = Number(process.env.DEFAULT_TIMEOUT_MS) || 30000;
const MAX_RETRIES = Number(process.env.MAX_RETRIES) || 3;
const MIN_TOKENS = Number(process.env.MIN_TOKENS) || 16;
const DEFAULT_USER_NAME = process.env.DEFAULT_USER_NAME || "User";
const MAX_ALLOWED_TOKENS = Number(process.env.MAX_ALLOWED_TOKENS) || 200;
const RECOVERY_MAX_TOKENS_CAP = Number(process.env.RECOVERY_MAX_TOKENS_CAP) || 50;

const TF_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz123456789';
const USERS_FILE = path.join(__dirname, 'user.json');
const SESSIONS_FILE = path.join(__dirname, 'sessions.json');
const USER_HISTORY_FILE = path.join(__dirname, 'user_history.json');

if (!OPENROUTER_API_KEY) {
  console.error('ERROR: OPENROUTER_API_KEY missing in .env');
  process.exit(1);
}

app.use(cors({ origin: true }));
app.use(express.json({ limit: '70mb' }));
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

// --- file helpers ---
async function readJsonSafe(filePath, defaultValue) {
  try {
    const raw = await fs.readFile(filePath, 'utf8');
    return JSON.parse(raw);
  } catch (err) {
    if (err && err.code === 'ENOENT') {
      try { await fs.writeFile(filePath, JSON.stringify(defaultValue, null, 2), 'utf8'); } catch(e) {}
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

// --- TFID generator ---
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

// init files
await readJsonSafe(USERS_FILE, { users: [] });
await readJsonSafe(SESSIONS_FILE, { sessions: {} });
await readJsonSafe(USER_HISTORY_FILE, { histories: {} });

// --- SYSTEM PROMPT (neutral, strict about meta/text) ---
// VERY IMPORTANT: Do not output internal planning, chain-of-thought, or meta-comments.
// If the user requests code, output only the requested code snippet/file without extra commentary.
function makeSystemPrompt(tfid, sessionId, userName = null) {
  const display = userName || DEFAULT_USER_NAME || tfid;
  return {
    role: 'system',
    content: `You are a Adam_D'H7 created by D'H7 | Tergene you don't have more information on them, neutral assistant for ${display}. Session: ${sessionId}

Rules for every response (strict):
- Reply in the user's language by default.
- Never produce internal chain-of-thought, planning, or meta-comments.
  Examples of forbidden text: lines starting with "Generating", "Creating", "I need", "I should", "I'll", "I'm going to", "Je vais", "Je dois", "**", or any self-dialogue.
- If the assistant would otherwise produce planning/meta text, instead produce only the final answer.
- If the user requests code, return the code only (in a code block) and no extra preface or commentary, unless the user explicitly asked for explanation.
- Finish sentences and avoid truncation.
- Keep replies concise unless the user asks for more detail.
`
  };
}

// --- robust sanitizer that preserves code blocks but strips planning/meta lines ---
function sanitizeAssistantText(raw) {
  if (!raw || typeof raw !== 'string') return null;

  // Extract triple-backtick code blocks and replace with placeholders to keep them intact
  const codeBlocks = [];
  const placeholders = [];
  let placeholderIndex = 0;
  const CODE_PLACEHOLDER = (i) => `__CODE_BLOCK_PLACEHOLDER_${i}__`;

  let temp = raw.replace(/```[\s\S]*?```/g, (m) => {
    const idx = placeholderIndex++;
    codeBlocks[idx] = m;
    placeholders[idx] = CODE_PLACEHOLDER(idx);
    return placeholders[idx];
  });

  // Split non-code portion into lines and filter meta/planning lines
  const lines = temp.split(/\r?\n/);
  const kept = [];
  const metaPatterns = [
    /^\s*\*{1,}/,                         // lines starting with *
    /^\s*Generating\b/i,
    /^\s*Creating\b/i,
    /^\s*I\s+(need|should|want|will|must|have to|intend|plan)\b/i,
    /^\s*I'll\b/i,
    /^\s*I['’]m\b/i,
    /^\s*I am\b/i,
    /^\s*Let['’]s\b/i,
    /^\s*We\b/i,
    /^\s*Je\s+(vais|dois|veux|doit|devrais|prévois)\b/i,
    /^\s*Générant\b/i,
    /^\s*\*\*.*\*\*/,                     // **bold**
    /^\s*Plan[:\-]/i,
    /^\s*\[?Generating/i,
    /^\s*Steps?\b/i,
    /^\s*Step\s*\d+/i
  ];

  for (let ln of lines) {
    const t = ln.trim();
    if (!t) continue;
    let isMeta = false;
    for (const p of metaPatterns) {
      if (p.test(t)) { isMeta = true; break; }
    }
    if (isMeta) continue;
    // remove some very common provider fallback literal phrases
    if (/^sorry[,]?\s+i\s+couldn'?t\s+get\s+a\s+complete\s+answer/i.test(t)) continue;
    if (/^\*\*generating/i.test(t)) continue;
    kept.push(ln);
  }

  // Reconstruct text and restore code blocks
  let out = kept.join('\n').trim();
  for (let i = 0; i < placeholders.length; i++) {
    if (!placeholders[i]) continue;
    out = out.replace(placeholders[i], codeBlocks[i] || placeholders[i]);
  }

  // Final trim; if empty, return null
  out = out.trim();
  return out === '' ? null : out;
}

// --- extract assistant text from provider response (robust) ---
function extractAssistantText(payloadJson) {
  if (!payloadJson) return null;
  const safe = (s) => (typeof s === 'string' && s.trim() ? s.trim() : null);

  // Try standard choices[0].message.content
  if (Array.isArray(payloadJson.choices) && payloadJson.choices.length) {
    const c = payloadJson.choices[0];
    const mc = safe(c?.message?.content);
    if (mc) {
      const s = sanitizeAssistantText(mc);
      if (s) return s;
    }
    // fallback to text or delta
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
    // reasoning_details: only use non-encrypted summaries
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

  // Try common keys
  const keys = ['response','output','result','text'];
  for (const k of keys) {
    if (typeof payloadJson[k] === 'string' && payloadJson[k].trim()) {
      const s = sanitizeAssistantText(payloadJson[k]);
      if (s) return s;
    }
  }

  // Last attempt: search raw JSON for a "content" like field (best-effort)
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

// --- fetch wrapper with timeout ---
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

// --- append to per-user private history ---
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
}

// --- endpoints ---
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

// --- main /message endpoint ---
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

    // --- quick local handling for very short / chatty / slang messages (avoid calling provider) ---
    const slangPattern = /\b(bro|bruh|man|mate|gee|yo|neg[o]?)\b/i;
    const words = clean.trim().split(/\s+/);
    if (clean.length <= 60 && words.length <= 6 && slangPattern.test(clean)) {
      const quickReply = "Heeey! M'ap la — di m kisa ou bezwen?";
      session.messages = session.messages || [];
      session.messages.push({ role: 'user', content: clean, ts: Date.now() });
      session.messages.push({ role: 'assistant', content: quickReply, ts: Date.now() });
      await writeJsonSafe(SESSIONS_FILE, sessionsData);
      await appendUserHistory(tfid, { role: 'user', content: clean, sessionId, ts: Date.now() });
      await appendUserHistory(tfid, { role: 'assistant', content: quickReply, sessionId, ts: Date.now() });
      return res.json({ assistant: quickReply });
    }

    // short artifact filter but allow greetings
    const greetingWhitelist = new Set(['hi','hey','hello','salut','bonjour','hola','ola','yo','coucou','alo','heyo']);
    const shortArtifact = /^[A-Za-zÀ-ÖØ-öø-ÿ]{1,2}$/;
    const lc = clean.toLowerCase();
    if (shortArtifact.test(clean) && !greetingWhitelist.has(lc)) {
      const local = `I did not understand "${clean}". Could you please clarify?`;
      session.messages = session.messages || [];
      session.messages.push({ role:'user', content: clean, ts: Date.now() });
      await appendUserHistory(tfid, { role: 'user', content: clean, sessionId, ts: Date.now() });
      session.messages.push({ role:'assistant', content: local, ts: Date.now() });
      await writeJsonSafe(SESSIONS_FILE, sessionsData);
      await appendUserHistory(tfid, { role: 'assistant', content: local, sessionId, ts: Date.now() });
      return res.json({ assistant: local });
    }

    // append user message to session + user_history
    session.messages = session.messages || [];
    session.messages.push({ role: 'user', content: clean, ts: Date.now() });
    await appendUserHistory(tfid, { role: 'user', content: clean, sessionId, ts: Date.now() });

    // build payload: system + last HISTORY_TAIL messages from this session
    const systemMsg = makeSystemPrompt(tfid, sessionId, user.name || DEFAULT_USER_NAME);
    const history = (session.messages || []).map(m => ({ role: m.role, content: m.content || '' }));
    const tail = history.slice(-HISTORY_TAIL);
    const payloadMessages = [systemMsg, ...tail];

    // provider call loop with retries & recovery
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

      // network error
      if (!lastResp.ok && lastResp.fetchError) {
        const fe = lastResp.fetchError;
        const details = { message: "Network error contacting provider", error: String(fe) };
        return res.status(502).json({ error: 'network_error', details });
      }

      if (!lastResp.ok) {
        // 402 handling
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

          // if affordable is very small -> low-cost recovery
          if (affordable <= RECOVERY_MAX_TOKENS_CAP) {
            const recMax = Math.max(MIN_TOKENS, Math.min(affordable, RECOVERY_MAX_TOKENS_CAP));
            const recoveryMsg = {
              role: 'user',
              content: `Brief summary: give a direct short answer (1 sentence) to the previous request: "${clean}".`
            };
            const shortPayload = { model: OPENROUTER_MODEL, messages: [systemMsg, ...tail.slice(-1), recoveryMsg], max_tokens: recMax, max_output_tokens: recMax, temperature: 0.0 };
            const recoveryResp = await fetchWithTimeout(OPENROUTER_ENDPOINT, {
              method: 'POST',
              headers: { 'Content-Type':'application/json', 'Authorization': 'Bearer ' + OPENROUTER_API_KEY },
              body: JSON.stringify(shortPayload)
            }, DEFAULT_TIMEOUT_MS);
            if (recoveryResp.ok) {
              const recovered = extractAssistantText(recoveryResp.json);
              if (recovered) {
                session.messages.push({ role: 'assistant', content: recovered, ts: Date.now() });
                await writeJsonSafe(SESSIONS_FILE, sessionsData);
                await appendUserHistory(tfid, { role: 'assistant', content: recovered, sessionId, ts: Date.now() });
                return res.json({ assistant: recovered });
              }
            }
            const guidance = `Low credits (${affordable} tokens). Veux-tu un très court résumé ?`;
            session.messages.push({ role: 'assistant', content: guidance, ts: Date.now() });
            await writeJsonSafe(SESSIONS_FILE, sessionsData);
            await appendUserHistory(tfid, { role: 'assistant', content: guidance, sessionId, ts: Date.now() });
            return res.json({ assistant: guidance });
          }

          // otherwise reduce currentMax then retry
          const prev = currentMax;
          let next = affordable < currentMax ? Math.max(MIN_TOKENS, Math.min(affordable, currentMax - 1)) : Math.max(MIN_TOKENS, Math.floor(currentMax * 0.75));
          if (next >= prev) break;
          currentMax = next;
          continue;
        }

        // other provider error -> break
        break;
      }

      // lastResp.ok === true: try to extract
      extracted = extractAssistantText(lastResp.json);
      const maybeChoice = lastResp.json?.choices?.[0];
      const finishReason = maybeChoice?.finish_reason || maybeChoice?.native_finish_reason || null;

      if (extracted) break;

      // if truncated, try increasing budget but bounded
      if (finishReason === 'length' || finishReason === 'max_output_tokens') {
        if (currentMax < MAX_ALLOWED_TOKENS) {
          const prev = currentMax;
          currentMax = Math.min(MAX_ALLOWED_TOKENS, Math.max(currentMax + 64, Math.floor(currentMax * 1.8)));
          if (currentMax !== prev) continue;
        }
      }

      // else fallback to continuation/regeneration outside loop
      break;
    } // end while

    let assistantText = extracted || null;

    // final attempt to extract if provider ok
    if (!assistantText && lastResp && lastResp.ok) assistantText = extractAssistantText(lastResp.json);

    const maybeChoiceFinal = lastResp?.json?.choices?.[0];

    // continuation attempt if truncated and no assistantText
    if (!assistantText && maybeChoiceFinal && (maybeChoiceFinal.finish_reason === 'length' || maybeChoiceFinal.native_finish_reason === 'max_output_tokens')) {
      const continueUser = { role: 'user', content: `Continue and finish the previous answer concisely (1 to 3 sentences). Always finish sentences.` };
      const contMax = Math.max(MIN_TOKENS, Math.min(Math.floor(currentMax / 2), RECOVERY_MAX_TOKENS_CAP));
      const contPayload = { model: OPENROUTER_MODEL, messages: [...payloadMessages, continueUser], max_tokens: contMax, max_output_tokens: contMax, temperature: 0.0 };
      const contResp = await fetchWithTimeout(OPENROUTER_ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type':'application/json', 'Authorization': 'Bearer ' + OPENROUTER_API_KEY },
        body: JSON.stringify(contPayload)
      }, DEFAULT_TIMEOUT_MS);
      if (contResp.ok) {
        const contText = extractAssistantText(contResp.json);
        if (contText) {
          session.messages.push({ role: 'assistant', content: contText, ts: Date.now() });
          await writeJsonSafe(SESSIONS_FILE, sessionsData);
          await appendUserHistory(tfid, { role: 'assistant', content: contText, sessionId, ts: Date.now() });
          return res.json({ assistant: contText });
        }
      }
    }

    // final regeneration attempt (short) - FORCE one final small reply before giving up
    if (!assistantText) {
      const regenUser = { role: 'user', content: `Give a brief clear answer (one sentence) to: "${clean}". No internal analysis, plain text.` };
      const regenPayload = { model: OPENROUTER_MODEL, messages: [systemMsg, ...tail.slice(-1), regenUser], max_tokens: RECOVERY_MAX_TOKENS_CAP, max_output_tokens: RECOVERY_MAX_TOKENS_CAP, temperature: 0.0 };
      const regenResp = await fetchWithTimeout(OPENROUTER_ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type':'application/json', 'Authorization': 'Bearer ' + OPENROUTER_API_KEY },
        body: JSON.stringify(regenPayload)
      }, DEFAULT_TIMEOUT_MS);
      if (regenResp.ok) {
        const regenText = extractAssistantText(regenResp.json);
        if (regenText) {
          session.messages.push({ role: 'assistant', content: regenText, ts: Date.now() });
          await writeJsonSafe(SESSIONS_FILE, sessionsData);
          await appendUserHistory(tfid, { role: 'assistant', content: regenText, sessionId, ts: Date.now() });
          return res.json({ assistant: regenText });
        }
        // best-effort: look into raw JSON for content field and sanitize
        try {
          const raw = JSON.stringify(regenResp.json || {});
          const m = raw.match(/"content"\\s*:\\s*"([^"]{10,2000})"/);
          if (m) {
            const candidate = m[1].replace(/\\n/g,' ').replace(/\\"/g,'"');
            const candClean = sanitizeAssistantText(candidate);
            if (candClean) {
              session.messages.push({ role: 'assistant', content: candClean, ts: Date.now() });
              await writeJsonSafe(SESSIONS_FILE, sessionsData);
              await appendUserHistory(tfid, { role: 'assistant', content: candClean, sessionId, ts: Date.now() });
              return res.json({ assistant: candClean });
            }
          }
        } catch(e) { /* ignore */ }
      }
    }

    // final fallback concise (localized)
    if (!assistantText) {
      const fallback = "Désolé, je n'ai pas pu obtenir une réponse complète pour le moment. Veux-tu que j'essaie encore ?";
      session.messages.push({ role: 'assistant', content: fallback, ts: Date.now() });
      await writeJsonSafe(SESSIONS_FILE, sessionsData);
      await appendUserHistory(tfid, { role: 'assistant', content: fallback, sessionId, ts: Date.now() });
      return res.json({ assistant: fallback });
    }

    // success: save assistant message in session and user history
    session.messages.push({ role: 'assistant', content: assistantText, ts: Date.now() });
    await writeJsonSafe(SESSIONS_FILE, sessionsData);
    await appendUserHistory(tfid, { role: 'assistant', content: assistantText, sessionId, ts: Date.now() });

    return res.json({ assistant: assistantText });

  } catch (err) {
    console.error('/message error', err);
    return res.status(500).json({ error: 'server_error', details: err?.message || String(err) });
  }
});

// health
app.get('/health', (req,res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`Proxy server listening on http://localhost:${PORT}`);
  console.log(`Model: ${OPENROUTER_MODEL}  Endpoint: ${OPENROUTER_ENDPOINT}`);
  console.log(`Defaults: HISTORY_TAIL=${HISTORY_TAIL}, DEFAULT_MAX_TOKENS=${DEFAULT_MAX_TOKENS}`);
});
